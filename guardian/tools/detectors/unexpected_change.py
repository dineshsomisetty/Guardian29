"""What changed: D4-11 legacy mini-diff + D2-06 compare-ref diff with findings. Owner: Dev4 (D4-11), Dev2 (D2-06).

Two baselines:
  legacy      `ftp/package.json.bak` (+ `ftp/package-lock.json.bak`) shipped in the target vs current
              package.json / resolved lockfile. An old backup, so only integrity changes become findings
              (the same name@version must never change its hash); the rest is context for the panel.
  compare-ref `--compare-ref <git ref>` vs the working tree of the target, per npm project. A real change
              between two commits, so it produces findings:
                new dependency            -> unexpected_change
                major-version jump        -> major_jump
                integrity changed         -> integrity_change
                install script added      -> install_script
              Lockfiles are compared when present at both points (the resolved lockfile is used for HEAD
              when the target commits none).

`changes.json` (§4.1) holds the compare-ref diff when one was given (legacy diff under `legacy`), otherwise
the legacy diff.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from guardian.adapters.npm import find_projects, line_of, purl
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.binaries import run
from guardian.tools.registry import ToolContext, ToolOutput

BASE_MANIFEST = "ftp/package.json.bak"
BASE_LOCK = "ftp/package-lock.json.bak"
_VER = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_GIT_REF = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./~^@{}-]{0,99}$")
MAX_FINDINGS_PER_KIND = 25  # a huge diff is one story, not 500 findings; counts stay complete in changes.json


# ---------------------------------------------------------------- pure diff helpers


def _deps(data: dict) -> dict[str, str]:
    return {**data.get("dependencies", {}), **data.get("devDependencies", {})}


def _base(rng: str) -> str:
    m = _VER.search(rng)
    return ".".join(g for g in m.groups() if g is not None) if m else rng


def _major(rng: str) -> int | None:
    m = _VER.search(rng)
    return int(m.group(1)) if m else None


def _lock_index(data: dict) -> dict[str, dict]:
    """name@version -> {integrity, install_script}, lockfile v1 (nested) and v2/v3 (`packages`)."""
    out: dict[str, dict] = {}
    for key, e in (data.get("packages") or {}).items():
        if key and e.get("version"):
            name = e.get("name") or key.rsplit("node_modules/", 1)[-1]
            out[f"{name}@{e['version']}"] = {"integrity": e.get("integrity"),
                                              "install_script": bool(e.get("hasInstallScript"))}

    def walk(deps: dict) -> None:
        for name, e in (deps or {}).items():
            if e.get("version"):
                out.setdefault(f"{name}@{e['version']}", {"integrity": e.get("integrity"), "install_script": False})
            walk(e.get("dependencies"))

    walk(data.get("dependencies"))
    return out


def diff_manifests(base: dict, head: dict) -> dict:
    b, h = _deps(base), _deps(head)
    added = sorted(purl(n, _base(h[n])) for n in h.keys() - b.keys())
    removed = sorted(purl(n, _base(b[n])) for n in b.keys() - h.keys())
    changed = []
    for n in sorted(b.keys() & h.keys()):
        if b[n] != h[n]:
            mb, mh = _major(b[n]), _major(h[n])
            changed.append({"name": n, "from": _base(b[n]), "to": _base(h[n]), "from_range": b[n], "to_range": h[n],
                            "major_jump": mb is not None and mh is not None and mh - mb >= 1})
    return {"added": added, "removed": removed, "changed": changed}


def diff_locks(base: dict, head: dict) -> dict:
    bi, hi = _lock_index(base), _lock_index(head)
    integrity, scripts = [], []
    for key in sorted(bi.keys() & hi.keys()):
        fb, fh = bi[key]["integrity"], hi[key]["integrity"]
        # same algorithm, different digest -> the bytes behind name@version changed (sha1 -> sha512 is not)
        if fb and fh and fb != fh and fb.split("-")[0] == fh.split("-")[0]:
            name, _, ver = key.rpartition("@")
            integrity.append({"purl": purl(name, ver), "from": fb, "to": fh})
    for key in sorted(hi.keys()):
        if hi[key]["install_script"] and not (bi.get(key) or {}).get("install_script"):
            name, _, ver = key.rpartition("@")
            scripts.append({"purl": purl(name, ver), "new_package": key not in bi})
    return {"integrity_changed": integrity, "install_scripts_added": scripts}


# ---------------------------------------------------------------- legacy baseline (D4-11)


def legacy_diff(root: Path) -> dict | None:
    base, head = root / BASE_MANIFEST, root / "package.json"
    if not base.exists() or not head.exists():
        return None
    out = {"base": BASE_MANIFEST, "head": "package.json",
           **diff_manifests(json.loads(base.read_text(encoding="utf-8")), json.loads(head.read_text(encoding="utf-8"))),
           "integrity_changed": [], "install_scripts_added": []}
    base_lock, head_lock = root / BASE_LOCK, root / "package-lock.json"
    if base_lock.exists() and head_lock.exists():
        locks = diff_locks(json.loads(base_lock.read_text(encoding="utf-8")),
                           json.loads(head_lock.read_text(encoding="utf-8")))
        out["integrity_changed"] = locks["integrity_changed"]  # install scripts vs a years-old backup: noise
    return out


def mini_diff(ctx: ToolContext) -> ToolOutput:
    """CP1 entry point (kept for the D4-11 binding): legacy diff only."""
    return _output(ctx, None, legacy_diff(ctx.work_dir or ctx.repo), [], [])


# ---------------------------------------------------------------- compare-ref baseline (D2-06)


def git_show(repo: Path, ref: str, rel: str) -> str | None:
    proc = run(["git", "-C", str(repo), "show", f"{ref}:{rel}"], timeout=30, ok_codes=(0, 128))
    return proc.stdout if proc.returncode == 0 else None


def compare_ref_diff(repo: Path, work: Path, ref: str) -> tuple[dict, list[dict]]:
    """Diff every npm project of the target between `ref` and the working tree. Returns (changes, per-project)."""
    if not _GIT_REF.match(ref):
        raise ValueError(f"unexpected git ref {ref!r}")
    sha = run(["git", "-C", str(repo), "rev-parse", "--verify", f"{ref}^{{commit}}"], timeout=30).stdout.strip()
    total = {"base": f"{ref} ({sha[:12]})", "head": "working tree", "added": [], "removed": [], "changed": [],
             "integrity_changed": [], "install_scripts_added": [], "compare_ref": ref, "compare_sha": sha}
    per_project = []
    for proj in find_projects(repo):
        rel_dir = "" if proj.name == "root" else f"{proj.name}/"
        old_manifest = git_show(repo, sha, f"{rel_dir}package.json")
        if old_manifest is None:
            entry = {"project": proj.name, "new_project": True}
            per_project.append(entry)
            continue
        d = diff_manifests(json.loads(old_manifest), json.loads(proj.manifest.read_text(encoding="utf-8")))
        locks = {"integrity_changed": [], "install_scripts_added": []}
        old_lock = git_show(repo, sha, f"{rel_dir}package-lock.json")
        head_lock = proj.lockfile if proj.lockfile.exists() else work / rel_dir / "package-lock.json"
        if old_lock and head_lock.exists():
            locks = diff_locks(json.loads(old_lock), json.loads(head_lock.read_text(encoding="utf-8")))
        for k in ("added", "removed"):
            total[k] += d[k]
        total["changed"] += [{**c, "project": proj.name} for c in d["changed"]]
        total["integrity_changed"] += [{**c, "project": proj.name} for c in locks["integrity_changed"]]
        total["install_scripts_added"] += [{**c, "project": proj.name} for c in locks["install_scripts_added"]]
        per_project.append({"project": proj.name, "manifest": f"{rel_dir}package.json", **d, **locks,
                            "lockfile_compared": bool(old_lock and head_lock.exists())})
    return total, per_project


def _findings(ctx: ToolContext, ref: str, per_project: list[dict]) -> tuple[list[Finding], list[Evidence]]:
    findings, evidence = [], []
    counts: dict[str, int] = {}

    def add(category: FindingCategory, title: str, project: str, file_path: str, facts: dict,
            component: str | None, line: int | None = None) -> None:
        if counts.get(category.value, 0) >= MAX_FINDINGS_PER_KIND:
            return
        counts[category.value] = counts.get(category.value, 0) + 1
        ev = Evidence(run_id=ctx.run_id, kind="diff", source_tool="detector:unexpected_change",
                      facts={"compare_ref": ref, "project": project, **facts}, file_path=file_path, line=line)
        evidence.append(ev)
        findings.append(Finding(run_id=ctx.run_id, category=category, title=title,
                                detector="detector:unexpected_change", component_purl=component, scope=Scope.UNKNOWN,
                                project=project, file_path=file_path, line=line, evidence_ids=[ev.evidence_id]))

    for p in per_project:
        if p.get("new_project"):
            continue
        proj, manifest = p["project"], p["manifest"]
        mpath = ctx.repo / manifest
        for added in p["added"]:
            name = added.split("/", 1)[1].rsplit("@", 1)[0].replace("%40", "@")
            line = line_of(mpath, rf'^\s*"{re.escape(name)}"\s*:')
            add(FindingCategory.UNEXPECTED_CHANGE, f"New dependency {name} added since {ref}", proj, manifest,
                {"change": "added", "purl": added, "name": name}, added, line)
        for c in p["changed"]:
            if c["major_jump"]:
                line = line_of(mpath, rf'^\s*"{re.escape(c["name"])}"\s*:')
                add(FindingCategory.MAJOR_JUMP, f"{c['name']} jumped a major version {c['from']} -> {c['to']} since {ref}",
                    proj, manifest, {"change": "major_jump", "name": c["name"], "from": c["from_range"],
                                     "to": c["to_range"]}, purl(c["name"], c["to"]), line)
        lock = f"{'' if proj == 'root' else proj + '/'}package-lock.json"
        for c in p["integrity_changed"]:
            add(FindingCategory.INTEGRITY_CHANGE, f"Integrity hash of {c['purl']} changed since {ref}", proj, lock,
                {"change": "integrity", "purl": c["purl"], "from": c["from"], "to": c["to"]}, c["purl"])
        for c in p["install_scripts_added"]:
            what = "new dependency with an install script" if c["new_package"] else "install script added"
            add(FindingCategory.INSTALL_SCRIPT, f"{c['purl']}: {what} since {ref}", proj, lock,
                {"change": "install_script_added", "purl": c["purl"], "new_package": c["new_package"]}, c["purl"])
    return findings, evidence


def _output(ctx: ToolContext, compare: dict | None, legacy: dict | None, findings: list, evidence: list) -> ToolOutput:
    if compare is None and legacy is None:
        return ToolOutput(summary="no baseline to compare (no --compare-ref, no legacy manifest)")
    main = compare or legacy
    facts = {"base": main["base"], "head": main["head"], "added": len(main["added"]),
             "removed": len(main["removed"]), "changed": len(main["changed"]),
             "major_jumps": sum(c["major_jump"] for c in main["changed"]),
             "integrity_changed": len(main["integrity_changed"]),
             "install_scripts_added": len(main["install_scripts_added"]),
             "removed_names": [r.split("/")[-1] for r in main["removed"]][:50]}
    ev = Evidence(run_id=ctx.run_id, kind="changes", source_tool="detector:unexpected_change", facts=facts,
                  file_path=main["base"] if main is legacy else None)
    changes = {**main, "evidence_ids": [ev.evidence_id, *(e.evidence_id for e in evidence)][:200]}
    if compare is not None and legacy is not None:
        changes["legacy"] = {**legacy, "evidence_ids": [ev.evidence_id]}  # same changes evidence covers both
    if legacy is not None and compare is None:  # integrity changes vs the backup are still findings
        for c in legacy["integrity_changed"]:
            fev = Evidence(run_id=ctx.run_id, kind="diff", source_tool="detector:unexpected_change",
                           facts={"change": "integrity", "baseline": BASE_LOCK, **c}, file_path=BASE_LOCK)
            evidence.append(fev)
            findings.append(Finding(run_id=ctx.run_id, category=FindingCategory.INTEGRITY_CHANGE,
                                    title=f"Integrity hash of {c['purl']} differs from {BASE_LOCK}",
                                    detector="detector:unexpected_change", component_purl=c["purl"],
                                    project="root", file_path="package-lock.json", evidence_ids=[fev.evidence_id]))
    summary = (f"vs {main['base']}: +{facts['added']} / -{facts['removed']} / ~{facts['changed']} deps, "
               f"{facts['major_jumps']} major jumps, {facts['integrity_changed']} integrity changes, "
               f"{facts['install_scripts_added']} install scripts added -> {len(findings)} findings")
    return ToolOutput(findings=findings, evidence=[ev, *evidence], artifacts={"changes": changes}, summary=summary)


def detect(ctx: ToolContext) -> ToolOutput:
    work = ctx.work_dir or ctx.repo
    legacy = legacy_diff(work)
    ref = ctx.artifacts.get("compare_ref")
    if not ref:
        return _output(ctx, None, legacy, [], [])
    compare, per_project = compare_ref_diff(ctx.repo, work, ref)
    findings, evidence = _findings(ctx, ref, per_project)
    return _output(ctx, compare, legacy, findings, evidence)
