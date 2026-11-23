"""Detector `unexpected_change` (D2-06, Dev2; generalises Dev4's D4-11 mini-diff).

Compares a BASE and a HEAD version of the npm manifest (+ lockfile when both exist):
  * `--compare-ref <ref>`: base = files at that git ref, head = working tree (real change review)
  * otherwise (CP1 / Juice Shop): base = `ftp/package.json.bak` (+ `ftp/package-lock.json.bak`), head = current
Writes the changes.json document (§4.1, built with Dev4's `compute_changes`) and raises findings ONLY for the
risky kinds of change: integrity change for the same version, install script appearing, version downgrade,
major-version jump in a prod dependency, new prod dependency (individually only if few), and typosquats in the
base manifest (legacy typosquat). The full diff stays in changes.json for the UI panel.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from guardian.adapters.npm import lock_entries, npm_purl, parse_manifest
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.changes import compute_changes
from guardian.tools.detectors.similarity import check_name
from guardian.tools.registry import ToolOutput

DETECTOR = "detector:unexpected_change"
BAK_MANIFEST, BAK_LOCK = "ftp/package.json.bak", "ftp/package-lock.json.bak"
MAX_INDIVIDUAL_NEW_DEPS = 10  # more than this = a wholesale rewrite: one aggregate finding instead


def _major(spec: str | None) -> int | None:
    m = re.search(r"(\d+)", spec or "")
    return int(m.group(1)) if m else None


def lock_diff(base_lock: Path, head_lock: Path) -> tuple[list[dict], list[dict]]:
    """(integrity_changed, install_scripts_added) comparing every (name, version) present in both lockfiles."""
    def index(p):
        out = {}
        for key, e in lock_entries(p).items():
            if e.get("version"):
                out.setdefault((e["_name"], e["version"]), {**e, "_key": key})
        return out

    b, h = index(base_lock), index(head_lock)
    base_names_with_script = {n for (n, _), e in b.items() if e.get("hasInstallScript")}
    integ, scripts = [], []
    for nv, he in h.items():
        be = b.get(nv)
        if be and be.get("integrity") and he.get("integrity") and be["integrity"] != he["integrity"]:
            integ.append({"purl": npm_purl(*nv), "from": be["integrity"], "to": he["integrity"],
                          "line": he["_line"], "lock_key": he["_key"]})
        if he.get("hasInstallScript") and nv[0] not in base_names_with_script and any(n == nv[0] for n, _ in b):
            scripts.append({"purl": npm_purl(*nv), "line": he["_line"], "lock_key": he["_key"]})
    return integ, scripts


def _git_show(repo: Path, ref: str, rel: str, dest: Path) -> Path | None:
    r = subprocess.run(["git", "-C", str(repo), "show", f"{ref}:{rel}"], capture_output=True, timeout=30)
    if r.returncode != 0:
        return None
    dest.write_bytes(r.stdout)
    return dest


def _sources(ctx, tmp: Path) -> dict | None:
    """Pick base/head files. Returns None when there is nothing to compare."""
    repo = Path(ctx.repo)
    work = Path(ctx.work_dir or ctx.repo)
    ref = getattr(ctx.settings, "compare_ref", None) or ctx.artifacts.get("compare_ref")
    if ref:
        bm = _git_show(repo, ref, "package.json", tmp / "base.package.json")
        bl = _git_show(repo, ref, "package-lock.json", tmp / "base.package-lock.json")
        if not bm:
            return None
        return {"mode": f"git:{ref}", "base": bm, "base_label": f"{ref}:package.json", "base_lock": bl,
                "head": repo / "package.json", "head_label": "package.json",
                "head_lock": (repo / "package-lock.json") if (repo / "package-lock.json").is_file()
                else (work / "package-lock.json")}
    if (repo / BAK_MANIFEST).is_file():
        return {"mode": "bak", "base": repo / BAK_MANIFEST, "base_label": BAK_MANIFEST,
                "base_lock": repo / BAK_LOCK if (repo / BAK_LOCK).is_file() else None,
                "head": repo / "package.json", "head_label": "package.json",
                "head_lock": work / "package-lock.json" if (work / "package-lock.json").is_file() else None}
    return None


def mini_diff(ctx) -> ToolOutput:
    """Tool entry point (registry binding `changes`): changes.json artifact + change findings."""
    with tempfile.TemporaryDirectory() as td:
        src = _sources(ctx, Path(td))
        if src is None:
            return ToolOutput(summary="no base version to compare against (no --compare-ref, no .bak manifest)")
        return _diff(ctx, src)


def _diff(ctx, src: dict) -> ToolOutput:
    doc = compute_changes(src["base"], src["head"])  # Dev4: added/removed/changed (+ major_jump)
    doc["base"], doc["head"], doc["mode"] = src["base_label"], src["head_label"], src["mode"]
    if src.get("base_lock") and src.get("head_lock") and Path(src["head_lock"]).is_file():
        integ, scripts = lock_diff(Path(src["base_lock"]), Path(src["head_lock"]))
    else:
        integ, scripts = [], []
    doc["integrity_changed"] = [{k: v for k, v in i.items() if k in ("purl", "from", "to")} for i in integ]
    doc["install_scripts_added"] = [s["purl"] for s in scripts]

    head_deps = {d.name: d for d in parse_manifest(src["head"])}
    base_deps = {d.name: d for d in parse_manifest(src["base"])}
    for c in doc["changed"]:  # ADDITIVE field: downgrade
        bm, hm = _major(c["from"]), _major(c["to"])
        c["downgrade"] = bm is not None and hm is not None and hm < bm

    run_id = ctx.run_id
    summary_ev = Evidence(run_id=run_id, kind="changes", source_tool=DETECTOR,
                          facts={"mode": src["mode"], "base": doc["base"], "head": doc["head"],
                                 "added": len(doc["added"]), "removed": len(doc["removed"]),
                                 "changed": len(doc["changed"]), "integrity_changed": len(integ),
                                 "install_scripts_added": len(scripts),
                                 "major_jumps": sum(c["major_jump"] for c in doc["changed"]),
                                 "downgrades": sum(c["downgrade"] for c in doc["changed"])})
    evidence, findings = [summary_ev], []

    def add(category, title, *, file_path, line, excerpt, facts, purl=None, scope=Scope.UNKNOWN):
        ev = Evidence(run_id=run_id, kind="diff", source_tool=DETECTOR, file_path=file_path, line=line,
                      excerpt=excerpt, facts={"mode": src["mode"], "base": doc["base"], "head": doc["head"], **facts})
        evidence.append(ev)
        findings.append(Finding(run_id=run_id, category=category, title=title, detector=DETECTOR,
                                component_purl=purl, scope=scope, project="root", file_path=file_path, line=line,
                                evidence_ids=[ev.evidence_id, summary_ev.evidence_id]))

    head_lock_label = "package-lock.json (resolved)" if src["mode"] == "bak" else "package-lock.json"
    for i in integ:
        add(FindingCategory.INTEGRITY_CHANGE, f"Integrity hash changed for {i['purl']} (same version)",
            file_path=head_lock_label, line=i["line"], excerpt=f"{i['from'][:24]}... -> {i['to'][:24]}...",
            facts={"purl": i["purl"], "integrity_from": i["from"], "integrity_to": i["to"]}, purl=i["purl"])
    for s in scripts:
        add(FindingCategory.INSTALL_SCRIPT, f"Install script appeared in {s['purl']}",
            file_path=head_lock_label, line=s["line"], excerpt=f'"{s["lock_key"]}": hasInstallScript: true',
            facts={"purl": s["purl"], "install_script_added": True}, purl=s["purl"])
    for c in doc["changed"]:
        hd = head_deps.get(c["name"])
        scope = Scope(hd.scope) if hd else Scope.UNKNOWN
        facts = {"name": c["name"], "from": c["from"], "to": c["to"], "major_jump": c["major_jump"],
                 "downgrade": c["downgrade"]}
        if c["downgrade"]:
            add(FindingCategory.UNEXPECTED_CHANGE, f"Version downgrade: {c['name']} {c['from']} -> {c['to']}",
                file_path=doc["head"], line=hd.line if hd else None, excerpt=hd.excerpt if hd else None,
                facts=facts, scope=scope)
        elif c["major_jump"] and scope is Scope.PROD:
            add(FindingCategory.MAJOR_JUMP, f"Major-version jump: {c['name']} {c['from']} -> {c['to']}",
                file_path=doc["head"], line=hd.line if hd else None, excerpt=hd.excerpt if hd else None,
                facts=facts, scope=scope)
    new_prod = [head_deps[n] for n in head_deps if n not in base_deps and head_deps[n].scope == "prod"]
    if 0 < len(new_prod) <= MAX_INDIVIDUAL_NEW_DEPS:
        for d in new_prod:
            add(FindingCategory.UNEXPECTED_CHANGE, f"New dependency: {d.name} {d.spec}", file_path=doc["head"],
                line=d.line, excerpt=d.excerpt, facts={"name": d.name, "spec": d.spec, "new_dependency": True},
                scope=Scope.PROD)
    elif new_prod:
        add(FindingCategory.UNEXPECTED_CHANGE,
            f"{len(new_prod)} new prod dependencies since {doc['base']} (wholesale change)",
            file_path=doc["head"], line=None, excerpt=", ".join(d.name for d in new_prod[:12]) + " ...",
            facts={"new_dependencies": [d.name for d in new_prod]}, scope=Scope.PROD)
    for d in base_deps.values():  # legacy typosquat (Juice Shop "Legacy Typosquatting")
        hit = check_name(d.name)
        if hit:
            add(FindingCategory.TYPOSQUAT,
                f"Possible typosquat in {doc['base']}: '{d.name}' resembles '{hit.popular}' ({hit.reason})",
                file_path=doc["base"], line=d.line, excerpt=d.excerpt,
                facts={"candidate": d.name, "popular_name": hit.popular, "distance": hit.distance,
                       "reason": hit.reason, "still_in_head": d.name in head_deps}, scope=Scope(d.scope))

    doc["evidence_ids"] = [summary_ev.evidence_id]
    by = {}
    for f in findings:
        by[f.category.value] = by.get(f.category.value, 0) + 1
    return ToolOutput(findings=findings, evidence=evidence, artifacts={"changes": doc},
                      summary=f"{src['mode']}: +{len(doc['added'])} -{len(doc['removed'])} ~{len(doc['changed'])}; "
                              f"findings {by}")
