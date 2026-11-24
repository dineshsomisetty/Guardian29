"""Policy-as-code (D4-07; ported from dev04 and adapted to this branch's adapters/registry/evidence).

Rules (guardian.yaml `policies`/`thresholds`/`denylist`): lockfile committed, GitHub Actions pinned to a commit
SHA, base images pinned by digest, no denylisted / typosquat packages, no package younger than N days.

* `policy_check(doc, config)` evaluates the rules natively (no OPA needed) over one input document.
* The same rules exist as Rego in policies/guardian.rego. If `conftest` or `opa` is on PATH the Rego is also run on
  the same document and both results are recorded in the `policy_result` Evidence (`facts.rego`).
* `run_policy_check(ctx)` is the registered tool `policy_check` (detection; the validator may re-run it on a
  patched copy: set `ctx.artifacts["policy_lock_root"]` to the patched copy so the lockfile check looks there).
  It writes `policy_input.json`, one `policy_result` Evidence per rule that fired (or one passing result) and one
  aggregated `policy_violation` Finding per rule. Registry age lookups are cache/throttle bound and offline-safe.

Input document: {has_lockfile, actions:[{file,line,uses}], images:[{file,line,image}],
                 packages:[{name, version, age_days|None, typosquat_of|None, denylisted}]}
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import yaml

from guardian.adapters import dockerfile, github_actions, npm, pypi
from guardian.core.config import REPO_ROOT
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolContext, ToolOutput

DEFAULT_CONFIG = REPO_ROOT / "guardian.yaml"
POLICY_DIR = REPO_ROOT / "policies"
AGE_LOOKUP_CAP = 80  # registry lookups for package age per run (cached, throttled)

RULES = {
    "missing_lockfile": "No lockfile committed; installs are not reproducible",
    "unpinned_action": "GitHub Action not pinned to a commit SHA",
    "tag_only_image": "Base image not pinned by digest",
    "denylisted_package": "Package is on the guardian.yaml denylist",
    "typosquat_package": "Package name looks like a popular package",
    "package_too_new": "Package first published less than the minimum age ago",
}


def load_config(path: Path | str | None = None) -> dict:
    p = Path(path or os.environ.get("GUARDIAN_CONFIG") or DEFAULT_CONFIG)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def min_age_days(cfg: dict) -> int | None:
    thr = cfg.get("thresholds", {})
    return thr.get("min_package_age_days", thr.get("max_package_age_days"))


def _v(rule: str, message: str, file: str | None = None, line: int | None = None, **extra) -> dict:
    return {"rule": rule, "message": message, "file": file, "line": line, **extra}


def _is_sha(ref: str) -> bool:
    return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)


def _has_digest(image: str) -> bool:
    _, _, d = image.partition("@sha256:")
    return len(d) == 64 and all(c in "0123456789abcdef" for c in d)


def policy_check(doc: dict, config: dict | None = None) -> list[dict]:
    """Native evaluation of the guardian rules over `doc`. Returns violations (empty = pass)."""
    cfg = config if config is not None else load_config()
    pol = cfg.get("policies", {})
    out: list[dict] = []

    if pol.get("require_lockfile", True) and not doc.get("has_lockfile", True):
        out.append(_v("missing_lockfile", RULES["missing_lockfile"]))

    if pol.get("require_pinned_actions", True):
        for a in doc.get("actions", []):
            ref = a["uses"]
            if ref.startswith(("./", "docker://")):
                continue
            version = ref.split("@", 1)[1] if "@" in ref else ""
            if not _is_sha(version):
                out.append(_v("unpinned_action", f"{ref} is not pinned to a 40-char commit SHA",
                              a.get("file"), a.get("line")))

    if pol.get("require_pinned_base_images", True):
        for i in doc.get("images", []):
            img = i["image"]
            if img.lower() != "scratch" and not _has_digest(img):
                out.append(_v("tag_only_image", f"{img} is not pinned by digest", i.get("file"), i.get("line")))

    deny = {str(d["name"]).lower(): d.get("reason", "") for d in cfg.get("denylist", [])}
    min_age = min_age_days(cfg)
    for p in doc.get("packages", []):
        name = p["name"]
        if p.get("denylisted") or name.lower() in deny:
            reason = deny.get(name.lower(), "")
            out.append(_v("denylisted_package", f"{name} is denylisted" + (f": {reason}" if reason else ""),
                          p.get("file"), p.get("line"), package=name))
        if p.get("typosquat_of"):
            out.append(_v("typosquat_package", f"{name} looks like {p['typosquat_of']}",
                          p.get("file"), p.get("line"), package=name))
        age = p.get("age_days")
        if min_age is not None and age is not None and age < min_age:
            out.append(_v("package_too_new", f"{name} was published {age} days ago (< {min_age})",
                          p.get("file"), p.get("line"), package=name))
    return out


# ---------------------------------------------------------------- input document


def _npm_packages(root: Path) -> list[dict]:
    pk: list[dict] = []
    seen: set[str] = set()
    manifests = [(p.manifest, p.manifest.relative_to(root).as_posix()) for p in npm.find_projects(root)]
    legacy = root / "ftp" / "package.json.bak"  # shipped backup manifest (Juice Shop "Legacy Typosquatting")
    if legacy.exists():
        manifests.append((legacy, "ftp/package.json.bak"))
    for manifest, rel in manifests:
        try:
            deps = npm.manifest_deps(manifest)
        except (ValueError, OSError):
            continue
        for name, rng, section, line in deps:
            if name in seen:
                continue
            seen.add(name)
            pk.append({"name": name, "version": rng, "section": section, "file": rel, "line": line,
                       "age_days": None, "typosquat_of": None, "denylisted": False})
    return pk


def _has_lockfile(root: Path) -> bool:
    projects = npm.find_projects(root)
    return all(p.lockfile.exists() for p in projects)  # no npm project -> nothing to lock (pip pins are in-file)


def package_age_days(meta: dict | None, now: datetime | None = None) -> int | None:
    created = ((meta or {}).get("time") or {}).get("created")
    if not created:
        return None
    try:
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, ((now or datetime.now(UTC)) - dt).days)


def build_policy_input(root: Path | str, config: dict | None = None, intel=None,
                       lock_root: Path | str | None = None, now: datetime | None = None) -> dict:
    """Build the evaluator input from a project tree. `intel` (an IntelClient) adds package ages for the first
    AGE_LOOKUP_CAP direct prod packages; without it (or on offline cache misses) age stays None = unknown."""
    from guardian.tools.detectors.similarity import check_name

    root = Path(root)
    cfg = config if config is not None else load_config()
    deny = {str(d["name"]).lower() for d in cfg.get("denylist", [])}
    actions = [{"file": r.file, "line": r.line, "uses": f"{r.action}@{r.ref}" if r.ref else r.action}
               for r in github_actions.parse(root) if not r.local]
    images, _ = dockerfile.parse(root)
    pk = _npm_packages(root)
    looked = 0
    for p in pk:
        p["denylisted"] = p["name"].lower() in deny
        hit = check_name(p["name"])
        p["typosquat_of"] = hit.popular if hit else None
        if intel is not None and p["section"] == "dependencies" and looked < AGE_LOOKUP_CAP:
            looked += 1
            p["age_days"] = package_age_days(intel.registry_metadata(npm.purl(p["name"], "0")), now)
    pk += [{"name": n, "version": v or "", "section": "requirements", "file": req.name, "line": line,
            "age_days": None, "typosquat_of": None, "denylisted": n.lower() in deny}
           for proj in pypi.find_projects(root) for req in proj.requirements
           for n, v, _spec, line in pypi.requirement_pins(req) if n.lower() in deny]
    return {"has_lockfile": _has_lockfile(Path(lock_root) if lock_root else root),
            "actions": actions,
            "images": [{"file": i.file, "line": i.line,
                        "image": i.image + (f":{i.tag}" if i.tag else "") + (f"@{i.digest}" if i.digest else "")}
                       for i in images],
            "packages": pk}


# ---------------------------------------------------------------- optional Rego run


def run_rego(doc: dict, workdir: Path, policies: Path = POLICY_DIR) -> dict:
    """Run policies/guardian.rego with `conftest` or `opa` when installed. Never raises."""
    conftest, opa = shutil.which("conftest"), shutil.which("opa")
    if not conftest and not opa:
        return {"available": False, "note": "neither conftest nor opa on PATH; native evaluator only"}
    workdir.mkdir(parents=True, exist_ok=True)
    inp = workdir / "policy_input.json"
    inp.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    try:
        if conftest:
            proc = subprocess.run([conftest, "test", str(inp), "-p", str(policies), "--namespace", "guardian",
                                   "-o", "json"], capture_output=True, text=True, timeout=60)
            data = json.loads(proc.stdout or "[]")
            msgs = [f["msg"] for entry in data for f in entry.get("failures") or []]
            engine = "conftest"
        else:
            proc = subprocess.run([opa, "eval", "-d", str(policies / "guardian.rego"), "-i", str(inp),
                                   "data.guardian.deny", "--format", "json"],
                                  capture_output=True, text=True, timeout=60)
            data = json.loads(proc.stdout or "{}")
            msgs = sorted(data["result"][0]["expressions"][0]["value"]) if data.get("result") else []
            engine = "opa"
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as exc:
        return {"available": True, "ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    return {"available": True, "ok": True, "engine": engine, "denials": len(msgs), "messages": msgs[:25]}


# ---------------------------------------------------------------- registered tool


def run_policy_check(ctx: ToolContext) -> ToolOutput:
    from guardian.tools.threat_intel import IntelClient

    cfg = ctx.artifacts.get("guardian_config") or load_config()
    root = ctx.work_dir or ctx.repo
    lock_root = ctx.artifacts.get("policy_lock_root") or ctx.repo
    intel = IntelClient(ctx=ctx, agent="detection")
    doc = build_policy_input(root, cfg, intel=intel, lock_root=lock_root)
    (ctx.run_dir / "policy_input.json").write_text(json.dumps(doc, indent=1), encoding="utf-8")
    violations = policy_check(doc, cfg)
    rego = run_rego(doc, ctx.run_dir)
    if rego.get("ok"):
        rego["agrees_with_native"] = rego["denials"] == len(violations)
    by_rule: dict[str, list[dict]] = {}
    for v in violations:
        by_rule.setdefault(v["rule"], []).append(v)

    base = {"checked": {"actions": len(doc["actions"]), "images": len(doc["images"]),
                        "packages": len(doc["packages"]), "has_lockfile": doc["has_lockfile"]},
            "rego": rego, "engine": "native" + (f"+{rego['engine']}" if rego.get("engine") else "")}
    evidence, findings = [], []
    if not by_rule:
        evidence.append(Evidence(run_id=ctx.run_id, kind="policy_result", source_tool="policy_check",
                                 facts={**base, "violations": [], "count": 0, "passed": True},
                                 artifact_path="policy_input.json"))
    for rule, items in by_rule.items():
        first = items[0]
        ev = Evidence(run_id=ctx.run_id, kind="policy_result", source_tool="policy_check",
                      facts={**base, "rule": rule, "violations": items[:50], "count": len(items), "passed": False},
                      file_path=first.get("file"), line=first.get("line"), excerpt=first["message"],
                      artifact_path="policy_input.json")
        evidence.append(ev)
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.POLICY_VIOLATION, detector="detector:policy_check",
            title=f"Policy {rule}: {len(items)} violation{'s' if len(items) != 1 else ''} ({RULES[rule]})",
            scope=Scope.PROD, project="root", file_path=first.get("file"), line=first.get("line"),
            evidence_ids=[ev.evidence_id]))
    return ToolOutput(findings=findings, evidence=evidence,
                      artifacts={"policy_violations": violations},
                      summary=f"{len(violations)} violations in {len(by_rule)} rules ({base['engine']})")
