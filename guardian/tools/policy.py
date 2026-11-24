# Document the contract for the surrounding module or callable.
"""Policy-as-code (D4-07; ported from dev04 and adapted to this branch's adapters/registry/evidence).

Called by: the detection agent (registered tool `policy_check`) and the validator, which may re-run it on a
patched copy to prove a policy violation is gone (set ctx.artifacts["policy_lock_root"] to the patched copy so
the lockfile check looks there instead of the original repo).

Rules (guardian.yaml `policies` / `thresholds` / `denylist`): lockfile committed, GitHub Actions pinned to a
commit SHA, base images pinned by digest, no denylisted / typosquat packages, no package younger than N days.

* `policy_check(doc, config)` evaluates the rules natively (no OPA needed) over one input document.
* The same rules exist as Rego in policies/guardian.rego. If `conftest` or `opa` is on PATH the Rego is also run on
  the same document and both results are recorded in the `policy_result` Evidence (`facts.rego`).
* `run_policy_check(ctx)` writes `policy_input.json`, one `policy_result` Evidence per rule that fired (or one
  passing result) and one aggregated `policy_violation` Finding per rule.
  policy_result facts: {checked{actions,images,packages,has_lockfile}, rego, engine, rule, violations (max 50),
  count, passed}. The Finding is scoped prod / project "root" and points at the first violation's file and line.

Network: only package ages need the npm registry (IntelClient: G3.5 allowlist, disk cache, throttle, at most
AGE_LOOKUP_CAP lookups per run). Offline or on a cache miss the age is None = unknown, and that rule is skipped
rather than guessed. Rego is optional: when neither tool is installed the native result stands alone.

Input document: {has_lockfile, actions:[{file,line,uses}], images:[{file,line,image}],
                 packages:[{name, version, age_days|None, typosquat_of|None, denylisted}]}
"""
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Load json for repository policy evaluation.
import json
# Load os for repository policy evaluation.
import os
# Load shutil for repository policy evaluation.
import shutil
# Load subprocess for repository policy evaluation.
import subprocess
# Import UTC, datetime from datetime.
from datetime import UTC, datetime
# Import Path from pathlib.
from pathlib import Path

# Load yaml for repository policy evaluation.
import yaml

# Import dockerfile, github_actions, npm, pypi from guardian.adapters.
from guardian.adapters import dockerfile, github_actions, npm, pypi
# Import REPO_ROOT from guardian.core.config.
from guardian.core.config import REPO_ROOT
# Import Evidence, Finding, FindingCategory, Scope from guardian.core.models.
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
# Import ToolContext, ToolOutput from guardian.tools.registry.
from guardian.tools.registry import ToolContext, ToolOutput

# Store REPO_ROOT / 'guardian.yaml' in DEFAULT_CONFIG.
DEFAULT_CONFIG = REPO_ROOT / "guardian.yaml"
# Store REPO_ROOT / 'policies' in POLICY_DIR.
POLICY_DIR = REPO_ROOT / "policies"
# Give AGE_LOOKUP_CAP its starting value.
# The initial value is 80.
AGE_LOOKUP_CAP = 80  # registry lookups for package age per run (cached, throttled)

# Rule id -> human-readable reason; also used as the finding title suffix and by the Rego policy messages.
# Store a mapping keyed by the fields below in RULES.
RULES = {
    # Provide the mapping fields missing_lockfile on this line.
    "missing_lockfile": "No lockfile committed; installs are not reproducible",
    # Provide the mapping fields unpinned_action on this line.
    "unpinned_action": "GitHub Action not pinned to a commit SHA",
    # Provide the mapping fields tag_only_image on this line.
    "tag_only_image": "Base image not pinned by digest",
    # Provide the mapping fields denylisted_package on this line.
    "denylisted_package": "Package is on the guardian.yaml denylist",
    # Provide the mapping fields typosquat_package on this line.
    "typosquat_package": "Package name looks like a popular package",
    # Provide the mapping fields package_too_new on this line.
    "package_too_new": "Package first published less than the minimum age ago",
# Close the current expression or collection.
}


# Define load_config for repository policy evaluation.
# Inputs include path.
def load_config(path: Path | str | None = None) -> dict:
    # Document the contract for the surrounding module or callable.
    """Read guardian.yaml (path argument, else env GUARDIAN_CONFIG, else the repo default). A missing or empty
    file gives {} so every rule falls back to its default (all rules on)."""
    # Store the result of Path in p.
    p = Path(path or os.environ.get("GUARDIAN_CONFIG") or DEFAULT_CONFIG)
    # Check whether not p.exists().
    if not p.exists():
        # Return a mapping keyed by the fields below to the caller.
        return {}
    # Return yaml.safe_load(p.read_text(encoding='utf-8')) or {} to the caller.
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


# Define min_age_days for repository policy evaluation.
# Inputs include cfg.
def min_age_days(cfg: dict) -> int | None:
    # Document the contract for the surrounding module or callable.
    """Minimum package age in days from thresholds; None disables the rule.
    `max_package_age_days` is the old (misleading) key name, still accepted."""
    # Store the result of cfg.get in thr.
    thr = cfg.get("thresholds", {})
    # Return the result of thr.get to the caller.
    return thr.get("min_package_age_days", thr.get("max_package_age_days"))


# Define _v for repository policy evaluation.
# Inputs include rule, message, file, line.
def _v(rule: str, message: str, file: str | None = None, line: int | None = None, **extra) -> dict:
    # Document the contract for the surrounding module or callable.
    """One violation record; `extra` carries e.g. the package name."""
    # Return a mapping keyed by the fields below to the caller.
    return {"rule": rule, "message": message, "file": file, "line": line, **extra}


# Define _is_sha for repository policy evaluation.
# Inputs include ref.
def _is_sha(ref: str) -> bool:
    # Document the contract for the surrounding module or callable.
    """A full 40-character lowercase hex commit SHA (a short SHA or a tag is mutable/ambiguous, so not accepted)."""
    # Return len(ref) == 40 and all((c in '0123456789abcdef' for c in ref)) to the caller.
    return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref)


# Define _has_digest for repository policy evaluation.
# Inputs include image.
def _has_digest(image: str) -> bool:
    # Document the contract for the surrounding module or callable.
    """True when the image reference carries an @sha256:<64 hex> digest (content-addressed, cannot be moved)."""
    # Store the result of image.partition in (_, _, d).
    _, _, d = image.partition("@sha256:")
    # Return len(d) == 64 and all((c in '0123456789abcdef' for c in d)) to the caller.
    return len(d) == 64 and all(c in "0123456789abcdef" for c in d)


# Evaluate the supplied repository facts against configured rules.
# Inputs include doc, config.
def policy_check(doc: dict, config: dict | None = None) -> list[dict]:
    # Document the contract for the surrounding module or callable.
    """Native evaluation of the guardian rules over `doc`. Returns violations (empty = pass).

    `config` defaults to guardian.yaml. Each violation is {rule, message, file, line, ...}. Rules can be turned
    off with policies.require_lockfile / require_pinned_actions / require_pinned_base_images (default on); the
    denylist and the age threshold come from `denylist` and `thresholds`. A package with unknown age
    (age_days None) is never reported as too new."""
    # Store config if config is not None else load_config() in cfg.
    cfg = config if config is not None else load_config()
    # Store the result of cfg.get in pol.
    pol = cfg.get("policies", {})
    # Declare out with type list[dict].
    # Use an ordered collection as its initial value.
    out: list[dict] = []

    # Check whether the expression on this line.
    if pol.get("require_lockfile", True) and not doc.get("has_lockfile", True):
        # Call out.append at this point.
        out.append(_v("missing_lockfile", RULES["missing_lockfile"]))

    # Check whether pol.get('require_pinned_actions', True).
    if pol.get("require_pinned_actions", True):
        # Iterate over doc.get('actions', []).
        # Bind each item to a before processing it.
        for a in doc.get("actions", []):
            # Store a['uses'] in ref.
            ref = a["uses"]
            # Check whether ref.startswith(('./', 'docker://')).
            if ref.startswith(("./", "docker://")):  # local composite action / docker image: no ref to pin
                # Skip the remaining work for this item.
                continue
            # Store ref.split('@', 1)[1] if '@' in ref else '' in version.
            version = ref.split("@", 1)[1] if "@" in ref else ""
            # Check whether not _is_sha(version).
            if not _is_sha(version):
                # Call out.append at this point.
                out.append(_v("unpinned_action", f"{ref} is not pinned to a 40-char commit SHA",
                              # Supply the next part of the expression started above.
                              a.get("file"), a.get("line")))

    # Check whether pol.get('require_pinned_base_images', True).
    if pol.get("require_pinned_base_images", True):
        # Iterate over doc.get('images', []).
        # Bind each item to i before processing it.
        for i in doc.get("images", []):
            # Store i['image'] in img.
            img = i["image"]
            # Check whether img.lower() != 'scratch' and (not _has_digest(img)).
            if img.lower() != "scratch" and not _has_digest(img):
                # Call out.append at this point.
                out.append(_v("tag_only_image", f"{img} is not pinned by digest", i.get("file"), i.get("line")))

    # denylist from guardian.yaml: lowercase name -> why it is banned (names are compared case-insensitively)
    # Store a lookup built from the input records in deny.
    deny = {str(d["name"]).lower(): d.get("reason", "") for d in cfg.get("denylist", [])}
    # Store the result of min_age_days in min_age.
    min_age = min_age_days(cfg)
    # Iterate over doc.get('packages', []).
    # Bind each item to p before processing it.
    for p in doc.get("packages", []):
        # Store p['name'] in name.
        name = p["name"]
        # Check whether p.get('denylisted') or name.lower() in deny.
        if p.get("denylisted") or name.lower() in deny:
            # Store the result of deny.get in reason.
            reason = deny.get(name.lower(), "")
            # Call out.append at this point.
            out.append(_v("denylisted_package", f"{name} is denylisted" + (f": {reason}" if reason else ""),
                          # Supply the next part of the expression started above.
                          p.get("file"), p.get("line"), package=name))
        # Check whether p.get('typosquat_of').
        if p.get("typosquat_of"):
            # Call out.append at this point.
            out.append(_v("typosquat_package", f"{name} looks like {p['typosquat_of']}",
                          # Supply the next part of the expression started above.
                          p.get("file"), p.get("line"), package=name))
        # Store the result of p.get in age.
        age = p.get("age_days")
        # Check whether min_age is not None and age is not None and (age < min_age).
        if min_age is not None and age is not None and age < min_age:
            # Call out.append at this point.
            out.append(_v("package_too_new", f"{name} was published {age} days ago (< {min_age})",
                          # Supply the next part of the expression started above.
                          p.get("file"), p.get("line"), package=name))
    # Return out to the caller.
    return out


# ---------------------------------------------------------------- input document


# Define _npm_packages for repository policy evaluation.
# Inputs include root.
def _npm_packages(root: Path) -> list[dict]:
    # Document the contract for the surrounding module or callable.
    """Every distinct dependency name declared in the repo's package.json files (plus the legacy backup manifest),
    as policy-document package entries with age/typosquat/denylist still unset. First declaration wins."""
    # Declare pk with type list[dict].
    # Use an ordered collection as its initial value.
    pk: list[dict] = []
    # Declare seen with type set[str].
    # Use the result of set as its initial value.
    seen: set[str] = set()
    # Store values selected or transformed from the input in manifests.
    manifests = [(p.manifest, p.manifest.relative_to(root).as_posix()) for p in npm.find_projects(root)]
    # Store root / 'ftp' / 'package.json.bak' in legacy.
    legacy = root / "ftp" / "package.json.bak"  # shipped backup manifest (Juice Shop "Legacy Typosquatting")
    # Check whether legacy.exists().
    if legacy.exists():
        # Call manifests.append at this point.
        manifests.append((legacy, "ftp/package.json.bak"))
    # Iterate over manifests.
    # Bind each item to (manifest, rel) before processing it.
    for manifest, rel in manifests:
        # Run the following operation with exception handling.
        # The handlers below determine how the listed failures are handled.
        try:
            # Store the result of npm.manifest_deps in deps.
            deps = npm.manifest_deps(manifest)
        # Handle (ValueError, OSError) from the preceding block.
        except (ValueError, OSError):
            # Skip the remaining work for this item.
            continue
        # Iterate over deps.
        # Bind each item to (name, rng, section, line) before processing it.
        for name, rng, section, line in deps:
            # Check whether name in seen.
            if name in seen:
                # Skip the remaining work for this item.
                continue
            # Call seen.add at this point.
            seen.add(name)
            # Call pk.append at this point.
            pk.append({"name": name, "version": rng, "section": section, "file": rel, "line": line,
                       # Provide the mapping fields age_days, typosquat_of, denylisted on this line.
                       "age_days": None, "typosquat_of": None, "denylisted": False})
    # Return pk to the caller.
    return pk


# Define _has_lockfile for repository policy evaluation.
# Inputs include root.
def _has_lockfile(root: Path) -> bool:
    # Document the contract for the surrounding module or callable.
    """True when every npm project under `root` has a lockfile (vacuously true when there is no npm project)."""
    # Store the result of npm.find_projects in projects.
    projects = npm.find_projects(root)
    # Return the result of all to the caller.
    return all(p.lockfile.exists() for p in projects)  # no npm project -> nothing to lock (pip pins are in-file)


# Define package_age_days for repository policy evaluation.
# Inputs include meta, now.
def package_age_days(meta: dict | None, now: datetime | None = None) -> int | None:
    # Document the contract for the surrounding module or callable.
    """Days since the package was first published (registry `time.created`); None if unknown.
    `now` is injectable for tests. Never negative."""
    # Store the result of ((meta or {}).get('time') or {}).get in created.
    created = ((meta or {}).get("time") or {}).get("created")
    # Check whether not created.
    if not created:
        # Return None to represent an absent value to the caller.
        return None
    # Run the following operation with exception handling.
    # The handlers below determine how the listed failures are handled.
    try:
        # Store the result of datetime.fromisoformat in dt.
        dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
    # Handle ValueError from the preceding block.
    except ValueError:
        # Return None to represent an absent value to the caller.
        return None
    # Return the result of max to the caller.
    return max(0, ((now or datetime.now(UTC)) - dt).days)


# Collect repository facts together with their original source locations.
# Inputs include root, config, intel, lock_root, now.
def build_policy_input(root: Path | str, config: dict | None = None, intel=None,
                       # Continue the function signature with its remaining arguments.
                       lock_root: Path | str | None = None, now: datetime | None = None) -> dict:
    # Document the contract for the surrounding module or callable.
    """Build the evaluator input from a project tree. `intel` (an IntelClient) adds package ages for the first
    AGE_LOOKUP_CAP direct prod packages; without it (or on offline cache misses) age stays None = unknown."""
    # imported here, not at module level, to keep tools.policy importable without the detectors package
    # Import check_name from guardian.tools.detectors.similarity.
    from guardian.tools.detectors.similarity import check_name

    # Store the result of Path in root.
    root = Path(root)
    # Store config if config is not None else load_config() in cfg.
    cfg = config if config is not None else load_config()
    # Store values selected or transformed from the input in deny.
    deny = {str(d["name"]).lower() for d in cfg.get("denylist", [])}
    # Store values selected or transformed from the input in actions.
    actions = [{"file": r.file, "line": r.line, "uses": f"{r.action}@{r.ref}" if r.ref else r.action}
               # Use this clause to iterate or filter the surrounding expression.
               # The collection includes the results of the completed expression.
               for r in github_actions.parse(root) if not r.local]
    # Store the result of dockerfile.parse in (images, _).
    images, _ = dockerfile.parse(root)
    # Store the result of _npm_packages in pk.
    pk = _npm_packages(root)
    # Give looked its starting value.
    # The initial value is 0.
    looked = 0  # registry age lookups spent so far (capped by AGE_LOOKUP_CAP)
    # Iterate over pk.
    # Bind each item to p before processing it.
    for p in pk:
        # Store p['name'].lower() in deny in p['denylisted'].
        p["denylisted"] = p["name"].lower() in deny
        # Store the result of check_name in hit.
        hit = check_name(p["name"])
        # Store hit.popular if hit else None in p['typosquat_of'].
        p["typosquat_of"] = hit.popular if hit else None
        # Check whether the expression on this line.
        if intel is not None and p["section"] == "dependencies" and looked < AGE_LOOKUP_CAP:
            # Update the existing value of looked.
            # The update incorporates 1.
            looked += 1
            # Store the result of package_age_days in p['age_days'].
            p["age_days"] = package_age_days(intel.registry_metadata(npm.purl(p["name"], "0")), now)
    # Python requirements are only checked against the denylist (typosquat/age data is npm-only here)
    # Update the existing value of pk.
    # The update incorporates values selected or transformed from the input.
    pk += [{"name": n, "version": v or "", "section": "requirements", "file": req.name, "line": line,
            # Provide the mapping fields age_days, typosquat_of, denylisted on this line.
            "age_days": None, "typosquat_of": None, "denylisted": n.lower() in deny}
           # Use this clause to iterate or filter the surrounding expression.
           # The collection includes the results of the completed expression.
           for proj in pypi.find_projects(root) for req in proj.requirements
           # Use this clause to iterate or filter the surrounding expression.
           # The collection includes the results of the completed expression.
           for n, v, _spec, line in pypi.requirement_pins(req) if n.lower() in deny]
    # image refs are rebuilt as name[:tag][@digest] so the evaluator sees exactly what the Dockerfile pins
    # Return a mapping keyed by the fields below to the caller.
    return {"has_lockfile": _has_lockfile(Path(lock_root) if lock_root else root),
            # Provide the mapping fields actions on this line.
            "actions": actions,
            # Provide the mapping fields images, line on this line.
            "images": [{"file": i.file, "line": i.line,
                        # Provide the mapping fields image on this line.
                        "image": i.image + (f":{i.tag}" if i.tag else "") + (f"@{i.digest}" if i.digest else "")}
                       # Use this clause to iterate or filter the surrounding expression.
                       # The collection includes the results of the completed expression.
                       for i in images],
            # Provide the mapping fields packages on this line.
            "packages": pk}


# ---------------------------------------------------------------- optional Rego run


# Define run_rego for repository policy evaluation.
# Inputs include doc, workdir, policies.
def run_rego(doc: dict, workdir: Path, policies: Path = POLICY_DIR) -> dict:
    # Document the contract for the surrounding module or callable.
    """Run policies/guardian.rego with `conftest` or `opa` when installed. Never raises.

    Writes policy_input.json into `workdir`. Returns {available: False, note} when neither tool exists,
    {available: True, ok: False, error} when the run failed, else {available, ok, engine, denials, messages[:25]}."""
    # Optional cross-check: prefer conftest (reads the policy dir), fall back to plain opa eval of guardian.rego
    # Store (shutil.which('conftest'), shutil.which('opa')) in (conftest, opa).
    conftest, opa = shutil.which("conftest"), shutil.which("opa")
    # Check whether not conftest and (not opa).
    if not conftest and not opa:
        # Return a mapping keyed by the fields below to the caller.
        return {"available": False, "note": "neither conftest nor opa on PATH; native evaluator only"}
    # Call workdir.mkdir at this point.
    workdir.mkdir(parents=True, exist_ok=True)
    # Store workdir / 'policy_input.json' in inp.
    inp = workdir / "policy_input.json"
    # Call inp.write_text at this point.
    inp.write_text(json.dumps(doc, indent=1), encoding="utf-8")
    # Run the following operation with exception handling.
    # The handlers below determine how the listed failures are handled.
    try:
        # Check whether conftest.
        if conftest:
            # Store the result of subprocess.run in proc.
            proc = subprocess.run([conftest, "test", str(inp), "-p", str(policies), "--namespace", "guardian",
                                   # Supply the next part of the expression started above.
                                   "-o", "json"], capture_output=True, text=True, timeout=60)
            # Store the result of json.loads in data.
            data = json.loads(proc.stdout or "[]")
            # Store values selected or transformed from the input in msgs.
            msgs = [f["msg"] for entry in data for f in entry.get("failures") or []]
            # Give engine its starting value.
            # The initial value is 'conftest'.
            engine = "conftest"
        # Supply the alternative for the preceding condition.
        # This path covers the case where the earlier branch does not apply.
        else:
            # Store the result of subprocess.run in proc.
            proc = subprocess.run([opa, "eval", "-d", str(policies / "guardian.rego"), "-i", str(inp),
                                   # Supply the next part of the expression started above.
                                   "data.guardian.deny", "--format", "json"],
                                  # Supply capture_output, text, timeout as named arguments to the surrounding call.
                                  # These names connect the values to the receiving parameters.
                                  capture_output=True, text=True, timeout=60)
            # Store the result of json.loads in data.
            data = json.loads(proc.stdout or "{}")
            # Store the expression on this line in msgs.
            msgs = sorted(data["result"][0]["expressions"][0]["value"]) if data.get("result") else []
            # Give engine its starting value.
            # The initial value is 'opa'.
            engine = "opa"
    # Handle the expression on this line from the preceding block.
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError) as exc:
        # Return a mapping keyed by the fields below to the caller.
        return {"available": True, "ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    # Return a mapping keyed by the fields below to the caller.
    return {"available": True, "ok": True, "engine": engine, "denials": len(msgs), "messages": msgs[:25]}


# ---------------------------------------------------------------- registered tool


# Define run_policy_check for repository policy evaluation.
# Inputs include ctx.
def run_policy_check(ctx: ToolContext) -> ToolOutput:
    # Document the contract for the surrounding module or callable.
    """Registered tool `policy_check`: build the input document from the work copy, evaluate it (native and, if
    available, Rego) and emit Evidence + one `policy_violation` Finding per rule that fired.

    Side effects: writes policy_input.json (and the Rego input) into the run directory; may query the npm
    registry for package ages through the cache. Returns violations as the `policy_violations` artifact."""
    # Import IntelClient from guardian.tools.threat_intel.
    from guardian.tools.threat_intel import IntelClient

    # Store ctx.artifacts.get('guardian_config') or load_config() in cfg.
    cfg = ctx.artifacts.get("guardian_config") or load_config()
    # Store ctx.work_dir or ctx.repo in root.
    root = ctx.work_dir or ctx.repo
    # the lockfile check reads the ORIGINAL repo (the work copy gets generated lockfiles) unless the validator
    # points it at a patched copy
    # Store ctx.artifacts.get('policy_lock_root') or ctx.repo in lock_root.
    lock_root = ctx.artifacts.get("policy_lock_root") or ctx.repo
    # Store the result of IntelClient in intel.
    intel = IntelClient(ctx=ctx, agent="detection")
    # Store the result of build_policy_input in doc.
    doc = build_policy_input(root, cfg, intel=intel, lock_root=lock_root)
    # Call (ctx.run_dir / 'policy_input.json').write_text at this point.
    (ctx.run_dir / "policy_input.json").write_text(json.dumps(doc, indent=1), encoding="utf-8")
    # Store the result of policy_check in violations.
    violations = policy_check(doc, cfg)
    # Store the result of run_rego in rego.
    rego = run_rego(doc, ctx.run_dir)
    # Check whether rego.get('ok').
    if rego.get("ok"):
        # Store rego['denials'] == len(violations) in rego['agrees_with_native'].
        rego["agrees_with_native"] = rego["denials"] == len(violations)
    # Declare by_rule with type dict[str, list[dict]].
    # Use a mapping keyed by the fields below as its initial value.
    by_rule: dict[str, list[dict]] = {}  # rule id -> its violations (one Finding per rule, not per violation)
    # Iterate over violations.
    # Bind each item to v before processing it.
    for v in violations:
        # Call by_rule.setdefault(v['rule'], []).append at this point.
        by_rule.setdefault(v["rule"], []).append(v)

    # Store a mapping keyed by the fields below in base.
    base = {"checked": {"actions": len(doc["actions"]), "images": len(doc["images"]),
                        # Provide the mapping fields packages, has_lockfile on this line.
                        "packages": len(doc["packages"]), "has_lockfile": doc["has_lockfile"]},
            # Provide the mapping fields rego, engine on this line.
            "rego": rego, "engine": "native" + (f"+{rego['engine']}" if rego.get("engine") else "")}
    # Store ([], []) in (evidence, findings).
    evidence, findings = [], []
    # Check whether not by_rule.
    if not by_rule:  # record the pass too, so "checked and clean" is distinguishable from "never ran"
        # Call evidence.append at this point.
        evidence.append(Evidence(run_id=ctx.run_id, kind="policy_result", source_tool="policy_check",
                                 # Supply facts as named arguments to the surrounding call.
                                 # These names connect the values to the receiving parameters.
                                 facts={**base, "violations": [], "count": 0, "passed": True},
                                 # Supply artifact_path as named arguments to the surrounding call.
                                 # These names connect the values to the receiving parameters.
                                 artifact_path="policy_input.json"))
    # Iterate over by_rule.items().
    # Bind each item to (rule, items) before processing it.
    for rule, items in by_rule.items():
        # Store items[0] in first.
        first = items[0]
        # Store the result of Evidence in ev.
        ev = Evidence(run_id=ctx.run_id, kind="policy_result", source_tool="policy_check",
                      # Supply facts as named arguments to the surrounding call.
                      # These names connect the values to the receiving parameters.
                      facts={**base, "rule": rule, "violations": items[:50], "count": len(items), "passed": False},
                      # Supply file_path, line, excerpt as named arguments to the surrounding call.
                      # These names connect the values to the receiving parameters.
                      file_path=first.get("file"), line=first.get("line"), excerpt=first["message"],
                      # Supply artifact_path as named arguments to the surrounding call.
                      # These names connect the values to the receiving parameters.
                      artifact_path="policy_input.json")
        # Call evidence.append at this point.
        evidence.append(ev)
        # Call findings.append at this point.
        findings.append(Finding(
            # Supply run_id, category, detector as named arguments to the surrounding call.
            # These names connect the values to the receiving parameters.
            run_id=ctx.run_id, category=FindingCategory.POLICY_VIOLATION, detector="detector:policy_check",
            # Supply title as named arguments to the surrounding call.
            # These names connect the values to the receiving parameters.
            title=f"Policy {rule}: {len(items)} violation{'s' if len(items) != 1 else ''} ({RULES[rule]})",
            # Supply scope, project, file_path, line as named arguments to the surrounding call.
            # These names connect the values to the receiving parameters.
            scope=Scope.PROD, project="root", file_path=first.get("file"), line=first.get("line"),
            # Supply evidence_ids as named arguments to the surrounding call.
            # These names connect the values to the receiving parameters.
            evidence_ids=[ev.evidence_id]))
    # Return the result of ToolOutput to the caller.
    return ToolOutput(findings=findings, evidence=evidence,
                      # Supply artifacts as named arguments to the surrounding call.
                      # These names connect the values to the receiving parameters.
                      artifacts={"policy_violations": violations},
                      # Supply summary as named arguments to the surrounding call.
                      # These names connect the values to the receiving parameters.
                      summary=f"{len(violations)} violations in {len(by_rule)} rules ({base['engine']})")
