# Document the contract for the surrounding module or callable.
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

Called by: the detection agent (tool `changes`; `mini_diff` is the older CP1 binding). The investigator's
manifest_diff tool and the report read the `changes` artifact it returns.
Inputs: package.json and package-lock.json of each npm project, the shipped `ftp/*.bak` baseline files, and for
--compare-ref the same files read from git (`git show <sha>:<path>`; the ref is validated first). No network.
Output: Findings (scope unknown, at most MAX_FINDINGS_PER_KIND per category) with Evidence kind `diff`, facts
{compare_ref, project, change: added | major_jump | integrity | install_script_added, ...}; plus one Evidence kind
`changes` with the counts {base, head, added, removed, changed, major_jumps, integrity_changed,
install_scripts_added, removed_names}. With no baseline at all the tool reports that and emits nothing.
"""

# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Load json for unexpected change tests.
import json
# Load re for unexpected change tests.
import re
# Import Path from pathlib.
from pathlib import Path

# Import find_projects, line_of, purl from guardian.adapters.npm.
from guardian.adapters.npm import find_projects, line_of, purl
# Import Evidence, Finding, FindingCategory, Scope from guardian.core.models.
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
# Import run from guardian.tools.binaries.
from guardian.tools.binaries import run
# Import ToolContext, ToolOutput from guardian.tools.registry.
from guardian.tools.registry import ToolContext, ToolOutput

# Legacy baseline: old copies of the manifests that ship inside the target (the diff is "then vs now").
# Give BASE_MANIFEST its starting value.
# The initial value is 'ftp/package.json.bak'.
BASE_MANIFEST = "ftp/package.json.bak"
# Give BASE_LOCK its starting value.
# The initial value is 'ftp/package-lock.json.bak'.
BASE_LOCK = "ftp/package-lock.json.bak"
# First version found in a range string: major[.minor[.patch]] (so "^4.17.1" -> 4, 17, 1).
# Store the result of re.compile in _VER.
_VER = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
# Conservative git ref syntax (branch/tag/sha/HEAD~2); rejects spaces, leading "-" and shell metacharacters so a
# user-supplied --compare-ref cannot inject git options.
# Store the result of re.compile in _GIT_REF.
_GIT_REF = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./~^@{}-]{0,99}$")
# Give MAX_FINDINGS_PER_KIND its starting value.
# The initial value is 25.
MAX_FINDINGS_PER_KIND = 25  # a huge diff is one story, not 500 findings; counts stay complete in changes.json


# ---------------------------------------------------------------- pure diff helpers


# Define _deps for unexpected change tests.
# Inputs include data.
def _deps(data: dict) -> dict[str, str]:
    # Document the contract for the surrounding module or callable.
    """{name: version range} of dependencies and devDependencies of a parsed package.json."""
    # Return a mapping keyed by the fields below to the caller.
    return {**data.get("dependencies", {}), **data.get("devDependencies", {})}


# Define _base for unexpected change tests.
# Inputs include rng.
def _base(rng: str) -> str:
    # Document the contract for the surrounding module or callable.
    """The plain version inside a range ("^4.17.1" -> "4.17.1"); the input unchanged if none is found."""
    # Store the result of _VER.search in m.
    m = _VER.search(rng)
    # Return the expression on this line to the caller.
    return ".".join(g for g in m.groups() if g is not None) if m else rng


# Define _major for unexpected change tests.
# Inputs include rng.
def _major(rng: str) -> int | None:
    # Document the contract for the surrounding module or callable.
    """Major version number inside a range string, or None."""
    # Store the result of _VER.search in m.
    m = _VER.search(rng)
    # Return int(m.group(1)) if m else None to the caller.
    return int(m.group(1)) if m else None


# Define _lock_index for unexpected change tests.
# Inputs include data.
def _lock_index(data: dict) -> dict[str, dict]:
    # Document the contract for the surrounding module or callable.
    """name@version -> {integrity, install_script}, lockfile v1 (nested) and v2/v3 (`packages`).
    v1 lockfiles do not record install scripts, so their entries always say install_script False."""
    # Declare out with type dict[str, dict].
    # Use a mapping keyed by the fields below as its initial value.
    out: dict[str, dict] = {}
    # Iterate over (data.get('packages') or {}).items().
    # Bind each item to (key, e) before processing it.
    for key, e in (data.get("packages") or {}).items():
        # Check whether key and e.get('version').
        if key and e.get("version"):
            # Store e.get('name') or key.rsplit('node_modules/', 1)[-1] in name.
            name = e.get("name") or key.rsplit("node_modules/", 1)[-1]
            # Store a mapping keyed by the fields below in out[f'{name}@{e['version']}'].
            out[f"{name}@{e['version']}"] = {"integrity": e.get("integrity"),
                                              # Provide the mapping fields install_script on this line.
                                              "install_script": bool(e.get("hasInstallScript"))}

    # Define walk for unexpected change tests.
    # Inputs include deps.
    def walk(deps: dict) -> None:
        # Iterate over (deps or {}).items().
        # Bind each item to (name, e) before processing it.
        for name, e in (deps or {}).items():
            # Check whether e.get('version').
            if e.get("version"):
                # Call out.setdefault at this point.
                out.setdefault(f"{name}@{e['version']}", {"integrity": e.get("integrity"), "install_script": False})
            # Call walk at this point.
            walk(e.get("dependencies"))

    # Call walk at this point.
    walk(data.get("dependencies"))
    # Return out to the caller.
    return out


# Define diff_manifests for unexpected change tests.
# Inputs include base, head.
def diff_manifests(base: dict, head: dict) -> dict:
    # Document the contract for the surrounding module or callable.
    """Compare two parsed package.json files: {added: [purl], removed: [purl], changed: [{name, from, to,
    from_range, to_range, major_jump}]}. A major_jump is a rise of the major version of at least 1."""
    # Store (_deps(base), _deps(head)) in (b, h).
    b, h = _deps(base), _deps(head)
    # Store the result of sorted in added.
    added = sorted(purl(n, _base(h[n])) for n in h.keys() - b.keys())
    # Store the result of sorted in removed.
    removed = sorted(purl(n, _base(b[n])) for n in b.keys() - h.keys())
    # Store an ordered collection in changed.
    changed = []
    # Iterate over sorted(b.keys() & h.keys()).
    # Bind each item to n before processing it.
    for n in sorted(b.keys() & h.keys()):
        # Check whether b[n] != h[n].
        if b[n] != h[n]:
            # Store (_major(b[n]), _major(h[n])) in (mb, mh).
            mb, mh = _major(b[n]), _major(h[n])
            # Call changed.append at this point.
            changed.append({"name": n, "from": _base(b[n]), "to": _base(h[n]), "from_range": b[n], "to_range": h[n],
                            # Provide the mapping fields major_jump on this line.
                            "major_jump": mb is not None and mh is not None and mh - mb >= 1})
    # Return a mapping keyed by the fields below to the caller.
    return {"added": added, "removed": removed, "changed": changed}


# Define diff_locks for unexpected change tests.
# Inputs include base, head.
def diff_locks(base: dict, head: dict) -> dict:
    # Document the contract for the surrounding module or callable.
    """Compare two parsed lockfiles: {integrity_changed: [{purl, from, to}], install_scripts_added: [{purl,
    new_package}]}. Only name@version pairs present in both are checked for integrity: the same release must
    always hash the same, so a different digest means the published bytes were swapped."""
    # Store (_lock_index(base), _lock_index(head)) in (bi, hi).
    bi, hi = _lock_index(base), _lock_index(head)
    # Store ([], []) in (integrity, scripts).
    integrity, scripts = [], []
    # Iterate over sorted(bi.keys() & hi.keys()).
    # Bind each item to key before processing it.
    for key in sorted(bi.keys() & hi.keys()):
        # Store (bi[key]['integrity'], hi[key]['integrity']) in (fb, fh).
        fb, fh = bi[key]["integrity"], hi[key]["integrity"]
        # same algorithm, different digest -> the bytes behind name@version changed (sha1 -> sha512 is not)
        # Check whether the expression on this line.
        if fb and fh and fb != fh and fb.split("-")[0] == fh.split("-")[0]:
            # Store the result of key.rpartition in (name, _, ver).
            name, _, ver = key.rpartition("@")
            # Call integrity.append at this point.
            integrity.append({"purl": purl(name, ver), "from": fb, "to": fh})
    # Iterate over sorted(hi.keys()).
    # Bind each item to key before processing it.
    for key in sorted(hi.keys()):
        # Check whether the expression on this line.
        if hi[key]["install_script"] and not (bi.get(key) or {}).get("install_script"):
            # Store the result of key.rpartition in (name, _, ver).
            name, _, ver = key.rpartition("@")
            # Call scripts.append at this point.
            scripts.append({"purl": purl(name, ver), "new_package": key not in bi})
    # Return a mapping keyed by the fields below to the caller.
    return {"integrity_changed": integrity, "install_scripts_added": scripts}


# ---------------------------------------------------------------- legacy baseline (D4-11)


# Define legacy_diff for unexpected change tests.
# Inputs include root.
def legacy_diff(root: Path) -> dict | None:
    # Document the contract for the surrounding module or callable.
    """Diff the shipped legacy baseline against the current manifest/lockfile; None if either manifest is missing."""
    # Store (root / BASE_MANIFEST, root / 'package.json') in (base, head).
    base, head = root / BASE_MANIFEST, root / "package.json"
    # Check whether not base.exists() or not head.exists().
    if not base.exists() or not head.exists():
        # Return None to represent an absent value to the caller.
        return None
    # Store a mapping keyed by the fields below in out.
    out = {"base": BASE_MANIFEST, "head": "package.json",
           # Supply the next part of the expression started above.
           **diff_manifests(json.loads(base.read_text(encoding="utf-8")), json.loads(head.read_text(encoding="utf-8"))),
           # Provide the mapping fields integrity_changed, install_scripts_added on this line.
           "integrity_changed": [], "install_scripts_added": []}
    # Store (root / BASE_LOCK, root / 'package-lock.json') in (base_lock, head_lock).
    base_lock, head_lock = root / BASE_LOCK, root / "package-lock.json"
    # Check whether base_lock.exists() and head_lock.exists().
    if base_lock.exists() and head_lock.exists():
        # Store the result of diff_locks in locks.
        locks = diff_locks(json.loads(base_lock.read_text(encoding="utf-8")),
                           # Supply the next part of the expression started above.
                           json.loads(head_lock.read_text(encoding="utf-8")))
        # Store locks['integrity_changed'] in out['integrity_changed'].
        out["integrity_changed"] = locks["integrity_changed"]  # install scripts vs a years-old backup: noise
    # Return out to the caller.
    return out


# Define mini_diff for unexpected change tests.
# Inputs include ctx.
def mini_diff(ctx: ToolContext) -> ToolOutput:
    # Document the contract for the surrounding module or callable.
    """CP1 entry point (kept for the D4-11 binding): legacy diff only."""
    # Return the result of _output to the caller.
    return _output(ctx, None, legacy_diff(ctx.work_dir or ctx.repo), [], [])


# ---------------------------------------------------------------- compare-ref baseline (D2-06)


# Define git_show for unexpected change tests.
# Inputs include repo, ref, rel.
def git_show(repo: Path, ref: str, rel: str) -> str | None:
    # Document the contract for the surrounding module or callable.
    """File contents at a git ref, or None if the path does not exist there (git exits 128)."""
    # Store the result of run in proc.
    proc = run(["git", "-C", str(repo), "show", f"{ref}:{rel}"], timeout=30, ok_codes=(0, 128))
    # Return proc.stdout if proc.returncode == 0 else None to the caller.
    return proc.stdout if proc.returncode == 0 else None


# Define compare_ref_diff for unexpected change tests.
# Inputs include repo, work, ref.
def compare_ref_diff(repo: Path, work: Path, ref: str) -> tuple[dict, list[dict]]:
    # Document the contract for the surrounding module or callable.
    """Diff every npm project of the target between `ref` and the working tree. Returns (changes, per-project)."""
    # Check whether not _GIT_REF.match(ref).
    if not _GIT_REF.match(ref):
        # Raise ValueError(f'unexpected git ref {ref!r}').
        # The error leaves this branch and can be handled by the caller.
        raise ValueError(f"unexpected git ref {ref!r}")
    # resolve to a full commit SHA once, so every later `git show` reads the same commit even if the ref moves
    # Store the result of the expression on this line in sha.
    sha = run(["git", "-C", str(repo), "rev-parse", "--verify", f"{ref}^{{commit}}"], timeout=30).stdout.strip()
    # Store a mapping keyed by the fields below in total.
    total = {"base": f"{ref} ({sha[:12]})", "head": "working tree", "added": [], "removed": [], "changed": [],
             # Provide the mapping fields integrity_changed, install_scripts_added, compare_ref, compare_sha on this line.
             "integrity_changed": [], "install_scripts_added": [], "compare_ref": ref, "compare_sha": sha}
    # Store an ordered collection in per_project.
    per_project = []
    # Iterate over find_projects(repo).
    # Bind each item to proj before processing it.
    for proj in find_projects(repo):
        # Store '' if proj.name == 'root' else f'{proj.name}/' in rel_dir.
        rel_dir = "" if proj.name == "root" else f"{proj.name}/"  # sub-project folder prefix inside the repo
        # Store the result of git_show in old_manifest.
        old_manifest = git_show(repo, sha, f"{rel_dir}package.json")
        # Check whether old_manifest is None.
        if old_manifest is None:
            # Store a mapping keyed by the fields below in entry.
            entry = {"project": proj.name, "new_project": True}  # project did not exist at the ref: nothing to diff
            # Call per_project.append at this point.
            per_project.append(entry)
            # Skip the remaining work for this item.
            continue
        # Store the result of diff_manifests in d.
        d = diff_manifests(json.loads(old_manifest), json.loads(proj.manifest.read_text(encoding="utf-8")))
        # Store a mapping keyed by the fields below in locks.
        locks = {"integrity_changed": [], "install_scripts_added": []}
        # Store the result of git_show in old_lock.
        old_lock = git_show(repo, sha, f"{rel_dir}package-lock.json")
        # the target may commit no lockfile; then the one Guardian generated in the work copy is the "head"
        # Store the expression on this line in head_lock.
        head_lock = proj.lockfile if proj.lockfile.exists() else work / rel_dir / "package-lock.json"
        # Check whether old_lock and head_lock.exists().
        if old_lock and head_lock.exists():
            # Store the result of diff_locks in locks.
            locks = diff_locks(json.loads(old_lock), json.loads(head_lock.read_text(encoding="utf-8")))
        # Iterate over ('added', 'removed').
        # Bind each item to k before processing it.
        for k in ("added", "removed"):
            # Update the existing value of total[k].
            # The update incorporates d[k].
            total[k] += d[k]
        # Update the existing value of total['changed'].
        # The update incorporates values selected or transformed from the input.
        total["changed"] += [{**c, "project": proj.name} for c in d["changed"]]
        # Update the existing value of total['integrity_changed'].
        # The update incorporates values selected or transformed from the input.
        total["integrity_changed"] += [{**c, "project": proj.name} for c in locks["integrity_changed"]]
        # Update the existing value of total['install_scripts_added'].
        # The update incorporates values selected or transformed from the input.
        total["install_scripts_added"] += [{**c, "project": proj.name} for c in locks["install_scripts_added"]]
        # Call per_project.append at this point.
        per_project.append({"project": proj.name, "manifest": f"{rel_dir}package.json", **d, **locks,
                            # Provide the mapping fields lockfile_compared on this line.
                            "lockfile_compared": bool(old_lock and head_lock.exists())})
    # Return (total, per_project) to the caller.
    return total, per_project


# Define _findings for unexpected change tests.
# Inputs include ctx, ref, per_project.
def _findings(ctx: ToolContext, ref: str, per_project: list[dict]) -> tuple[list[Finding], list[Evidence]]:
    # Document the contract for the surrounding module or callable.
    """Turn per-project compare-ref diffs into Findings + `diff` Evidence: new dependency (unexpected_change),
    major jump, integrity change, install script added. Each kind is capped at MAX_FINDINGS_PER_KIND."""
    # Store ([], []) in (findings, evidence).
    findings, evidence = [], []
    # Declare counts with type dict[str, int].
    # Use a mapping keyed by the fields below as its initial value.
    counts: dict[str, int] = {}  # findings emitted so far per category, for the cap

    # Define add for unexpected change tests.
    # Inputs include category, title, project, file_path, facts, component, line.
    def add(category: FindingCategory, title: str, project: str, file_path: str, facts: dict,
            # Continue the function signature with its remaining arguments.
            component: str | None, line: int | None = None) -> None:
        # Check whether counts.get(category.value, 0) >= MAX_FINDINGS_PER_KIND.
        if counts.get(category.value, 0) >= MAX_FINDINGS_PER_KIND:
            # Return the current value to the caller.
            return
        # Store counts.get(category.value, 0) + 1 in counts[category.value].
        counts[category.value] = counts.get(category.value, 0) + 1
        # Store the result of Evidence in ev.
        ev = Evidence(run_id=ctx.run_id, kind="diff", source_tool="detector:unexpected_change",
                      # Supply facts, file_path, line as named arguments to the surrounding call.
                      # These names connect the values to the receiving parameters.
                      facts={"compare_ref": ref, "project": project, **facts}, file_path=file_path, line=line)
        # Call evidence.append at this point.
        evidence.append(ev)
        # Call findings.append at this point.
        findings.append(Finding(run_id=ctx.run_id, category=category, title=title,
                                # Supply detector, component_purl, scope as named arguments to the surrounding call.
                                # These names connect the values to the receiving parameters.
                                detector="detector:unexpected_change", component_purl=component, scope=Scope.UNKNOWN,
                                # Supply project, file_path, line, evidence_ids as named arguments to the surrounding call.
                                # These names connect the values to the receiving parameters.
                                project=project, file_path=file_path, line=line, evidence_ids=[ev.evidence_id]))

    # Iterate over per_project.
    # Bind each item to p before processing it.
    for p in per_project:
        # Check whether p.get('new_project').
        if p.get("new_project"):
            # Skip the remaining work for this item.
            continue
        # Store (p['project'], p['manifest']) in (proj, manifest).
        proj, manifest = p["project"], p["manifest"]
        # Store ctx.repo / manifest in mpath.
        mpath = ctx.repo / manifest
        # Iterate over p['added'].
        # Bind each item to added before processing it.
        for added in p["added"]:
            # purl pkg:npm/%40scope/name@1.0.0 -> "@scope/name" (drop "pkg:npm/" prefix and "@version" suffix)
            # Store the result of added.split('/', 1)[1].rsplit('@', 1)[0].replace in name.
            name = added.split("/", 1)[1].rsplit("@", 1)[0].replace("%40", "@")
            # Store the result of line_of in line.
            line = line_of(mpath, rf'^\s*"{re.escape(name)}"\s*:')
            # Call add at this point.
            add(FindingCategory.UNEXPECTED_CHANGE, f"New dependency {name} added since {ref}", proj, manifest,
                # Supply the next part of the expression started above.
                {"change": "added", "purl": added, "name": name}, added, line)
        # Iterate over p['changed'].
        # Bind each item to c before processing it.
        for c in p["changed"]:
            # Check whether c['major_jump'].
            if c["major_jump"]:
                # Store the result of line_of in line.
                line = line_of(mpath, rf'^\s*"{re.escape(c["name"])}"\s*:')
                # Call add at this point.
                add(FindingCategory.MAJOR_JUMP, f"{c['name']} jumped a major version {c['from']} -> {c['to']} since {ref}",
                    # Supply the next part of the expression started above.
                    proj, manifest, {"change": "major_jump", "name": c["name"], "from": c["from_range"],
                                     # Provide the mapping fields to on this line.
                                     "to": c["to_range"]}, purl(c["name"], c["to"]), line)
        # Store f'{('' if proj == 'root' else proj + '/')}package-lock.json' in lock.
        lock = f"{'' if proj == 'root' else proj + '/'}package-lock.json"
        # Iterate over p['integrity_changed'].
        # Bind each item to c before processing it.
        for c in p["integrity_changed"]:
            # Call add at this point.
            add(FindingCategory.INTEGRITY_CHANGE, f"Integrity hash of {c['purl']} changed since {ref}", proj, lock,
                # Supply the next part of the expression started above.
                {"change": "integrity", "purl": c["purl"], "from": c["from"], "to": c["to"]}, c["purl"])
        # Iterate over p['install_scripts_added'].
        # Bind each item to c before processing it.
        for c in p["install_scripts_added"]:
            # Store the expression on this line in what.
            what = "new dependency with an install script" if c["new_package"] else "install script added"
            # Call add at this point.
            add(FindingCategory.INSTALL_SCRIPT, f"{c['purl']}: {what} since {ref}", proj, lock,
                # Supply the next part of the expression started above.
                {"change": "install_script_added", "purl": c["purl"], "new_package": c["new_package"]}, c["purl"])
    # Return (findings, evidence) to the caller.
    return findings, evidence


# Define _output for unexpected change tests.
# Inputs include ctx, compare, legacy, findings, evidence.
def _output(ctx: ToolContext, compare: dict | None, legacy: dict | None, findings: list, evidence: list) -> ToolOutput:
    # Document the contract for the surrounding module or callable.
    """Assemble the ToolOutput: the summary `changes` Evidence, the `changes` artifact (full diff for the report
    and the investigator) and, for a legacy-only run, integrity findings. The compare-ref diff wins as the main
    diff when both exist; the legacy one is nested under changes["legacy"]."""
    # Check whether compare is None and legacy is None.
    if compare is None and legacy is None:
        # Return the result of ToolOutput to the caller.
        return ToolOutput(summary="no baseline to compare (no --compare-ref, no legacy manifest)")
    # Store compare or legacy in main.
    main = compare or legacy
    # Store a mapping keyed by the fields below in facts.
    facts = {"base": main["base"], "head": main["head"], "added": len(main["added"]),
             # Provide the mapping fields removed, changed on this line.
             "removed": len(main["removed"]), "changed": len(main["changed"]),
             # Provide the mapping fields major_jumps on this line.
             "major_jumps": sum(c["major_jump"] for c in main["changed"]),
             # Provide the mapping fields integrity_changed on this line.
             "integrity_changed": len(main["integrity_changed"]),
             # Provide the mapping fields install_scripts_added on this line.
             "install_scripts_added": len(main["install_scripts_added"]),
             # Provide the mapping fields removed_names on this line.
             "removed_names": [r.split("/")[-1] for r in main["removed"]][:50]}
    # Store the result of Evidence in ev.
    ev = Evidence(run_id=ctx.run_id, kind="changes", source_tool="detector:unexpected_change", facts=facts,
                  # Supply file_path as named arguments to the surrounding call.
                  # These names connect the values to the receiving parameters.
                  file_path=main["base"] if main is legacy else None)
    # artifact stored as changes.json; evidence ids let the report link each change to its proof (capped at 200)
    # Store a mapping keyed by the fields below in changes.
    changes = {**main, "evidence_ids": [ev.evidence_id, *(e.evidence_id for e in evidence)][:200]}
    # Check whether compare is not None and legacy is not None.
    if compare is not None and legacy is not None:
        # Store a mapping keyed by the fields below in changes['legacy'].
        changes["legacy"] = {**legacy, "evidence_ids": [ev.evidence_id]}  # same changes evidence covers both
    # Check whether legacy is not None and compare is None.
    if legacy is not None and compare is None:  # integrity changes vs the backup are still findings
        # Iterate over legacy['integrity_changed'].
        # Bind each item to c before processing it.
        for c in legacy["integrity_changed"]:
            # Store the result of Evidence in fev.
            fev = Evidence(run_id=ctx.run_id, kind="diff", source_tool="detector:unexpected_change",
                           # Supply facts, file_path as named arguments to the surrounding call.
                           # These names connect the values to the receiving parameters.
                           facts={"change": "integrity", "baseline": BASE_LOCK, **c}, file_path=BASE_LOCK)
            # Call evidence.append at this point.
            evidence.append(fev)
            # Call findings.append at this point.
            findings.append(Finding(run_id=ctx.run_id, category=FindingCategory.INTEGRITY_CHANGE,
                                    # Supply title as named arguments to the surrounding call.
                                    # These names connect the values to the receiving parameters.
                                    title=f"Integrity hash of {c['purl']} differs from {BASE_LOCK}",
                                    # Supply detector, component_purl as named arguments to the surrounding call.
                                    # These names connect the values to the receiving parameters.
                                    detector="detector:unexpected_change", component_purl=c["purl"],
                                    # Supply project, file_path, evidence_ids as named arguments to the surrounding call.
                                    # These names connect the values to the receiving parameters.
                                    project="root", file_path="package-lock.json", evidence_ids=[fev.evidence_id]))
    # Store the expression on this line in summary.
    summary = (f"vs {main['base']}: +{facts['added']} / -{facts['removed']} / ~{facts['changed']} deps, "
               # Supply the next part of the expression started above.
               f"{facts['major_jumps']} major jumps, {facts['integrity_changed']} integrity changes, "
               # Supply the next part of the expression started above.
               f"{facts['install_scripts_added']} install scripts added -> {len(findings)} findings")
    # Return the result of ToolOutput to the caller.
    return ToolOutput(findings=findings, evidence=[ev, *evidence], artifacts={"changes": changes}, summary=summary)


# Define detect for unexpected change tests.
# Inputs include ctx.
def detect(ctx: ToolContext) -> ToolOutput:
    # Document the contract for the surrounding module or callable.
    """Entry point of the `changes` tool: legacy diff always, compare-ref diff + findings when
    ctx.artifacts["compare_ref"] is set. Raises ValueError for a malformed git ref."""
    # Store ctx.work_dir or ctx.repo in work.
    work = ctx.work_dir or ctx.repo
    # Store the result of legacy_diff in legacy.
    legacy = legacy_diff(work)
    # Store the result of ctx.artifacts.get in ref.
    ref = ctx.artifacts.get("compare_ref")
    # Check whether not ref.
    if not ref:
        # Return the result of _output to the caller.
        return _output(ctx, None, legacy, [], [])
    # Store the result of compare_ref_diff in (compare, per_project).
    compare, per_project = compare_ref_diff(ctx.repo, work, ref)
    # Store the result of _findings in (findings, evidence).
    findings, evidence = _findings(ctx, ref, per_project)
    # Return the result of _output to the caller.
    return _output(ctx, compare, legacy, findings, evidence)
