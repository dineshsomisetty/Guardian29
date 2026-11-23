"""Patch operations (D2-07, Dev2): the ONLY code that edits files, and only inside the run's work copy (G6.6).

Each op edits text in place (keeps formatting, so diffs stay small and reviewable) and returns a unified diff,
stored as Evidence(kind="patch_diff"). Approval is enforced by the registry before any of this runs (G3.3).
Nothing here commits, pushes or publishes (G3.4, G5.5).

Ops (PatchOp.op):
  set_dependency_version  file_path=<package.json>  args={name, version}
  remove_dependency       file_path=<package.json>  args={name}
  replace_dependency      file_path=<package.json>  args={name, new_name, version}
  pin_action_sha          file_path=<workflow.yml>  args={action, ref, sha?}   (tag -> SHA via `git ls-remote`)
  generate_lockfile       file_path=<package.json>  args={}   (drops `package-lock=false`, resolves --ignore-scripts)
"""
from __future__ import annotations

import difflib
import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardian.adapters.npm import parse_manifest, read_npmrc
from guardian.core.workspace import safe_path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+$")
REF_RE = re.compile(r"^[A-Za-z0-9_.\-/]+$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+\-~^<>=| *]+$")
NAME_RE = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")


class PatchError(Exception):
    pass


@dataclass
class PatchResult:
    op: str
    file_path: str  # relative to the work copy, posix
    diff: str  # unified diff of every text file touched (lockfile summarised, see generate_lockfile)
    files: list[str] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------- helpers
def _rel(work: Path, p: Path) -> str:
    return p.resolve().relative_to(Path(work).resolve()).as_posix()


def _udiff(rel: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}"))


def _check(pattern: re.Pattern, value: str, what: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise PatchError(f"invalid {what}: {value!r}")
    return value


def _dep_line(manifest: Path, name: str):
    for d in parse_manifest(manifest):
        if d.name == name:
            return d
    raise PatchError(f"{name} is not declared in {manifest.name}")


def _rewrite_line(text: str, line_no: int, new_line: str | None) -> str:
    """Replace (or delete when new_line is None) a 1-based line, fixing JSON trailing commas on delete."""
    lines = text.splitlines(keepends=True)
    idx = line_no - 1
    if new_line is not None:
        nl = lines[idx][len(lines[idx].rstrip("\r\n")):]
        lines[idx] = new_line + nl
        return "".join(lines)
    removed = lines.pop(idx)
    if not removed.rstrip().endswith(","):  # was the last entry: previous entry must lose its comma
        j = idx - 1
        while j >= 0 and not lines[j].strip():
            j -= 1
        if j >= 0 and lines[j].rstrip("\r\n").endswith(","):
            body = lines[j].rstrip("\r\n")
            lines[j] = body[:-1] + lines[j][len(body):]
    return "".join(lines)


def _entry(old_line: str, name: str, spec: str) -> str:
    indent = old_line[: len(old_line) - len(old_line.lstrip())]
    comma = "," if old_line.rstrip().endswith(",") else ""
    return f'{indent}"{name}": "{spec}"{comma}'


# ---------------------------------------------------------------- ops
def set_dependency_version(work: Path, file_path: str, args: dict) -> PatchResult:
    name = _check(NAME_RE, args.get("name"), "package name")
    version = _check(VERSION_RE, args.get("version"), "version")
    p = safe_path(work, file_path)
    before = p.read_text(encoding="utf-8")
    dep = _dep_line(p, name)
    old = before.splitlines()[dep.line - 1]
    after = _rewrite_line(before, dep.line, _entry(old, name, version))
    p.write_text(after, encoding="utf-8")
    rel = _rel(work, p)
    return PatchResult("set_dependency_version", rel, _udiff(rel, before, after), [rel],
                       {"name": name, "from": dep.spec, "to": version, "section": dep.section})


def remove_dependency(work: Path, file_path: str, args: dict) -> PatchResult:
    name = _check(NAME_RE, args.get("name"), "package name")
    p = safe_path(work, file_path)
    before = p.read_text(encoding="utf-8")
    dep = _dep_line(p, name)
    after = _rewrite_line(before, dep.line, None)
    p.write_text(after, encoding="utf-8")
    rel = _rel(work, p)
    return PatchResult("remove_dependency", rel, _udiff(rel, before, after), [rel],
                       {"name": name, "removed_spec": dep.spec, "section": dep.section})


def replace_dependency(work: Path, file_path: str, args: dict) -> PatchResult:
    name = _check(NAME_RE, args.get("name"), "package name")
    new_name = _check(NAME_RE, args.get("new_name"), "replacement package name")
    version = _check(VERSION_RE, args.get("version"), "version")
    p = safe_path(work, file_path)
    before = p.read_text(encoding="utf-8")
    dep = _dep_line(p, name)
    if any(d.name == new_name for d in parse_manifest(p)):
        raise PatchError(f"{new_name} already declared; use remove_dependency instead")
    old = before.splitlines()[dep.line - 1]
    after = _rewrite_line(before, dep.line, _entry(old, new_name, version))
    p.write_text(after, encoding="utf-8")
    rel = _rel(work, p)
    return PatchResult("replace_dependency", rel, _udiff(rel, before, after), [rel],
                       {"name": name, "new_name": new_name, "version": version, "section": dep.section})


def resolve_action_sha(action: str, ref: str, timeout: int = 30) -> str:
    """Tag/branch -> commit SHA with `git ls-remote` (read-only, github.com is on the §14 allowlist).
    Annotated tags: prefer the peeled `^{}` line (the commit, not the tag object)."""
    owner_repo = "/".join(_check(ACTION_RE, action, "action").split("/")[:2])
    _check(REF_RE, ref, "ref")
    url = f"https://github.com/{owner_repo}"
    r = subprocess.run(["git", "ls-remote", url, f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}"],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise PatchError(f"git ls-remote failed for {url}: {r.stderr.strip()[:200]}")
    refs = dict(reversed(line.split("\t", 1)) for line in r.stdout.splitlines() if "\t" in line)
    sha = refs.get(f"refs/tags/{ref}^{{}}") or refs.get(f"refs/tags/{ref}") or refs.get(f"refs/heads/{ref}")
    if not sha or not SHA_RE.match(sha):
        raise PatchError(f"could not resolve {action}@{ref} to a commit SHA")
    return sha


def pin_action_sha(work: Path, file_path: str, args: dict, resolver=resolve_action_sha) -> PatchResult:
    action = _check(ACTION_RE, args.get("action"), "action")
    ref = _check(REF_RE, args.get("ref"), "ref")
    sha = args.get("sha") or resolver(action, ref)
    _check(SHA_RE, sha, "sha")
    p = safe_path(work, file_path)
    before = p.read_text(encoding="utf-8")
    pat = re.compile(r"^(\s*-?\s*uses:\s*)" + re.escape(action) + "@" + re.escape(ref) + r"(\s*(#.*)?)$", re.M)
    after, n = pat.subn(lambda m: f"{m.group(1)}{action}@{sha} # {ref}", before)
    if n == 0:
        raise PatchError(f"`uses: {action}@{ref}` not found in {file_path}")
    p.write_text(after, encoding="utf-8")
    rel = _rel(work, p)
    return PatchResult("pin_action_sha", rel, _udiff(rel, before, after), [rel],
                       {"action": action, "ref": ref, "sha": sha, "occurrences": n})


def generate_lockfile(work: Path, file_path: str, args: dict, resolver=None) -> PatchResult:
    """Remove `package-lock=false` from the project's .npmrc and resolve a lockfile with --ignore-scripts."""
    from guardian.tools.resolve import resolve_npm_project

    manifest = safe_path(work, file_path)
    if manifest.name != "package.json" or not manifest.is_file():
        raise PatchError("generate_lockfile needs a package.json path")
    d = manifest.parent
    diffs, files, facts = [], [], {"npmrc_changed": False}
    npmrc = d / ".npmrc"
    if npmrc.is_file():
        before = npmrc.read_text(encoding="utf-8")
        bad = [ln for ln, k, v, _ in read_npmrc(d) if k == "package-lock" and v.lower() == "false"]
        if bad:
            after = before
            for ln in sorted(bad, reverse=True):
                after = _rewrite_line(after, ln, None)
            npmrc.write_text(after, encoding="utf-8")
            rel = _rel(work, npmrc)
            diffs.append(_udiff(rel, before, after))
            files.append(rel)
            facts["npmrc_changed"] = True
    lock = d / "package-lock.json"
    existed = lock.is_file()
    res = (resolver or resolve_npm_project)(d)
    data = lock.read_bytes()
    rel_lock = _rel(work, lock)
    files.append(rel_lock)
    facts.update({"lockfile": rel_lock, "lockfile_sha256": hashlib.sha256(data).hexdigest(),
                  "lockfile_bytes": len(data), "replaced_existing": existed,
                  "resolve_flags": (res or {}).get("flags")})
    # A full lockfile diff is thousands of lines; record a header + hash instead (the file itself is the artifact).
    diffs.append(f"--- a/{rel_lock}\n+++ b/{rel_lock}\n@@ generated lockfile: {len(data)} bytes, "
                 f"sha256 {facts['lockfile_sha256'][:16]}... (--package-lock-only --ignore-scripts) @@\n")
    return PatchResult("generate_lockfile", _rel(work, manifest), "".join(diffs), files, facts)


OPS = {
    "set_dependency_version": set_dependency_version,
    "remove_dependency": remove_dependency,
    "replace_dependency": replace_dependency,
    "pin_action_sha": pin_action_sha,
    "generate_lockfile": generate_lockfile,
}


def apply_op(work: Path, op: Any) -> PatchResult:
    """`op` is a PatchOp (Dev1 model) or a dict with keys op/file_path/args."""
    name = op["op"] if isinstance(op, dict) else op.op
    file_path = op["file_path"] if isinstance(op, dict) else op.file_path
    args = (op.get("args") if isinstance(op, dict) else op.args) or {}
    if name not in OPS:
        raise PatchError(f"unsupported patch op: {name}")
    return OPS[name](Path(work), file_path, args)


def apply_ops(work: Path, ops: list, run_id: str, out_dir: Path | None = None):
    """Apply ops in order -> (results, evidence). Stops at the first error (raised) so a half-patched copy is
    never validated; the caller discards the work copy (rollback = fresh copy)."""
    from guardian.core.models import Evidence

    results, evidence = [], []
    for i, op in enumerate(ops):
        r = apply_op(work, op)
        art = None
        if out_dir is not None:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            art = Path(out_dir) / f"{i:02d}_{r.op}.diff"
            art.write_text(r.diff, encoding="utf-8")
        results.append(r)
        evidence.append(Evidence(
            run_id=run_id, kind="patch_diff", source_tool=f"patch:{r.op}", file_path=r.file_path,
            excerpt=r.diff[:2000], artifact_path=str(art) if art else None,
            sha256=hashlib.sha256(r.diff.encode()).hexdigest(),
            facts={"op": r.op, "files": r.files, **r.facts,
                   "lines_added": sum(1 for ln in r.diff.splitlines() if ln.startswith("+") and not ln.startswith("+++")),
                   "lines_removed": sum(1 for ln in r.diff.splitlines()
                                        if ln.startswith("-") and not ln.startswith("---"))}))
    return results, evidence
