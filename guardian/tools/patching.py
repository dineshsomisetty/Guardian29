"""D2-07 core patch ops: edit a copy of the target, never the target itself. Owner: Dev2.

Ops (§5.1 PatchOp.op):
  set_dependency_version  package.json  {name, version}
  remove_dependency       package.json  {name}
  replace_dependency      package.json  {name, new_name, version?}
  pin_action_sha          workflow.yml  {action, ref, sha}
  generate_lockfile       .npmrc        {projects: [...]}   drop `package-lock=false`, add the lockfiles resolved
                                                             in discovery with --ignore-scripts
Edits are line-based so the rest of the file (formatting, comments) stays byte-identical, and every edited
package.json is re-parsed. Paths are confined to the copy (G6.6).

Tools (called through the registry):
  resolve_action_sha  (remediation) tag/branch -> commit SHA via `git ls-remote` (read-only, github.com)
  plan_preview        (remediation) dry run: the unified diff a human approves; writes nothing
  apply_plan          (validator, write tool: needs a matching Approval, G3.3) fresh copy of the target under
                      runs/<id>/attempts/<attempt_id>/work + ops applied
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from guardian.core.config import REPO_ROOT
from guardian.core.models import Evidence, PatchOp
from guardian.core.workspace import IGNORE
from guardian.tools.binaries import run
from guardian.tools.registry import ToolContext, ToolOutput

DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.I)
_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?$")
_REF = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,99}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA_CACHE = REPO_ROOT / "data" / "cache" / "intel" / "action_shas.json"


class PatchError(ValueError):
    pass


# ---------------------------------------------------------------- typed args (G3.2)


class ActionRefArgs(BaseModel):
    action: str
    ref: str

    @field_validator("action")
    @classmethod
    def _action(cls, v: str) -> str:
        if not _ACTION.fullmatch(v) or any(seg in {".", ".."} for seg in v.split("/")):
            raise ValueError("action must look like owner/repo[/path]")
        return v

    @field_validator("ref")
    @classmethod
    def _ref(cls, v: str) -> str:
        if not _REF.fullmatch(v) or ".." in v:
            raise ValueError("ref has unexpected characters")
        return v


class PlanArgs(BaseModel):
    plan_id: str = Field(pattern=r"^pl_[0-9A-Z]{26}$")
    attempt_id: str | None = Field(default=None, pattern=r"^at_[0-9A-Z]{26}$")
    ops: list[PatchOp] = Field(min_length=1, max_length=20)


# ---------------------------------------------------------------- helpers


def confined(root: Path, rel: str) -> Path:
    """G6.6: resolve `rel` inside `root` or refuse."""
    root = root.resolve()
    target = (root / rel).resolve()
    if not target.is_relative_to(root) or target == root:
        raise PatchError(f"{rel} is outside the work copy")
    return target


def _dep_line(lines: list[str], name: str) -> int:
    """Index of the line declaring dependency `name` inside a dependency section."""
    section = None
    key = re.compile(rf'^\s*"{re.escape(name)}"\s*:\s*"')
    for i, ln in enumerate(lines):
        m = re.match(r'^\s*"(\w+)"\s*:\s*\{', ln)
        if m:
            section = m.group(1)
        elif re.match(r"^\s*\}", ln):
            section = None
        elif section in DEP_SECTIONS and key.match(ln):
            return i
    raise PatchError(f"dependency {name} not found")


def _check_name(name: str) -> None:
    if not _NAME.fullmatch(name):
        raise PatchError(f"not an npm package name: {name!r}")


def _set_version(text: str, a: dict) -> str:
    name, version = a["name"], str(a["version"])
    _check_name(name)
    if not re.fullmatch(r"[\w.^~<>=| -]+", version):
        raise PatchError(f"unexpected version spec {version!r}")
    lines = text.splitlines(keepends=True)
    i = _dep_line(lines, name)
    lines[i] = re.sub(r'(:\s*")[^"]*(")', lambda m: f"{m.group(1)}{version}{m.group(2)}", lines[i], count=1)
    return "".join(lines)


def _remove(text: str, a: dict) -> str:
    _check_name(a["name"])
    lines = text.splitlines(keepends=True)
    i = _dep_line(lines, a["name"])
    del lines[i]
    nxt = next((ln for ln in lines[i:] if ln.strip()), "")
    if nxt.lstrip().startswith("}") and i > 0:  # removed the last entry: drop the dangling comma
        prev = lines[i - 1]
        lines[i - 1] = re.sub(r",(\s*)$", r"\1", prev)
    return "".join(lines)


def _replace(text: str, a: dict) -> str:
    name, new = a["name"], a["new_name"]
    _check_name(name)
    _check_name(new)
    lines = text.splitlines(keepends=True)
    i = _dep_line(lines, name)
    lines[i] = lines[i].replace(f'"{name}"', f'"{new}"', 1)
    text = "".join(lines)
    return _set_version(text, {"name": new, "version": a["version"]}) if a.get("version") else text


def _pin_action(text: str, a: dict) -> str:
    action, ref, sha = a["action"], a["ref"], a["sha"]
    if not _SHA.fullmatch(sha):
        raise PatchError("sha must be a 40-char commit SHA")
    pat = re.compile(rf"(uses:\s*['\"]?){re.escape(action)}@{re.escape(ref)}(['\"]?)[ \t]*(#[^\r\n]*)?(?=\r?$)", re.M)
    new, n = pat.subn(lambda m: f"{m.group(1)}{action}@{sha}{m.group(2)} # {ref}", text)
    if n == 0:
        raise PatchError(f"uses: {action}@{ref} not found")
    return new


def _drop_lock_disable(text: str, a: dict) -> str:
    out = [ln for ln in text.splitlines(keepends=True) if not re.match(r"^\s*package-lock\s*=\s*false", ln)]
    return "".join(out)


_TEXT_OPS = {
    "set_dependency_version": _set_version,
    "remove_dependency": _remove,
    "replace_dependency": _replace,
    "pin_action_sha": _pin_action,
    "generate_lockfile": _drop_lock_disable,
}


def _diff(rel: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        f"a/{rel}", f"b/{rel}", n=2))


def apply_ops(root: Path, ops: list[PatchOp], lock_source: Path | None, write: bool) -> list[dict]:
    """Apply ops under `root`. Returns one {op, file, diff} per op. With write=False nothing is written."""
    pending: dict[str, str] = {}  # rel -> current text (several ops may touch one file)
    results = []
    for op in ops:
        fn = _TEXT_OPS.get(op.op)
        if fn is None:
            raise PatchError(f"op {op.op} is not implemented yet (Day 2: D2-07b)")
        path = confined(root, op.file_path)
        rel = path.relative_to(root.resolve()).as_posix()
        before = pending.get(rel, path.read_bytes().decode("utf-8") if path.exists() else "")
        after = fn(before, op.args)
        if path.name == "package.json":
            json.loads(after)  # edited manifest must still parse
        pending[rel] = after
        entry = {"op": op.op, "file": rel, "diff": _diff(rel, before, after)}
        if op.op == "generate_lockfile":
            entry["lockfiles"] = _lockfiles(root, op.args.get("projects") or ["root"], lock_source, write)
        results.append(entry)
    if write:
        for rel, text in pending.items():
            confined(root, rel).write_bytes(text.encode("utf-8"))  # bytes: no newline translation
    return results


def _lockfiles(root: Path, projects: list[str], lock_source: Path | None, write: bool) -> list[dict]:
    out = []
    for proj in projects:
        rel = "package-lock.json" if proj == "root" else f"{proj}/package-lock.json"
        src = confined(lock_source, rel) if lock_source else None
        if src is None or not src.exists():
            raise PatchError(f"no resolved lockfile for {proj} (discovery resolve step missing)")
        dst = confined(root, rel)
        lines = sum(1 for _ in src.open(encoding="utf-8"))
        if write:
            shutil.copyfile(src, dst)
        out.append({"file": rel, "lines": lines, "source": "npm install --package-lock-only --ignore-scripts"})
    return out


def _patch_evidence(ctx: ToolContext, plan_id: str, results: list[dict], preview: bool) -> Evidence:
    diff = "\n".join(r["diff"] for r in results)
    for r in results:
        for lf in r.get("lockfiles", []):
            diff += f"\n+++ b/{lf['file']}  (new file, {lf['lines']} lines, {lf['source']})"
    return Evidence(run_id=ctx.run_id, kind="patch_diff", source_tool="patching",
                    facts={"plan_id": plan_id, "preview": preview,
                           "files": sorted({r["file"] for r in results}), "ops": [r["op"] for r in results],
                           "lockfiles_added": [lf["file"] for r in results for lf in r.get("lockfiles", [])]},
                    excerpt=diff[:20000])


# ---------------------------------------------------------------- tools


def plan_preview(ctx: ToolContext, args: PlanArgs) -> ToolOutput:
    base = ctx.repo
    results = apply_ops(base, args.ops, ctx.work_dir, write=False)
    ev = _patch_evidence(ctx, args.plan_id, results, preview=True)
    return ToolOutput(evidence=[ev], artifacts={"preview_diff": ev.excerpt},
                      summary=f"dry run: {len(results)} ops on {ev.facts['files']}")


def apply_plan(ctx: ToolContext, args: PlanArgs) -> ToolOutput:
    if not args.attempt_id:
        raise PatchError("apply_plan needs an attempt_id")
    attempt_dir = ctx.run_dir / "attempts" / args.attempt_id / "work"
    if attempt_dir.exists():
        raise PatchError(f"attempt {args.attempt_id} already exists")
    shutil.copytree(ctx.repo, attempt_dir, ignore=IGNORE)  # fresh copy of the target, not the work copy
    results = apply_ops(attempt_dir, args.ops, ctx.work_dir, write=True)
    ev = _patch_evidence(ctx, args.plan_id, results, preview=False)
    ev.facts["attempt_id"] = args.attempt_id
    return ToolOutput(evidence=[ev], artifacts={"attempt_dir": attempt_dir},
                      summary=f"applied {len(results)} ops in attempts/{args.attempt_id}/work")


def _load_cache() -> dict:
    try:
        return json.loads(_SHA_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def ls_remote(action: str, ref: str) -> tuple[str, str]:
    """(sha, ref_type) for a tag or branch of a GitHub action repo. Peeled tag commit preferred."""
    owner_repo = "/".join(action.split("/")[:2])
    url = f"https://github.com/{owner_repo}.git"
    out = run(["git", "ls-remote", url, f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}", f"refs/heads/{ref}"],
              timeout=60).stdout
    refs = dict(reversed(line.split("\t", 1)) for line in out.splitlines() if "\t" in line)
    for key, kind in ((f"refs/tags/{ref}^{{}}", "tag"), (f"refs/tags/{ref}", "tag"), (f"refs/heads/{ref}", "branch")):
        if key in refs and _SHA.match(refs[key]):
            return refs[key], kind
    raise PatchError(f"{action}@{ref} not found on github.com")


def resolve_action_sha(ctx: ToolContext, args: ActionRefArgs) -> ToolOutput:
    key = f"{args.action}@{args.ref}"
    cache = _load_cache()
    if key in cache:
        sha, kind, source = cache[key]["sha"], cache[key]["ref_type"], "cache"
    elif ctx.settings.offline:
        raise PatchError(f"{key} not in cache and GUARDIAN_OFFLINE=1")
    else:
        sha, kind = ls_remote(args.action, args.ref)
        source = "git ls-remote github.com"
        cache[key] = {"sha": sha, "ref_type": kind}
        _SHA_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _SHA_CACHE.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")
    ev = Evidence(run_id=ctx.run_id, kind="registry_metadata", source_tool="git ls-remote",
                  facts={"action": args.action, "ref": args.ref, "sha": sha, "ref_type": kind, "source": source})
    return ToolOutput(evidence=[ev], artifacts={"action_sha": sha},
                      summary=f"{key} -> {sha[:12]} ({kind}, {source})")
