"""D2-07 core patch ops: edit a copy of the target, never the target itself. Owner: Dev2.

Ops (§5.1 PatchOp.op):
  set_dependency_version  package.json  {name, version}
  set_requirement_version requirements*.txt {name, version}  pin `name==version` (pip; extras, markers and
                                                             comments on the line are kept)
  remove_dependency       package.json  {name}
  replace_dependency      package.json  {name, new_name, version?}
  rename_import           a .js/.ts source file  {name, new_name}  module strings in import/require (pairs with
                                                             replace_dependency when code imports the package)
  pin_action_sha          workflow.yml  {action, ref, sha}
  generate_lockfile       .npmrc        {projects: [...]}   drop `package-lock=false`, add the lockfiles resolved
                                                             in discovery with --ignore-scripts
  pin_image_digest        Dockerfile / docker-compose.yml  {image, tag, digest}  `FROM image:tag` ->
                                                             `FROM image:tag@sha256:...` (compose: `image:` lines)
  update_base_image       Dockerfile / compose  {image, tag, new_tag, digest}  bump the tag, pin the new digest
  block_package           package.json / requirements*.txt  {name}  remove the dependency and append the name to
                                                             `.guardian/denylist.txt` (two files, one diff)
Edits are line-based so the rest of the file (formatting, comments) stays byte-identical, and every edited
package.json is re-parsed. Paths are confined to the copy (G6.6).

Tools (called through the registry):
  resolve_action_sha  (remediation) tag/branch -> commit SHA via `git ls-remote` (read-only, github.com)
  resolve_image_digest (remediation) image:tag -> sha256 digest via `docker buildx imagetools inspect` (argv,
                      read-only; registry-1.docker.io / gcr.io / ghcr.io only; cached; offline = cache only)
  plan_preview        (remediation) dry run: the unified diff a human approves; writes nothing
  apply_plan          (validator, write tool: needs a matching Approval, G3.3) fresh copy of the target under
                      runs/<id>/attempts/<attempt_id>/work + ops applied

Pipeline use: the remediation agent builds a plan out of PatchOps and previews it; after a human approves, the
validator applies it to a COPY and sandboxes/rescans that copy. This module never edits the original target.
Evidence produced: `patch_diff` (unified diff excerpt, files, ops, lockfiles added) for preview and for apply, and
`registry_metadata` for the SHA / digest lookups, which later let the validator check G4.5 (a plan may only pin
a SHA or digest that a lookup tool really returned, not one the model invented).
Network (G3.5): only resolve_action_sha (github.com via `git ls-remote`) and resolve_image_digest (docker
registries via `docker buildx imagetools`), both host-checked by guardrails.network.check_url, cached under
data/cache/intel, and cache-only when GUARDIAN_OFFLINE=1. Everything else is local text editing.
Failure: PatchError (a ValueError) for any bad argument, missing target line or escaped path; call_tool logs it
and the plan simply cannot be applied.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from guardian.core.config import REPO_ROOT
from guardian.core.models import Evidence, PatchOp
from guardian.core.workspace import IGNORE
from guardian.guardrails.network import check_url
from guardian.tools.binaries import run
from guardian.tools.registry import ToolContext, ToolOutput

DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")  # package.json keys
# The regexes below validate every value before it is used in a pattern, a path or an argv (G3.2): they reject
# anything that could smuggle in a shell/argv option, a path escape or a regex of the attacker's choosing.
_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.I)
_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?$")
_REF = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_./-]{0,99}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA_CACHE = REPO_ROOT / "data" / "cache" / "intel" / "action_shas.json"  # "owner/repo@ref" -> {sha, ref_type}
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,199}$")  # no @, no leading dash (argv injection)
_TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
DENYLIST = ".guardian/denylist.txt"  # block_package appends package names here, inside the patched copy only
IMAGE_REGISTRY_HOSTS = frozenset({"registry-1.docker.io", "gcr.io", "ghcr.io"})  # G3.5 for image digest lookups


MAX_PLAN_OPS = 100  # G3.2 bound: a replacement may rename imports in many files (Juice Shop: 35)


class PatchError(ValueError):
    """A patch op or tool argument is invalid, or the file it targets does not contain what the op expects."""

    pass


# ---------------------------------------------------------------- typed args (G3.2)


class ActionRefArgs(BaseModel):
    """resolve_action_sha input: a GitHub action (`owner/repo[/path]`) and the tag/branch to look up."""

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


class ImageArgs(BaseModel):
    """resolve_image_digest input: image name (optionally with registry host) and tag; no `@digest`, no `-opts`."""

    image: str
    tag: str

    @field_validator("image")
    @classmethod
    def _image(cls, v: str) -> str:
        if not _IMAGE.fullmatch(v) or ".." in v or "//" in v:
            raise ValueError("image has unexpected characters")
        return v

    @field_validator("tag")
    @classmethod
    def _tag(cls, v: str) -> str:
        if not _TAG.fullmatch(v):
            raise ValueError("tag has unexpected characters")
        return v


class PlanArgs(BaseModel):
    """plan_preview / apply_plan input: the plan id, the attempt it is applied under (apply only) and its ops."""

    plan_id: str = Field(pattern=r"^pl_[0-9A-Z]{26}$")
    attempt_id: str | None = Field(default=None, pattern=r"^at_[0-9A-Z]{26}$")
    ops: list[PatchOp] = Field(min_length=1, max_length=MAX_PLAN_OPS)
    extend: bool = False  # batch validation: apply onto the attempt copy an earlier plan of the same attempt made


# ---------------------------------------------------------------- helpers


def confined(root: Path, rel: str) -> Path:
    """G6.6: resolve `rel` inside `root` or refuse (so `..` or an absolute path cannot reach outside the copy;
    the root itself is not a valid target either). Returns the resolved absolute path."""
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
    """Refuse anything that is not a plain (optionally scoped) npm/pip package name."""
    if not _NAME.fullmatch(name):
        raise PatchError(f"not an npm package name: {name!r}")


def _set_version(text: str, a: dict) -> str:
    """package.json: set the version spec of dependency `a["name"]` to `a["version"]`, editing only that line
    (the rest of the file stays byte-identical, including indentation and key order)."""
    name, version = a["name"], str(a["version"])
    _check_name(name)
    if not re.fullmatch(r"[\w.^~<>=| -]+", version):
        raise PatchError(f"unexpected version spec {version!r}")
    lines = text.splitlines(keepends=True)
    i = _dep_line(lines, name)
    lines[i] = re.sub(r'(:\s*")[^"]*(")', lambda m: f"{m.group(1)}{version}{m.group(2)}", lines[i], count=1)
    return "".join(lines)


def _pep503(name: str) -> str:
    """Normalise a Python package name per PEP 503 (case-insensitive, runs of - _ . are equal)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _set_requirement(text: str, a: dict) -> str:
    """requirements.txt: rewrite the version specifier of the one line declaring `name` to `==version`."""
    name, version = a["name"], str(a["version"])
    _check_name(name)
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+!-]*", version):
        raise PatchError(f"unexpected pip version {version!r}")
    lines = text.splitlines(keepends=True)
    pat = re.compile(r"^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\s*\[[^\]]*\])?(\s*(?:[<>=!~]=?|===)[^;#\s]*)?")
    hits = [i for i, ln in enumerate(lines)
            if (m := pat.match(ln)) and not ln.lstrip().startswith(("#", "-")) and _pep503(m.group(2)) == _pep503(name)]
    if len(hits) != 1:
        raise PatchError(f"{name}: expected exactly one requirement line, found {len(hits)}")
    i = hits[0]
    m = pat.match(lines[i])
    lines[i] = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}=={version}{lines[i][m.end():]}"
    return "".join(lines)


def _remove(text: str, a: dict) -> str:
    """package.json: delete the line declaring dependency `a["name"]`; if it was the last entry of its section,
    also strip the trailing comma of the previous line so the JSON stays valid."""
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
    """package.json: rename dependency `name` to `new_name` (typosquat -> legitimate package), optionally with a
    new version spec. Imports in source files are changed separately by rename_import."""
    name, new = a["name"], a["new_name"]
    _check_name(name)
    _check_name(new)
    lines = text.splitlines(keepends=True)
    i = _dep_line(lines, name)
    lines[i] = lines[i].replace(f'"{name}"', f'"{new}"', 1)
    text = "".join(lines)
    return _set_version(text, {"name": new, "version": a["version"]}) if a.get("version") else text


def _module_spec(name: str) -> str:
    """Regex for `name` (or `name/sub/path`) as a module string in import/require/export-from/import()."""
    q = re.escape(name)
    return (r"((?:\bfrom\s*|\brequire\(\s*|\bimport\(\s*|^\s*import\s+)(['\"]))" + q + r"(?=(?:/[^'\"]*)?\2)")


def _rename_import(text: str, a: dict) -> str:
    """Rewrite module strings `name` -> `new_name` in import/require statements of one source file (the
    replacement for a typosquat is API-compatible). Only exact module specifiers change, never other text."""
    name, new = a["name"], a["new_name"]
    _check_name(name)
    _check_name(new)
    out, n = re.subn(_module_spec(name), lambda m: m.group(1) + new, text, flags=re.M)
    if n == 0:
        raise PatchError(f"no import of {name!r} in this file")
    return out


def _pin_action(text: str, a: dict) -> str:
    """workflow YAML: `uses: action@ref` -> `uses: action@<40-hex sha> # ref` (the old ref is kept as a trailing
    comment so humans still see the version). Fails if no such `uses:` line exists."""
    action, ref, sha = a["action"], a["ref"], a["sha"]
    if not _SHA.fullmatch(sha):
        raise PatchError("sha must be a 40-char commit SHA")
    pat = re.compile(rf"(uses:\s*['\"]?){re.escape(action)}@{re.escape(ref)}(['\"]?)[ \t]*(#[^\r\n]*)?(?=\r?$)", re.M)
    new, n = pat.subn(lambda m: f"{m.group(1)}{action}@{sha}{m.group(2)} # {ref}", text)
    if n == 0:
        raise PatchError(f"uses: {action}@{ref} not found")
    return new


def _drop_lock_disable(text: str, a: dict) -> str:
    """.npmrc: drop `package-lock=false` lines (the lockfiles themselves are added by _lockfiles)."""
    out = [ln for ln in text.splitlines(keepends=True) if not re.match(r"^\s*package-lock\s*=\s*false", ln)]
    return "".join(out)


def _check_image(a: dict) -> tuple[str, str, str]:
    """Validate image / tag / digest of an image op and return them as (image, tag, digest)."""
    image, tag, digest = str(a["image"]), str(a["tag"]), str(a["digest"])
    if not _IMAGE.fullmatch(image):
        raise PatchError(f"unexpected image name {image!r}")
    if not _TAG.fullmatch(tag):
        raise PatchError(f"unexpected image tag {tag!r}")
    if not _DIGEST.fullmatch(digest):
        raise PatchError("digest must be sha256:<64 hex>")
    return image, tag, digest


def _is_dockerfile(rel: str) -> bool:
    """Dockerfile, Dockerfile.dev, app.dockerfile ... (the file name only, case-insensitive)."""
    name = rel.rsplit("/", 1)[-1].lower()
    return name.startswith("dockerfile") or name.endswith(".dockerfile")


def _rewrite_image(text: str, rel: str, image: str, tag: str, new_ref: str) -> str:
    """Replace every un-pinned reference to `image:tag` by `new_ref` in a Dockerfile (FROM lines) or a compose
    file (`image:` lines). A tag-less `image` counts as `:latest` for tag == "latest". Digest-pinned lines stay."""
    ref = re.escape(image) + "(?::" + re.escape(tag) + ")" + ("?" if tag == "latest" else "")
    if _is_dockerfile(rel):
        pat = re.compile(r"^(\s*FROM\s+(?:--platform=\S+\s+)?)" + ref + r"(?=\s|$)", re.I | re.M)
    elif rel.endswith((".gitlab-ci.yml", ".gitlab-ci.yaml")) or rel.startswith(".gitlab/"):
        # GitLab CI: `image: ref`, `name: ref` (image/service mappings) and bare `- ref` service list items
        pat = re.compile(r"^(\s*(?:-\s+)?(?:(?:image|name)\s*:\s*)?['\"]?)" + ref + r"(?=['\"]?\s*(?:#.*)?$)", re.M)
    else:
        pat = re.compile(r"^(\s*(?:-\s+)?image\s*:\s*['\"]?)" + ref + r"(?=['\"]?\s*(?:#.*)?$)", re.M)
    new, n = pat.subn(lambda m: m.group(1) + new_ref, text)
    if n == 0:
        raise PatchError(f"un-pinned reference to {image}:{tag} not found in {rel}")
    return new


def _pin_image(text: str, a: dict, rel: str) -> str:
    """`image:tag` -> `image:tag@sha256:...` (same tag, now immutable)."""
    image, tag, digest = _check_image(a)
    return _rewrite_image(text, rel, image, tag, f"{image}:{tag}@{digest}")


def _update_base(text: str, a: dict, rel: str) -> str:
    """`image:tag` -> `image:new_tag@sha256:...`: move to a newer tag and pin its digest in one step."""
    image, tag, digest = _check_image(a)
    new_tag = str(a["new_tag"])
    if not _TAG.fullmatch(new_tag) or new_tag == tag:
        raise PatchError(f"new_tag {new_tag!r} must be a different, valid tag")
    return _rewrite_image(text, rel, image, tag, f"{image}:{new_tag}@{digest}")


def _remove_requirement(text: str, a: dict) -> str:
    """requirements.txt: delete the single line declaring `name` (matched PEP 503-normalised)."""
    name = a["name"]
    _check_name(name)
    lines = text.splitlines(keepends=True)
    pat = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
    hits = [i for i, ln in enumerate(lines)
            if (m := pat.match(ln)) and not ln.lstrip().startswith(("#", "-")) and _pep503(m.group(1)) == _pep503(name)]
    if len(hits) != 1:
        raise PatchError(f"{name}: expected exactly one requirement line, found {len(hits)}")
    del lines[hits[0]]
    return "".join(lines)


def _denylist_add(text: str, name: str) -> str:
    """Return the denylist text with `name` appended (and a header on a new file); unchanged if already listed."""
    _check_name(name)
    if name.lower() in {ln.strip().lower() for ln in text.splitlines()}:
        return text
    head = "" if text else "# Guardian denylist: package names that must not be installed (one per line)\n"
    return text + ("" if not text or text.endswith("\n") else "\n") + head + name + "\n"


# op name -> text transformer fn(text, args) -> new text. The two special cases are handled in apply_ops:
# _FILE_OPS also need the file name, and block_package edits two files so it has its own function.
_TEXT_OPS = {
    "set_dependency_version": _set_version,
    "set_requirement_version": _set_requirement,
    "remove_dependency": _remove,
    "replace_dependency": _replace,
    "rename_import": _rename_import,
    "pin_action_sha": _pin_action,
    "generate_lockfile": _drop_lock_disable,
}
_FILE_OPS = {"pin_image_digest": _pin_image, "update_base_image": _update_base}  # these also need the file name


def _diff(rel: str, before: str, after: str) -> str:
    """Unified diff of one file with 2 lines of context, labelled a/<rel> b/<rel> like `git diff`."""
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        f"a/{rel}", f"b/{rel}", n=2))


def apply_ops(root: Path, ops: list[PatchOp], lock_source: Path | None, write: bool) -> list[dict]:
    """Apply ops under `root`. Returns one {op, file, diff} per op. With write=False nothing is written.

    `lock_source` is the directory holding the lockfiles discovery resolved (generate_lockfile copies from it).
    Ops are applied in order against an in-memory view, so several ops on one file compose; files are only
    written at the end, and only if every op succeeded (all-or-nothing). Files are written as bytes so line
    endings are not translated, and an edited package.json must still parse as JSON."""
    pending: dict[str, str] = {}  # rel -> current text (several ops may touch one file)
    results = []
    def current(rel: str) -> str:
        path = confined(root, rel)
        return pending.get(rel, path.read_bytes().decode("utf-8") if path.exists() else "")

    for op in ops:
        if op.op == "block_package":
            results.append(_block_package(root, op, pending, current))
            continue
        fn = _TEXT_OPS.get(op.op)
        path = confined(root, op.file_path)
        rel = path.relative_to(root.resolve()).as_posix()
        if fn is None and op.op in _FILE_OPS:
            fn = lambda t, a, _f=_FILE_OPS[op.op], _r=rel: _f(t, a, _r)  # noqa: E731
        if fn is None:
            raise PatchError(f"op {op.op} is not implemented")
        before = current(rel)
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
            dst = confined(root, rel)
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(text.encode("utf-8"))  # bytes: no newline translation
    return results


def _block_package(root: Path, op: PatchOp, pending: dict[str, str], current: Callable[[str], str]) -> dict:
    """Remove the dependency from its manifest and add its name to the denylist inside the copy (two files).
    Result carries `files` (both paths) so the evidence and the PR list the denylist too."""
    path = confined(root, op.file_path)
    rel = path.relative_to(root.resolve()).as_posix()
    name = op.args["name"]
    before = current(rel)
    if path.name == "package.json":
        after = _remove(before, {"name": name})
        json.loads(after)
    elif path.suffix == ".txt":
        after = _remove_requirement(before, {"name": name})
    else:
        raise PatchError(f"block_package supports package.json and requirements*.txt, not {rel}")
    deny_before = current(DENYLIST)
    deny_after = _denylist_add(deny_before, name)
    pending[rel], pending[DENYLIST] = after, deny_after
    return {"op": op.op, "file": rel, "files": [rel, DENYLIST],
            "diff": _diff(rel, before, after) + _diff(DENYLIST, deny_before, deny_after)}


def _lockfiles(root: Path, projects: list[str], lock_source: Path | None, write: bool) -> list[dict]:
    """Copy the lockfiles discovery resolved (`--ignore-scripts`) into the patched copy for each project name
    ("root" or a subfolder). Fails if discovery did not resolve one. Returns {file, lines, source} per lockfile."""
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
    """One `patch_diff` Evidence for a set of op results. `preview` marks a dry run (local_pr only trusts the
    non-preview one). The excerpt is capped at 20 000 chars; new lockfiles appear as one summary line each."""
    diff = "\n".join(r["diff"] for r in results)
    for r in results:
        for lf in r.get("lockfiles", []):
            diff += f"\n+++ b/{lf['file']}  (new file, {lf['lines']} lines, {lf['source']})"
    return Evidence(run_id=ctx.run_id, kind="patch_diff", source_tool="patching",
                    facts={"plan_id": plan_id, "preview": preview,
                           "files": sorted({f for r in results for f in r.get("files", [r["file"]])}), "ops": [r["op"] for r in results],
                           "lockfiles_added": [lf["file"] for r in results for lf in r.get("lockfiles", [])]},
                    excerpt=diff[:20000])


# ---------------------------------------------------------------- tools


def plan_preview(ctx: ToolContext, args: PlanArgs) -> ToolOutput:
    """Dry run: apply the ops in memory against the target and return the diff a human will be asked to approve.
    Writes nothing (the target is only read). Artifact `preview_diff` = the diff text."""
    base = ctx.repo
    results = apply_ops(base, args.ops, ctx.work_dir, write=False)
    ev = _patch_evidence(ctx, args.plan_id, results, preview=True)
    return ToolOutput(evidence=[ev], artifacts={"preview_diff": ev.excerpt},
                      summary=f"dry run: {len(results)} ops on {ev.facts['files']}")


def apply_plan(ctx: ToolContext, args: PlanArgs) -> ToolOutput:
    """Write tool (G3.3, approval required): create runs/<id>/attempts/<attempt_id>/work as a fresh copy of the
    target and apply the plan's ops there. With `extend=True` (batch validation) the ops go onto the copy an
    earlier plan of the same attempt already made. One attempt id = one copy, so an existing copy is refused
    unless extending. Returns a non-preview `patch_diff` Evidence tagged with the attempt id."""
    if not args.attempt_id:
        raise PatchError("apply_plan needs an attempt_id")
    attempt_dir = ctx.run_dir / "attempts" / args.attempt_id / "work"
    if args.extend:
        if not attempt_dir.exists():
            raise PatchError(f"attempt {args.attempt_id} has no copy to extend")
    elif attempt_dir.exists():
        raise PatchError(f"attempt {args.attempt_id} already exists")
    else:
        shutil.copytree(ctx.repo, attempt_dir, ignore=IGNORE)  # fresh copy of the target, not the work copy
    results = apply_ops(attempt_dir, args.ops, ctx.work_dir, write=True)
    ev = _patch_evidence(ctx, args.plan_id, results, preview=False)
    ev.facts["attempt_id"] = args.attempt_id
    return ToolOutput(evidence=[ev], artifacts={"attempt_dir": attempt_dir},
                      summary=f"applied {len(results)} ops in attempts/{args.attempt_id}/work")


def _load_cache() -> dict:
    """The action-SHA cache as a dict; empty if missing or corrupt."""
    try:
        return json.loads(_SHA_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def ls_remote(action: str, ref: str) -> tuple[str, str]:
    """(sha, ref_type) for a tag or branch of a GitHub action repo. Peeled tag commit preferred.

    Annotated tags point at a tag object; `^{}` asks git for the commit it points to, which is what a workflow
    must pin. Read-only `git ls-remote`, 60 s cap; raises PatchError if neither tag nor branch exists."""
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
    """Tag/branch -> commit SHA for a GitHub action, as `registry_metadata` Evidence (G4.5 source for pin_action_sha).
    Cache first; offline runs may use only the cache; otherwise the github.com host is allow-checked (G3.5)
    before `git ls-remote` runs and the answer is cached for rehearsal/demo stability (C3)."""
    key = f"{args.action}@{args.ref}"
    cache = _load_cache()
    if key in cache:
        sha, kind, source = cache[key]["sha"], cache[key]["ref_type"], "cache"
    elif ctx.settings.offline:
        raise PatchError(f"{key} not in cache and GUARDIAN_OFFLINE=1")
    else:
        check_url(f"https://github.com/{'/'.join(args.action.split('/')[:2])}.git", ctx=ctx, agent="remediation")  # G3.5
        sha, kind = ls_remote(args.action, args.ref)
        source = "git ls-remote github.com"
        cache[key] = {"sha": sha, "ref_type": kind}
        _SHA_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _SHA_CACHE.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")
    ev = Evidence(run_id=ctx.run_id, kind="registry_metadata", source_tool="git ls-remote",
                  facts={"action": args.action, "ref": args.ref, "sha": sha, "ref_type": kind, "source": source})
    return ToolOutput(evidence=[ev], artifacts={"action_sha": sha},
                      summary=f"{key} -> {sha[:12]} ({kind}, {source})")


# ---------------------------------------------------------------- image digests (D2-07b)

InspectRunner = Callable[[list[str], int], "subprocess.CompletedProcess"]  # (argv, timeout seconds) -> process
_inspect_runner: InspectRunner | None = None  # tests inject a fake: no Docker, no network


def set_inspect_runner(fn: InspectRunner | None) -> None:
    """Test hook: replace the docker subprocess call with `fn` (None restores the real one)."""
    global _inspect_runner
    _inspect_runner = fn


def _digest_cache_path() -> Path:
    """data/cache/intel/image_digests.json, or under GUARDIAN_INTEL_CACHE when that env var is set."""
    base = os.environ.get("GUARDIAN_INTEL_CACHE")
    return (Path(base) if base else REPO_ROOT / "data" / "cache" / "intel") / "image_digests.json"


def registry_host(image: str) -> str:
    """The registry host an image reference points at (`node` -> Docker Hub's registry-1.docker.io)."""
    first = image.split("/", 1)[0]
    if "/" in image and ("." in first or ":" in first or first == "localhost"):
        return first.split(":", 1)[0].lower()
    return "registry-1.docker.io"


def _run_inspect(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Run a docker inspect command (argv list, any exit code allowed so the caller can read stderr)."""
    if _inspect_runner is not None:
        return _inspect_runner(argv, timeout)
    from guardian.tools import binaries

    argv = [binaries.find("docker"), *argv[1:]] if argv and argv[0] == "docker" else argv
    return binaries.run(argv, timeout=timeout, ok_codes=tuple(range(256)))


def _digest_from_manifest(text: str) -> str | None:
    """`.Manifest` of buildx (`{"digest": ...}`) or `docker manifest inspect --verbose` (`Descriptor.digest`)."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    for node in (data if isinstance(data, list) else [data]):
        if not isinstance(node, dict):
            continue
        for cand in (node.get("digest"), (node.get("Descriptor") or {}).get("digest")):
            if isinstance(cand, str) and _DIGEST.fullmatch(cand):
                return cand
    return None


def inspect_digest(ref: str) -> tuple[str, str]:
    """(digest, source command) for `image:tag`. argv only, never a shell.

    Tries `docker buildx imagetools inspect` first, then `docker manifest inspect`; each is a read-only registry
    query (90 s cap). Raises PatchError with the last failure if neither yields a valid sha256 digest."""
    attempts = [
        (["docker", "buildx", "imagetools", "inspect", "--format", "{{json .Manifest}}", ref],
         "docker buildx imagetools inspect"),
        (["docker", "manifest", "inspect", "--verbose", ref], "docker manifest inspect"),
    ]
    last = ""
    for argv, label in attempts:
        try:
            p = _run_inspect(argv, 90)
        except (subprocess.TimeoutExpired, OSError, RuntimeError) as exc:
            last = f"{label}: {type(exc).__name__}"
            continue
        digest = _digest_from_manifest(p.stdout or "") if p.returncode == 0 else None
        if digest:
            return digest, label
        last = f"{label}: exit {p.returncode} {(p.stderr or '').strip()[-160:]}"
    raise PatchError(f"could not resolve a digest for {ref} ({last})")


def resolve_image_digest(ctx: ToolContext, args: ImageArgs) -> ToolOutput:
    """image:tag -> manifest digest, as Evidence (G4.5: a plan may only pin a digest that this tool returned)."""
    host = registry_host(args.image)
    ref = f"{args.image}:{args.tag}"
    path = _digest_cache_path()
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    entry = cache.get(ref)
    if entry and _DIGEST.fullmatch(entry.get("digest", "")):
        digest, source = entry["digest"], "cache"
    elif ctx.settings.offline or os.environ.get("GUARDIAN_OFFLINE") == "1":
        raise PatchError(f"{ref} not in the digest cache and GUARDIAN_OFFLINE=1")
    else:
        check_url(f"https://{host}/v2/", ctx=ctx, extra_hosts=IMAGE_REGISTRY_HOSTS, agent="remediation")  # G3.5
        digest, source = inspect_digest(ref)
        cache[ref] = {"digest": digest, "host": host}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")
    ev = Evidence(run_id=ctx.run_id, kind="registry_metadata", source_tool="docker buildx imagetools",
                  facts={"image": args.image, "tag": args.tag, "digest": digest, "registry": host, "source": source})
    return ToolOutput(evidence=[ev], artifacts={"image_digest": digest}, summary=f"{ref} -> {digest[:19]} ({source})")
