"""Investigator tools (D1-08): read-only lookups the investigator may call through `call_tool`. Owner: Dev1.

  registry_metadata(name, version?)  npm registry metadata, same cache dir + offline rules as install_scripts
  file_excerpt(path, line, context)  lines around a location in the work copy, via file_read (G1.1 denies secrets)
  manifest_diff()                    what changed vs the baseline, from the detection step's changes artifact

All three only read. They return Evidence (kind registry_metadata / file_excerpt / diff) so every claim the
investigator makes can be grounded (G4).

Evidence `facts` keys:
  registry_metadata  {package, requested_version, available, source, exists, version, description (300 chars),
                      maintainers, repository, deprecated, install_hooks}; excerpt = the summary as JSON
  file_excerpt       {path, line, context, start, end}; excerpt = the lines (3000 chars max), file_path/line set
  diff               {available, base, head, added, removed, changed, integrity_changed, install_scripts_added}
                     (lists cut to 100 entries); {available: False, reason} when there is no baseline
Network/cache: only registry_metadata touches the network (npm registry, G3.5 check_url, throttled). Summaries are
cached under install_scripts.CACHE as <name>@<tag>.meta.json (G7.4); with settings.offline only the cache is read
and a miss is reported as "unavailable (offline, cache miss)". Failure: a transport error or non-200 status gives
available=False with the reason in `source`; file_excerpt raises FileReadDenied for secrets or paths outside the repo.
"""

from __future__ import annotations

import json
import time
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field

from guardian.core.models import Evidence
from guardian.guardrails.network import check_url
from guardian.tools.detectors import install_scripts
from guardian.tools.file_read import file_read
from guardian.tools.registry import ToolContext, ToolOutput


class RegistryMetadataArgs(BaseModel):
    """Typed arguments (G3.2): an npm package name (optionally scoped) and an optional exact version/tag."""

    name: str = Field(min_length=1, max_length=214, pattern=r"^(@[a-z0-9._~-]+/)?[a-z0-9._~-]+$")
    version: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._+-]+$")


class FileExcerptArgs(BaseModel):
    """Typed arguments: a repo-relative path, the centre line (1-based) and how many lines to show either side."""

    path: str = Field(min_length=1, max_length=512)
    line: int = Field(default=1, ge=1, le=1_000_000)
    context: int = Field(default=5, ge=0, le=20)


def _fetch(name: str, version: str | None, ctx: ToolContext) -> tuple[dict | None, str]:
    """(summary, source). Cache first; with GUARDIAN_OFFLINE=1 only the cache is used (G7.3, G7.4)."""
    tag = version or "latest"  # no version asked for: the registry resolves "latest" to the newest release
    # shares install_scripts.CACHE but with a .meta.json suffix so it never collides with the scripts-only cache
    path = install_scripts.CACHE / f"{name.replace('/', '__')}@{tag}.meta.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8")), "cache"
    if ctx.settings.offline:
        return None, "unavailable (offline, cache miss)"
    url = check_url(f"{install_scripts.REGISTRY}/{quote(name, safe='@')}/{quote(tag)}", ctx=ctx,
                    agent="investigator")  # G3.5
    try:
        r = httpx.get(url, timeout=10, headers={"Accept": "application/json"})
        time.sleep(install_scripts._THROTTLE_S)
    except httpx.HTTPError as exc:
        return None, f"unavailable ({type(exc).__name__})"
    if r.status_code == 404:
        summary = {"exists": False}  # a 404 is a real answer (the package does not exist): worth caching and reporting
    elif r.status_code != 200:
        return None, f"unavailable (HTTP {r.status_code})"
    else:
        doc = r.json()
        repo = doc.get("repository")
        summary = {
            "exists": True,
            "version": doc.get("version"),
            "description": (doc.get("description") or "")[:300],
            "maintainers": sorted(m.get("name", "") for m in doc.get("maintainers") or [] if isinstance(m, dict)),
            "repository": (repo.get("url") if isinstance(repo, dict) else repo),
            "deprecated": doc.get("deprecated"),
            "install_hooks": sorted(k for k in (doc.get("scripts") or {}) if k in install_scripts.HOOKS),
        }
    install_scripts.CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=1), encoding="utf-8")
    return summary, "registry.npmjs.org"


def registry_metadata(ctx: ToolContext, args: RegistryMetadataArgs) -> ToolOutput:
    """Evidence `registry_metadata` for one npm package: does it exist, who maintains it, does it run install hooks.
    Useful to judge a suspicious dependency (typosquat, new maintainer). Never raises on network trouble: the
    facts say `available: False` and why."""
    summary, source = _fetch(args.name, args.version, ctx)
    facts = {"package": args.name, "requested_version": args.version or "latest", "available": summary is not None,
             "source": source, **(summary or {})}
    excerpt = json.dumps(summary, indent=1, sort_keys=True)[:1500] if summary is not None else None
    ev = Evidence(run_id=ctx.run_id, kind="registry_metadata", source_tool="registry_metadata", facts=facts,
                  excerpt=excerpt)
    what = "not available" if summary is None else ("not found on the registry" if not summary.get("exists")
                                                       else f"latest {summary.get('version')}")
    return ToolOutput(evidence=[ev], summary=f"{args.name}: {what} ({source})")


def file_excerpt(ctx: ToolContext, args: FileExcerptArgs) -> ToolOutput:
    """Evidence `file_excerpt`: the lines around args.line (+/- context) of a file in the work copy.
    Reads through file_read, so secret files and paths outside the repository are refused (G1.1)."""
    root = ctx.work_dir or ctx.repo
    start = max(1, args.line - args.context)
    end = args.line + args.context
    text = file_read(root, args.path, start, end)  # raises FileReadDenied for secrets / paths outside (G1.1)
    ev = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool="file_excerpt",
                  facts={"path": args.path, "line": args.line, "context": args.context, "start": start, "end": end},
                  excerpt=text[:3000], file_path=args.path, line=args.line)
    return ToolOutput(evidence=[ev], summary=f"{args.path}:{start}-{end}")


def manifest_diff(ctx: ToolContext) -> ToolOutput:
    """Evidence `diff` summarising what changed against the baseline (legacy backup manifest or --compare-ref),
    taken from the detection step's `changes` artifact or, on a resumed run, changes.json in the run directory.
    Without a baseline the Evidence says so (available: False) instead of failing."""
    changes = ctx.artifacts.get("changes")
    if not changes:
        path = ctx.run_dir / "changes.json"
        changes = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    if not changes:
        ev = Evidence(run_id=ctx.run_id, kind="diff", source_tool="manifest_diff",
                      facts={"available": False, "reason": "no baseline to compare against"})
        return ToolOutput(evidence=[ev], summary="no changes artifact")
    # long lists are cut to 100 entries below so one huge diff cannot flood the investigator's context
    keys = ("base", "head", "added", "removed", "changed", "integrity_changed", "install_scripts_added")
    facts = {"available": True, **{k: (changes[k][:100] if isinstance(changes[k], list) else changes[k])
                                   for k in keys if k in changes}}
    ev = Evidence(run_id=ctx.run_id, kind="diff", source_tool="manifest_diff", facts=facts)
    return ToolOutput(evidence=[ev], summary=f"{len(facts.get('added', []))} added, "
                                             f"{len(facts.get('removed', []))} removed, "
                                             f"{len(facts.get('changed', []))} changed")
