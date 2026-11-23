"""Detector `lockfile` (D2-05, Dev2): npm projects without a committed lockfile / `package-lock=false` in .npmrc.

Checks the ORIGINAL target (ctx.repo), not the work copy: Guardian generates a lockfile in the work copy, which
would hide the very problem this detector reports.
"""
from __future__ import annotations

from pathlib import Path

from guardian.adapters.npm import find_projects, has_lockfile, read_npmrc
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolOutput

DETECTOR = "detector:lockfile"


def detect(ctx) -> ToolOutput:
    base = Path(ctx.repo)
    if not (base / "package.json").is_file() and (base / "requirements.txt").is_file():
        return detect_pip(ctx)
    return detect_npm(ctx)


def detect_pip(ctx) -> ToolOutput:
    """pip (D2-09): requirements.txt is the lockfile. Flags loose specs, missing --hash (no integrity check on
    install), and runtime dependencies that are not pinned at all (from the graph's PyPI metadata)."""
    from guardian.adapters.pypi import parse_requirements

    reqs = parse_requirements(Path(ctx.repo) / "requirements.txt")
    loose = [r for r in reqs if not r.pinned_version]
    no_hash = [r for r in reqs if not r.has_hash]
    G = getattr(ctx.graph, "G", None)
    unpinned = list(G.graph.get("unpinned_requirements", [])) if G is not None else []
    if not (loose or no_hash or unpinned):
        return ToolOutput(summary="requirements.txt fully pinned with hashes")
    evidence = [Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool=DETECTOR, file_path="requirements.txt",
                         line=r.line, excerpt=r.excerpt, facts={"name": r.name, "spec": r.spec, "pinned": False})
                for r in loose[:20]]
    evidence.append(Evidence(
        run_id=ctx.run_id, kind="detector_result", source_tool=DETECTOR, file_path="requirements.txt",
        facts={"requirements": len(reqs), "loose_specs": [r.name for r in loose],
               "without_hash": len(no_hash), "runtime_deps_not_pinned": unpinned}))
    parts = []
    if loose:
        parts.append(f"{len(loose)} unpinned")
    if unpinned:
        parts.append(f"{len(unpinned)} runtime dependencies not pinned")
    if no_hash:
        parts.append(f"{len(no_hash)}/{len(reqs)} without --hash")
    line = loose[0].line if loose else None
    fd = Finding(run_id=ctx.run_id, category=FindingCategory.LOCKFILE, detector=DETECTOR, scope=Scope.UNKNOWN,
                 title=f"requirements.txt is not a complete, integrity-checked lock ({'; '.join(parts)})",
                 project="root", file_path="requirements.txt", line=line,
                 evidence_ids=[e.evidence_id for e in evidence])
    return ToolOutput(findings=[fd], evidence=evidence, summary="; ".join(parts))


def detect_npm(ctx) -> ToolOutput:
    base = Path(ctx.repo)
    evidence: list[Evidence] = []
    missing: list[str] = []
    disabled_at = None
    for proj in find_projects(base):
        if has_lockfile(proj.dir):
            continue
        missing.append(proj.name)
        for line, key, value, raw in read_npmrc(proj.dir):
            if key == "package-lock" and value.lower() == "false":
                path = proj.relpath(".npmrc")
                disabled_at = disabled_at or (path, line)
                evidence.append(Evidence(
                    run_id=ctx.run_id, kind="file_excerpt", source_tool=DETECTOR, file_path=path, line=line,
                    excerpt=raw, facts={"setting": "package-lock=false", "project": proj.name}))
    if not missing:
        return ToolOutput(summary="all npm projects have a lockfile")

    evidence.append(Evidence(
        run_id=ctx.run_id, kind="detector_result", source_tool=DETECTOR,
        facts={"projects_without_lockfile": missing, "package_lock_disabled": disabled_at is not None,
               "lockfiles_checked": ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]}))
    file_path, line = disabled_at or ("package.json", None)
    why = "package-lock=false in .npmrc" if disabled_at else "no lockfile found"
    fd = Finding(
        run_id=ctx.run_id, category=FindingCategory.LOCKFILE, detector=DETECTOR,
        title=f"No lockfile committed ({why}); dependency versions are not reproducible",
        scope=Scope.UNKNOWN, project=missing[0], file_path=file_path, line=line,
        evidence_ids=[e.evidence_id for e in evidence])
    return ToolOutput(findings=[fd], evidence=evidence,
                      summary=f"lockfile missing for {', '.join(missing)} ({why})")
