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
