"""D2-05 lockfile detector: lockfile generation disabled or no lockfile committed. Owner: Dev2."""

from __future__ import annotations

from guardian.adapters.npm import find_projects, line_of
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolContext, ToolOutput


def detect(ctx: ToolContext) -> ToolOutput:
    repo = ctx.repo  # check the ORIGINAL target: the work copy has our generated lockfiles
    findings, evidence = [], []
    missing = [p.name for p in find_projects(repo) if not p.lockfile.exists()]
    npmrc = repo / ".npmrc"
    line = line_of(npmrc, r"^\s*package-lock\s*=\s*false") if npmrc.exists() else None
    if line or missing:
        facts = {"package_lock_disabled": bool(line), "projects_without_lockfile": missing}
        ev = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool="detector:lockfile", facts=facts,
                      file_path=".npmrc" if line else None, line=line,
                      excerpt="package-lock=false" if line else None)
        evidence.append(ev)
        title = ("Lockfile generation disabled (.npmrc package-lock=false)" if line
                 else "No lockfile committed")
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.LOCKFILE,
            title=f"{title}; no lockfile for {', '.join(missing) or 'any project'}",
            detector="detector:lockfile", scope=Scope.PROD, project="root",
            file_path=".npmrc" if line else "package.json", line=line, evidence_ids=[ev.evidence_id]))
    return ToolOutput(findings=findings, evidence=evidence)
