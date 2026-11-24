"""D2-05 lockfile detector: lockfile generation disabled or no lockfile committed. Owner: Dev2.

Called by: the detection agent (tool `detector:lockfile`).
Why: without a committed lockfile every install resolves fresh versions, so a malicious or compromised release
can slip in unreviewed and builds are not reproducible.
Inputs: the ORIGINAL target repo (ctx.repo, not the work copy, because Guardian generates lockfiles in its copy),
its npm projects (adapters/npm.find_projects) and an optional `.npmrc` containing `package-lock=false`.
Output: at most one Finding, category `lockfile` (scope prod, project "root"), pointing at `.npmrc` (with the line)
when generation is disabled, else at package.json. Evidence kind `file_excerpt` with facts
{package_lock_disabled: bool, projects_without_lockfile: [project names]}.
No network, no cache. A repo with no npm project yields no finding.
"""

from __future__ import annotations

from guardian.adapters.npm import find_projects, line_of
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolContext, ToolOutput


def detect(ctx: ToolContext) -> ToolOutput:
    """Report projects lacking a lockfile and/or an .npmrc that disables lockfile generation."""
    repo = ctx.repo  # check the ORIGINAL target: the work copy has our generated lockfiles
    findings, evidence = [], []
    missing = [p.name for p in find_projects(repo) if not p.lockfile.exists()]
    npmrc = repo / ".npmrc"
    # line number of `package-lock=false` (None if absent); used both as the flag and as the evidence location
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
