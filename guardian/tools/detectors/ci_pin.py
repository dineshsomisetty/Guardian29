"""D4-12 ci_pin: GitHub Actions referenced by tag/branch instead of a 40-char commit SHA. Owner: Dev4."""

from __future__ import annotations

from guardian.adapters import github_actions, gitlab_ci
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolContext, ToolOutput


def detect(ctx: ToolContext) -> ToolOutput:
    root = ctx.work_dir or ctx.repo
    refs = github_actions.parse(root)
    groups: dict[tuple[str, str], list] = {}
    for r in refs:
        if not r.local and not r.pinned:
            groups.setdefault((r.file, f"{r.action}@{r.ref}"), []).append(r)
    findings, evidence = [], []
    for (file, target), hits in groups.items():
        first = hits[0]
        ev = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool="detector:ci_pin",
                      facts={"action": first.action, "ref": first.ref, "pinned_to_sha": False,
                             "lines": [h.line for h in hits], "workflow": file,
                             "pinned_actions_in_repo": sum(1 for r in refs if r.pinned)},
                      file_path=file, line=first.line, excerpt=first.raw)
        evidence.append(ev)
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.UNPINNED_CI,
            title=f"GitHub Action {target} not pinned to a commit SHA", detector="detector:ci_pin",
            scope=Scope.PROD, project="root", file_path=file, line=first.line, evidence_ids=[ev.evidence_id]))
    # GitLab CI: `include:` of another project's pipeline at a branch/tag, or of a remote URL
    _, includes = gitlab_ci.parse(root)
    for inc in includes:
        if inc.pinned:
            continue
        ev = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool="detector:ci_pin",
                      facts={"include": inc.source, "ref": inc.ref, "pinned_to_sha": False, "ci": "gitlab"},
                      file_path=inc.file, line=inc.line, excerpt=inc.raw)
        evidence.append(ev)
        at = f"@{inc.ref}" if inc.ref else " (remote URL)"
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.UNPINNED_CI,
            title=f"GitLab CI include {inc.source}{at} not pinned to a commit SHA", detector="detector:ci_pin",
            scope=Scope.PROD, project="root", file_path=inc.file, line=inc.line, evidence_ids=[ev.evidence_id]))
    return ToolOutput(findings=findings, evidence=evidence,
                      summary=f"{len(refs)} action refs + {len(includes)} GitLab includes, {len(findings)} not SHA-pinned")
