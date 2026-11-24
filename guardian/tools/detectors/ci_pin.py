"""D4-12 ci_pin: CI references (GitHub Actions, GitLab includes) not pinned to a commit SHA. Owner: Dev4.

Called by: the detection agent (tool `detector:ci_pin`); the validator re-runs it on patched copies.
Why: a tag or branch can be moved by whoever controls the action's repository, so every pipeline run would
execute different code with the pipeline's secrets. Only a full 40-char commit SHA is immutable.
Inputs: workflow files parsed by adapters/github_actions.py (`uses: owner/action@ref`) and
adapters/gitlab_ci.py (`include:` entries). Local actions (`./...`) are never flagged.
Output: Finding category `unpinned_ci` (scope prod, project "root"), one per (workflow file, action@ref) with every
line of that use in the evidence, and one per unpinned GitLab include. Evidence kind `file_excerpt` with facts
  GitHub: {action, ref, pinned_to_sha: False, lines, workflow, pinned_actions_in_repo}
  GitLab: {include, ref, pinned_to_sha: False, ci: "gitlab"}
No network, no cache: purely a read of the repo files.
"""

from __future__ import annotations

from guardian.adapters import github_actions, gitlab_ci
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolContext, ToolOutput


def detect(ctx: ToolContext) -> ToolOutput:
    """Flag every non-local, non-SHA-pinned GitHub Action use and GitLab include in the work copy."""
    root = ctx.work_dir or ctx.repo
    refs = github_actions.parse(root)
    # (workflow file, "action@ref") -> uses of it, so repeated uses in one file give one finding
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
                             # context for the analyst: the repo already pins some actions, so pinning is feasible
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
