"""D2-10 automated remediation "PR": a local git branch in the attempt's work copy + PR.md. Owner: Dev2.

After a `verified` validation the patched files are committed on `guardian/fix-<finding-short-id>` inside
runs/<id>/attempts/<attempt_id>/work and a reviewer-facing `PR.md` is written next to it. G5.5: no remote is ever
configured or contacted, nothing is pushed or merged, the target itself is never touched. Every git call is an argv
list (no shell) with hooks disabled, so a hook copied from the target cannot run.

The tool is a write tool (G3.3): it runs only under the `approve` Approval that matches the plan.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from guardian.core.models import Approval, Evidence, RemediationPlan, ValidationResult
from guardian.core.plans import load_plan, load_validation
from guardian.core.store import JsonStore
from guardian.guardrails.redact import redact
from guardian.tools import binaries
from guardian.tools.patching import PatchError, confined
from guardian.tools.registry import ToolContext, ToolOutput

AUTHOR = "Guardian <guardian@localhost>"


class BranchArgs(BaseModel):
    plan_id: str = Field(pattern=r"^pl_[0-9A-Z]{26}$")
    attempt_id: str = Field(pattern=r"^at_[0-9A-Z]{26}$")
    finding_id: str = Field(pattern=r"^fd_[0-9A-Z]{26}$")
    also_plan_ids: list[str] = Field(default=[], max_length=200)  # batch: other verified plans of the same attempt


def branch_name(finding_id: str) -> str:
    return f"guardian/fix-{finding_id[-8:].lower()}"


def _git(work: Path, hooks: Path, *args: str) -> str:
    argv = [binaries.find("git"), "-c", f"core.hooksPath={hooks}", "-c", "core.fsmonitor=false",
            "-c", "commit.gpgsign=false", "-c", "user.name=Guardian", "-c", "user.email=guardian@localhost",
            "-c", "init.defaultBranch=main", *args]
    return binaries.run(argv, cwd=work, timeout=120).stdout.strip()


def _approval(run_dir: Path, plan_id: str) -> Approval | None:
    path = run_dir / "approvals.jsonl"
    found = None
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                a = Approval.model_validate_json(line)
            except ValueError:
                continue
            if a.plan_id == plan_id:
                found = a
    return found


def patched_files(store: JsonStore, result: ValidationResult, attempt_id: str) -> list[str]:
    """Files the applied patch touched, from the (non-preview) patch_diff evidence of this attempt."""
    files: list[str] = []
    for eid in result.log_evidence_ids:
        ev = store.get_evidence(eid)
        if ev and ev.kind == "patch_diff" and ev.facts.get("attempt_id") == attempt_id:
            files += [*ev.facts.get("files", []), *ev.facts.get("lockfiles_added", [])]
    return sorted(dict.fromkeys(files))


def _commit_message(plan: RemediationPlan, finding_title: str, approval: Approval | None) -> str:
    who = approval.decided_by if approval else "unknown"
    return (f"guardian: {plan.action} - {finding_title[:90]}\n\n"
            f"Finding: {plan.finding_id}\nPlan: {plan.plan_id} ({plan.plan_hash[:12]})\n"
            f"Approved-by: {who}\n\nLocal branch only: Guardian never pushes or merges (G5.5).\n")


def _commit(work: Path, hooks: Path, branch: str, files: list[str], source: Path, message: str) -> str:
    fresh = not (work / ".git").exists()  # never run git here without its own repo: it would find a parent repo
    if fresh:
        _git(work, hooks, "init", "-q")
        saved: dict[str, bytes | None] = {}
        for rel in files:  # baseline = the target as it was, so the branch diff is exactly the patch
            dst = confined(work, rel)
            saved[rel] = dst.read_bytes() if dst.exists() else None
            src = confined(source, rel)
            if src.exists():
                dst.write_bytes(src.read_bytes())
            else:
                dst.unlink(missing_ok=True)
        _git(work, hooks, "add", "-A")
        _git(work, hooks, "commit", "-q", "--no-verify", "--allow-empty", "--author", AUTHOR,
             "-m", "baseline: target before the Guardian fix")
        _git(work, hooks, "checkout", "-q", "-b", branch)
        for rel, data in saved.items():
            dst = confined(work, rel)
            if data is None:
                dst.unlink(missing_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(data)
    else:
        _git(work, hooks, "checkout", "-q", "-B", branch)
    _git(work, hooks, "add", "-A", "--", *files)
    if not _git(work, hooks, "diff", "--cached", "--name-only"):
        raise PatchError("the patch changed nothing to commit")
    _git(work, hooks, "commit", "-q", "--no-verify", "--author", AUTHOR, "-m", message)
    return _git(work, hooks, "rev-parse", "HEAD")


def _fmt(d: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in d.items()) if d else "not run"


def render_pr(store: JsonStore, plan: RemediationPlan, result: ValidationResult, approval: Approval | None,
              finding_title: str, branch: str, commit: str, files: list[str]) -> str:
    diff_ev = next((e for e in (store.get_evidence(i) for i in plan.evidence_ids)
                    if e and e.kind == "patch_diff"), None)
    summary_ev = next((e for e in (store.get_evidence(i) for i in result.log_evidence_ids)
                       if e and e.source_tool == "validator"), None)
    sbom = store.get_evidence(result.sbom_diff_evidence_id) if result.sbom_diff_evidence_id else None
    out = [f"# Guardian fix: {finding_title}", "",
           f"Branch `{branch}` @ `{commit[:12]}` in the attempt's work copy. Local only: not pushed, not merged (G5.5).",
           "", "## Proposed fix", "",
           f"- action: `{plan.action}`" + (f" -> `{plan.target_version}`" if plan.target_version else ""),
           f"- files: {', '.join(f'`{f}`' for f in files)}",
           f"- plan `{plan.plan_id}` (hash `{plan.plan_hash[:12]}`), attempt {plan.attempt}"]
    if plan.compatibility_impact:
        c = plan.compatibility_impact
        out.append(f"- compatibility: {c.semver_delta} change {c.from_version} -> {c.to_version}, risk {c.level}")
    if diff_ev and diff_ev.excerpt:
        out += ["", "```diff", diff_ev.excerpt.rstrip(), "```"]
    out += ["", "## Rationale", ""]
    out += [f"- **{c.label.value.upper()}** {c.text}" for c in plan.rationale] or ["- none recorded"]
    out += ["", "## Validation", "", f"- verdict: **{result.verdict}** (confidence {result.final_confidence.value})",
            f"- build: {result.build_ok if result.build_ok is not None else 'not run'}",
            f"- unit tests: {_fmt(result.unit_tests)}", f"- integration tests: {_fmt(result.integration_tests)}",
            f"- artifact rescan: {result.artifact_rescanned or 'not run'}",
            f"- target finding resolved: {result.target_finding_resolved}",
            f"- new findings: {', '.join(result.new_findings) or 'none'}"]
    if sbom:
        f = sbom.facts
        out.append(f"- SBOM diff: +{len(f.get('added', []))} -{len(f.get('removed', []))} "
                   f"~{len(f.get('changed', []))} ({f.get('components_before')} -> {f.get('components_after')} components)")
        out += [f"  - changed {c['name']}: {c['from']} -> {c['to']}" for c in f.get("changed", [])[:10]]
    else:
        out.append("- SBOM diff: not run")
    if summary_ev:
        skipped = summary_ev.facts.get("checks_skipped") or []
        if skipped:
            out.append(f"- checks not run: {', '.join(skipped)}")
        out += [f"- known limitation: {t}" for t in summary_ev.facts.get("known_limitations", [])]
    out += ["", "## Risk", "", f"- before {result.risk_before:g} -> after {result.risk_after:g}",
            f"- {plan.expected_risk_reduction}", "", "## Rollback", "", plan.rollback,
            f"In this branch: `git revert {commit[:12]}`, or delete the branch.", "", "## Approval", ""]
    if approval:
        out.append(f"- {approval.decision} by **{approval.decided_by}** at {approval.ts.isoformat(timespec='seconds')}, "
                   f"plan_hash `{approval.plan_hash}`" + (f", comment: {approval.comment}" if approval.comment else ""))
    else:
        out.append("- no approval record found")
    out += ["", "_Generated by Guardian. A human must review and merge; Guardian never does._", ""]
    return redact("\n".join(out))


def local_fix_branch(ctx: ToolContext, args: BranchArgs) -> ToolOutput:
    work = ctx.work_dir
    attempt_dir = ctx.run_dir / "attempts" / args.attempt_id
    if work is None or work.resolve() != (attempt_dir / "work").resolve():
        raise PatchError("local_fix_branch works only in the attempt's own work copy")
    store = JsonStore(ctx.run_dir)
    plan = load_plan(ctx.run_dir, args.plan_id)
    result = load_validation(ctx.run_dir, args.attempt_id, args.plan_id)
    if plan is None or result is None:
        raise PatchError("plan or validation result missing")
    if result.verdict != "verified":
        raise PatchError(f"no branch for a {result.verdict} attempt")
    files = patched_files(store, result, args.attempt_id)
    if not files:
        raise PatchError("no patched files recorded")
    finding = store.get_finding(args.finding_id)
    approval = _approval(ctx.run_dir, plan.plan_id)
    extras = []  # batch: the other verified plans of this attempt go on the same branch and into the same PR.md
    for pid in args.also_plan_ids:
        p2, r2 = load_plan(ctx.run_dir, pid), load_validation(ctx.run_dir, args.attempt_id, pid)
        if p2 is None or r2 is None or r2.verdict != "verified":
            raise PatchError(f"plan {pid} is not a verified plan of attempt {args.attempt_id}")
        files = sorted(dict.fromkeys([*files, *patched_files(store, r2, args.attempt_id)]))
        extras.append((p2, r2, _approval(ctx.run_dir, pid), store.get_finding(p2.finding_id).title))
    branch = branch_name(args.finding_id)
    hooks = attempt_dir / ".nohooks"
    hooks.mkdir(exist_ok=True)
    message = _commit_message(plan, finding.title, approval)
    if extras:
        message += "\nAlso in this commit:\n" + "".join(
            f"- {p2.action} {t[:80]} (plan {p2.plan_id}, approved by {a.decided_by if a else 'unknown'})\n"
            for p2, _r, a, t in extras)
    commit = _commit(work, hooks, branch, files, ctx.artifacts.get("target_repo", ctx.repo), message)
    md = attempt_dir / "PR.md"
    text = render_pr(store, plan, result, approval, finding.title, branch, commit, files)
    for p2, r2, a2, t2 in extras:
        body = render_pr(store, p2, r2, a2, t2, branch, commit, files).split("\n", 4)[4]
        text += f"\n---\n\n# Also in this PR: {t2}\n\n" + body
    md.write_text(text, encoding="utf-8")
    ev = Evidence(run_id=ctx.run_id, kind="diff", source_tool="git (local)",
                  facts={"branch": branch, "commit": commit, "files": files, "pushed": False, "remote": None,
                         "author": AUTHOR}, excerpt=f"{branch} {commit}")
    return ToolOutput(evidence=[ev], artifacts={"pr_markdown": md, "branch": branch, "commit": commit},
                      summary=f"local branch {branch} @ {commit[:10]} + PR.md (not pushed)")
