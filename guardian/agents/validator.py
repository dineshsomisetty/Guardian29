"""Validator (Day-1 form): apply the approved plan to a fresh copy and re-run the detectors (C4). Owner: Dev1.

Verdict:
  verified      the target finding is gone from its detector's re-run and no detector reports anything new
  regressed     a re-run detector reports a finding the original run did not have (never verified)
  not_resolved  the target finding is still reported
  failed_build  the patch could not be applied
Build, unit/integration tests and the image rescan are the Docker sandbox (D2-08, Day 2): they are recorded as
not run (`build_ok: null`, `checks_skipped`), and a Day-1 `verified` therefore carries MEDIUM confidence.
A failed attempt goes back to remediation for a *different* plan; after 3 attempts the finding is escalated.
"""

from __future__ import annotations

from guardian.core.models import (
    Approval,
    Confidence,
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    Priority,
    ValidationResult,
    new_id,
)
from guardian.core.plans import load_plan, save_validation
from guardian.graph.state import GraphState, get_ctx
from guardian.tools.registry import EXTRA_ALLOW, ToolContext, call_tool

AGENT = "validator"
MAX_ATTEMPTS = 3
FILE_DETECTORS = ["detector:lockfile", "detector:typosquat", "detector:ci_pin", "detector:image_pin"]
CHECKS_SKIPPED = ["build", "unit_tests", "integration_tests", "image_rescan", "sbom_diff"]
BAND_SCORE = {Priority.CRITICAL: 90.0, Priority.HIGH: 70.0, Priority.MEDIUM: 50.0, Priority.LOW: 20.0, None: 50.0}


def finding_key(f: Finding) -> str:
    """Identity of a finding across runs of a detector (ids differ per run)."""
    if f.category is FindingCategory.LOCKFILE:
        return f.category.value  # one per repo; its title lists what is still missing
    return f"{f.category.value}|{f.file_path}|{f.title}"


def validator_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    plan = load_plan(ctx.run_dir, state["plan_id"])
    approval = Approval.model_validate(state["decision"])
    f = store.get_finding(plan.finding_id)
    attempt_id = new_id("at")
    audit.emit(AGENT, "agent_start", f"Validating plan {plan.plan_id} (attempt {plan.attempt}) for: {f.title[:80]}",
               finding_id=f.finding_id, evidence_ids=plan.evidence_ids)

    applied = call_tool(AGENT, "apply_plan", None, ctx, store, audit,
                        args={"plan_id": plan.plan_id, "attempt_id": attempt_id,
                              "ops": [o.model_dump(mode="json") for o in plan.ops]},
                        plan=plan, approval=approval)
    detectors = [d for d in dict.fromkeys([*FILE_DETECTORS, f.detector]) if d in EXTRA_ALLOW[AGENT]]
    after: list[Finding] = []
    det_ev: list[str] = []
    if applied is not None:
        attempt_dir = applied.artifacts["attempt_dir"]
        actx = ToolContext(run_id=ctx.run_id, run_dir=ctx.run_dir, repo=attempt_dir, settings=ctx.settings,
                           work_dir=attempt_dir, budget=ctx.budget)
        for d in detectors:
            out = call_tool(AGENT, d, None, actx, store, audit)
            if out is not None:
                after += out.findings
                det_ev += [e.evidence_id for e in out.evidence]
        before = {finding_key(g) for g in store.list_findings() if g.detector in detectors}
        now = {finding_key(g) for g in after}
        resolved = finding_key(f) not in now
        new = sorted(now - before)
        verdict = "verified" if resolved and not new else ("regressed" if new else "not_resolved")
    else:
        resolved, new, verdict = False, [], "failed_build"

    risk_before = BAND_SCORE[f.initial_risk]
    summary_ev = Evidence(run_id=ctx.run_id, kind="test_result", source_tool="validator",
                          facts={"attempt_id": attempt_id, "plan_id": plan.plan_id, "verdict": verdict,
                                 "target_finding_resolved": resolved, "new_findings": new,
                                 "detectors_rerun": detectors, "checks_skipped": CHECKS_SKIPPED,
                                 "risk_scale": "initial-risk band midpoint (full risk score in Day 2, D1-06)"})
    store.add_evidence(summary_ev)
    patch_ev = [e.evidence_id for e in (applied.evidence if applied else [])]
    result = ValidationResult(
        attempt_id=attempt_id, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=None,
        artifact_rescanned=None, target_finding_resolved=resolved, new_findings=new,
        detector_evidence_ids=det_ev, risk_before=risk_before, risk_after=0.0 if resolved else risk_before,
        verdict=verdict, final_confidence=Confidence.MEDIUM if verdict == "verified" else Confidence.LOW,
        log_evidence_ids=[summary_ev.evidence_id, *patch_ev])
    save_validation(ctx.run_dir, result)

    if verdict == "verified":
        f.status = FindingStatus.VERIFIED
        out = {"route": "next", "current": None, "attempt": 0, "plan_id": None, "last_validation": None}
    elif plan.attempt >= MAX_ATTEMPTS:
        f.status = FindingStatus.ESCALATED
        out = {"route": "next", "current": None, "attempt": 0, "plan_id": None, "last_validation": None}
    else:
        f.status = FindingStatus.PLANNED
        out = {"route": "replan", "last_validation": {"verdict": verdict, "attempt_id": attempt_id, "new": new}}
    store.update_finding(f)
    audit.emit(AGENT, "agent_end",
               f"{verdict.upper()}: {f.title[:70]} (target resolved={resolved}, new findings={len(new)}; "
               f"build/tests not run on Day 1) -> {f.status.value}",
               finding_id=f.finding_id, evidence_ids=[summary_ev.evidence_id, *det_ev][:50],
               data={"attempt_id": attempt_id, "verdict": verdict})
    return out
