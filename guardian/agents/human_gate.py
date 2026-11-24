"""Human gate (C6) + decision recording (G5.1, G5.2). Owner: Dev1.

`human_gate_node` contains only `interrupt()`: LangGraph re-runs an interrupted node from its start on resume,
so anything else in it would run twice (and a plan built there would get a new id). The plan is built before
it (remediation) and the decision is checked after it (record_decision), again in code even though the CLI /
API already checked it: the graph never trusts its caller.

Role in the pipeline (sequential mode only)
  remediation_node -> human_gate_node (pause) -> record_decision_node -> validator | remediation (replan) | next.
  Batch mode uses its own pair, `batch_gate_node` / `record_batch_node` in agents/batch.py, with the same split.

Inputs
  Graph state: run_id, plan_id (the plan being asked about), current (its finding id), decision (what the human
  submitted, injected by the resume call). Files: plans/<plan_id>.json (the plan the decision must match).

Outputs
  State keys: decision, route ("validate" | "replan" | "next" | "gate"), and after a reject
  last_validation = {"rejected": comment, "plan_id", "reason_type"} so remediation can steer the next alternative.
  Files: approvals.jsonl gets one appended line per accepted decision; pending_plan.json is cleared. Audit events:
  gate_resume (decision recorded), guardrail (decision refused), plus the "approval" record in the audit log.

Tools and LLM
  None: this agent calls no tool and no model. It only checks and records what a human decided.

Guardrails
  G5.1 the approval must carry the hash of the exact plan the human saw (approve / reject / accept_risk bind to it),
  so a plan cannot be swapped after the decision. G5.2 a reject or an accepted risk needs a written comment.
  A refused decision does not fail the run: the gate simply keeps waiting for a valid one.
"""

from __future__ import annotations

from langgraph.types import interrupt
from pydantic import ValidationError

from guardian.core.models import Approval, FindingStatus
from guardian.core.plans import append_approval, load_plan, set_pending
from guardian.graph.state import GraphState, get_ctx
from guardian.guardrails.approval import check_decision


def human_gate_node(state: GraphState) -> dict:
    """Pause the run until a human decides. Returns {"decision": <what the caller resumed with>}.

    The interrupt payload (plan and finding ids) is what the CLI / API show as "waiting for". Keep this node free of
    side effects: LangGraph re-executes it from the top when the run resumes."""
    return {"decision": interrupt({"plan_id": state.get("plan_id"), "finding_id": state.get("current")})}


def record_decision_node(state: GraphState) -> dict:
    """Validate the submitted decision against the stored plan, record it, and choose the next step.

    Returns {"route": "gate", "decision": None} when the decision is malformed or refused (G5.1 hash mismatch / G5.2
    missing comment): nothing is recorded and the run waits again. Otherwise it appends the approval to
    approvals.jsonl, clears pending_plan.json, updates the finding's status and routes by decision:
    approve -> "validate" (the validator applies the plan, G3.3), reject -> "replan" with the reviewer's comment and
    reason type for steering, accept_risk -> "next" (the finding is ACCEPTED, nothing is applied)."""
    rc = get_ctx(state["run_id"])
    run_dir, store, audit = rc.tool_ctx.run_dir, rc.store, rc.audit
    plan = load_plan(run_dir, state["plan_id"])
    # re-check in code even though the CLI / API did: this is the only check that cannot be bypassed by a caller
    try:
        approval = Approval.model_validate(state.get("decision") or {})
        reason = check_decision(plan, approval)
    except ValidationError as exc:
        approval, reason = None, f"malformed decision: {exc.errors()[0].get('msg')}"
    if reason:  # a refused decision is audited and the gate waits again; the run is neither failed nor advanced
        rule = "G5.2" if "comment" in reason else "G5.1"
        audit.emit("guardrail", "guardrail", f"{rule} decision refused: {reason} -> still waiting",
                   finding_id=plan.finding_id, data={"rule": rule, "plan_id": plan.plan_id})
        return {"decision": None, "route": "gate"}

    append_approval(run_dir, approval)  # approvals.jsonl is append-only: the validator later reads it back (G3.3)
    audit.record("approval", approval.model_dump(mode="json"))
    set_pending(run_dir, None)
    f = store.get_finding(plan.finding_id)
    audit.emit("human_gate", "gate_resume",
               f"{approval.decision.upper()} by {approval.decided_by} for plan {plan.plan_id}"
               + (f": {approval.comment}" if approval.comment else ""),
               finding_id=f.finding_id, data={"plan_id": plan.plan_id, "decision": approval.decision})
    if approval.decision == "approve":
        f.status = FindingStatus.VALIDATING
        route, out = "validate", {}
    elif approval.decision == "reject":
        f.status = FindingStatus.PLANNED
        route, out = "replan", {"last_validation": {"rejected": approval.comment, "plan_id": plan.plan_id,
                                                     "reason_type": approval.reason_type}}
    else:  # accept_risk: a person knowingly leaves the finding open; nothing is applied or validated
        f.status = FindingStatus.ACCEPTED
        route, out = "next", {"current": None, "attempt": 0, "plan_id": None}
    store.update_finding(f)
    return {"route": route, **out}
