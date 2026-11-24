"""Human gate (C6) + decision recording (G5.1, G5.2). Owner: Dev1.

`human_gate_node` contains only `interrupt()`: LangGraph re-runs an interrupted node from its start on resume,
so anything else in it would run twice (and a plan built there would get a new id). The plan is built before
it (remediation) and the decision is checked after it (record_decision), again in code even though the CLI /
API already checked it: the graph never trusts its caller.
"""

from __future__ import annotations

from langgraph.types import interrupt
from pydantic import ValidationError

from guardian.core.models import Approval, FindingStatus
from guardian.core.plans import append_approval, load_plan, set_pending
from guardian.graph.state import GraphState, get_ctx
from guardian.guardrails.approval import check_decision


def human_gate_node(state: GraphState) -> dict:
    return {"decision": interrupt({"plan_id": state.get("plan_id"), "finding_id": state.get("current")})}


def record_decision_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    run_dir, store, audit = rc.tool_ctx.run_dir, rc.store, rc.audit
    plan = load_plan(run_dir, state["plan_id"])
    try:
        approval = Approval.model_validate(state.get("decision") or {})
        reason = check_decision(plan, approval)
    except ValidationError as exc:
        approval, reason = None, f"malformed decision: {exc.errors()[0].get('msg')}"
    if reason:
        rule = "G5.2" if "comment" in reason else "G5.1"
        audit.emit("guardrail", "guardrail", f"{rule} decision refused: {reason} -> still waiting",
                   finding_id=plan.finding_id, data={"rule": rule, "plan_id": plan.plan_id})
        return {"decision": None, "route": "gate"}

    append_approval(run_dir, approval)
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
    else:  # accept_risk
        f.status = FindingStatus.ACCEPTED
        route, out = "next", {"current": None, "attempt": 0, "plan_id": None}
    store.update_finding(f)
    return {"route": route, **out}
