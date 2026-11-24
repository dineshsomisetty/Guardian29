"""G3.3 / G5.1 / G5.2: approvals are bound to the exact plan a human saw. Owner: Dev1.

`plan_hash` is a SHA-256 over the canonical JSON of the plan's content (ops, target, rationale ...), so an
approval for one plan can never be replayed onto a different or edited plan.
"""

from __future__ import annotations

import hashlib
import json

from guardian.core.models import Approval, RemediationPlan

DECISIONS = {"approve", "reject", "accept_risk"}
REASON_TYPES = {"too_big", "breaks_app", "different_approach", "other"}  # mirrors remediation.REASON_TYPES


def plan_hash(plan: RemediationPlan) -> str:
    body = plan.model_dump(mode="json", exclude={"plan_hash"})
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def check_decision(plan: RemediationPlan, approval: Approval) -> str | None:
    """Return why this decision is invalid for this plan, or None if it is valid (G5.1, G5.2)."""
    if approval.decision not in DECISIONS:
        return f"unknown decision {approval.decision!r}"
    if approval.plan_id != plan.plan_id:
        return f"decision is for plan {approval.plan_id}, pending plan is {plan.plan_id}"
    if approval.plan_hash != plan.plan_hash or plan.plan_hash != plan_hash(plan):
        return "plan_hash does not match the pending plan (plan changed or wrong plan)"
    if approval.decision in {"reject", "accept_risk"} and not (approval.comment or "").strip():
        return f"{approval.decision} requires a comment (G5.2)"
    if approval.reason_type is not None and (approval.decision != "reject" or approval.reason_type not in REASON_TYPES):
        return f"reason type {approval.reason_type!r} is only for a reject, one of {sorted(REASON_TYPES)}"
    return None


def check_write(plan: RemediationPlan | None, approval: Approval | None) -> str | None:
    """G3.3: a write tool may run only under an `approve` decision that matches the plan."""
    if plan is None or approval is None:
        return "write tool called without a plan + approval"
    if approval.decision != "approve":
        return f"decision is {approval.decision}, not approve"
    return check_decision(plan, approval)


def check_batch(pending: dict | None, batch_id: str, approvals: list[Approval], partial: bool = False) -> str | None:
    """Why this set of decisions is invalid for the batch waiting at the gate, or None.

    Validation starts only when EVERY item of the batch has a decision: a missing, extra or duplicated plan is
    refused as a whole, as is any hash mismatch (G5.1) or reject / accept_risk without a comment (G5.2).
    With `partial=True` ("one at a time") at least one decision is required and every decision must be for a pending
    item, but pending items may stay undecided."""
    if not pending:
        return "no batch is waiting for decisions"
    if batch_id != pending.get("batch_id"):
        return f"decisions are for batch {batch_id}, the pending batch is {pending.get('batch_id')}"
    items = {i["plan_id"]: i for i in pending.get("items", [])}
    ids = [a.plan_id for a in approvals]
    if len(set(ids)) != len(ids):
        return "a plan has more than one decision"
    if extra := sorted(set(ids) - set(items)):
        return f"decision for plan(s) not in this batch: {', '.join(extra)}"
    if partial and not ids:
        return "a one-at-a-time submission needs at least one decision"
    if not partial and (missing := sorted(set(items) - set(ids))):
        return f"{len(missing)} plan(s) have no decision yet (every fix needs one): {', '.join(missing)}"
    for a in approvals:
        if a.decision not in DECISIONS:
            return f"unknown decision {a.decision!r} for plan {a.plan_id}"
        if a.plan_hash != items[a.plan_id]["plan_hash"]:
            return f"plan_hash for plan {a.plan_id} does not match the pending plan (G5.1)"
        if a.decision in {"reject", "accept_risk"} and not (a.comment or "").strip():
            return f"{a.decision} for plan {a.plan_id} requires a comment (G5.2)"
        if a.reason_type is not None and (a.decision != "reject" or a.reason_type not in REASON_TYPES):
            return f"reason type {a.reason_type!r} for plan {a.plan_id} is only for a reject, one of {sorted(REASON_TYPES)}"
    return None
