"""G3.3 / G5.1 / G5.2: approvals are bound to the exact plan a human saw. Owner: Dev1.

`plan_hash` is a SHA-256 over the canonical JSON of the plan's content (ops, target, rationale ...), so an
approval for one plan can never be replayed onto a different or edited plan.
"""

from __future__ import annotations

import hashlib
import json

from guardian.core.models import Approval, RemediationPlan

DECISIONS = {"approve", "reject", "accept_risk"}


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
    return None


def check_write(plan: RemediationPlan | None, approval: Approval | None) -> str | None:
    """G3.3: a write tool may run only under an `approve` decision that matches the plan."""
    if plan is None or approval is None:
        return "write tool called without a plan + approval"
    if approval.decision != "approve":
        return f"decision is {approval.decision}, not approve"
    return check_decision(plan, approval)
