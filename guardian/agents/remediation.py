"""Remediation agent (Day-1 form): build one concrete, evidence-backed plan per attempt. Owner: Dev1.

Deterministic on purpose for Day 1: candidates come from the finding's evidence (similar-name evidence for a
typosquat, the workflow line for an action, the resolved lockfile for a missing lockfile) and every target
(replacement name, commit SHA, lockfile) is itself evidence (G4.5). The LLM choice between candidates and the
CVE upgrade path are D1-07 (Day 2). A retry never repeats an earlier plan for the same finding: after a reject
or a failed validation the next candidate is used, and when none is left the finding is escalated (G5.4).

Heuristic findings (typosquat) only get replace / remove / escalate (G5.3).
The plan, its dry-run diff and its hash are fixed *before* the human gate (C6), so the approval binds to the
exact change that will be applied.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from guardian.core.models import (
    Claim,
    ClaimLabel,
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    PatchOp,
    RemediationPlan,
    new_id,
)
from guardian.core.plans import list_plans, save_plan, set_pending
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.approval import plan_hash
from guardian.guardrails.grounding import value_matches
from guardian.tools.registry import call_tool

AGENT = "remediation"
MAX_ATTEMPTS = 3  # G5.4
HEURISTIC_ACTIONS = {"replace", "remove", "block", "escalate"}  # G5.3
HEURISTIC = {FindingCategory.TYPOSQUAT, FindingCategory.MALICIOUS_INDICATOR, FindingCategory.DEPENDENCY_CONFUSION}


@dataclass
class Candidate:
    action: str
    ops: list[PatchOp]
    target: str | None
    claims: list[tuple[str, str | None, str | None]]  # (text, field, value) citing the finding's evidence
    detector: str
    evidence_ids: list[str] = field(default_factory=list)
    sha_lookup: tuple[str, str] | None = None  # (action, ref) resolved just before the plan is fixed


def ops_key(ops: list[PatchOp]) -> str:
    return json.dumps([o.model_dump(mode="json") for o in ops], sort_keys=True)


def _facts(rc: RunContext, f: Finding) -> tuple[dict, Evidence | None]:
    for eid in f.evidence_ids:
        ev = rc.store.get_evidence(eid)
        if ev is not None:
            return ev.facts, ev
    return {}, None


def candidates(rc: RunContext, f: Finding) -> list[Candidate]:
    facts, _ = _facts(rc, f)
    out: list[Candidate] = []
    if f.category is FindingCategory.TYPOSQUAT and facts.get("name") and f.file_path:
        name, popular = facts["name"], facts.get("similar_to")
        why = (f"'{name}' differs from the popular package '{popular}' by {facts.get('distance')} edit(s)",
               "similar_to", popular)
        if popular and not facts.get("legacy_manifest"):
            out.append(Candidate("replace", [PatchOp(op="replace_dependency", file_path=f.file_path,
                                                     args={"name": name, "new_name": popular})],
                                 popular, [why, (f"declared in {f.file_path} as {facts.get('range')}", "range",
                                                 facts.get("range")),
                                           (f"version range {facts.get('range')} is kept; API compatibility of "
                                            f"'{popular}' is not verified until the sandbox build (Day 2)", None,
                                            None)],
                                 "detector:typosquat"))
        out.append(Candidate("remove", [PatchOp(op="remove_dependency", file_path=f.file_path, args={"name": name})],
                             None, [why, ("removing it drops the suspicious package from the manifest; code that "
                                          "imports it would break", None, None)], "detector:typosquat"))
    elif f.category is FindingCategory.LOCKFILE:
        projects = sorted({"root", *facts.get("projects_without_lockfile", [])} if facts.get("projects_without_lockfile")
                          else {"root"})
        out.append(Candidate("pin", [PatchOp(op="generate_lockfile", file_path=".npmrc", args={"projects": projects})],
                             None, [("lockfile generation is disabled in .npmrc", "package_lock_disabled", "True"),
                                    ("lockfiles come from discovery's npm install --package-lock-only "
                                     "--ignore-scripts, so no install script ran to produce them", None, None)],
                             "detector:lockfile"))
    elif f.category is FindingCategory.UNPINNED_CI and facts.get("action") and facts.get("ref"):
        out.append(Candidate("pin", [], None,
                             [(f"{facts['action']} is referenced by the mutable ref {facts['ref']}", "ref", facts["ref"]),
                              ("a commit SHA cannot be moved by the action's owner, a tag can", None, None)],
                             "detector:ci_pin", sha_lookup=(facts["action"], facts["ref"])))
    if f.category in HEURISTIC:
        out = [c for c in out if c.action in HEURISTIC_ACTIONS]
    return out


def _claims(rc: RunContext, f: Finding, cand: Candidate, extra: list[str]) -> list[Claim]:
    cited = [e for e in (rc.store.get_evidence(i) for i in [*f.evidence_ids, *extra]) if e]
    out = []
    for text, fld, value in cand.claims:
        label = ClaimLabel.VERIFIED if value is not None and value_matches(cited, fld, str(value)) else ClaimLabel.INFERRED
        out.append(Claim(text=text, field=fld, value=None if value is None else str(value),
                         evidence_ids=[e.evidence_id for e in cited], label=label))
    return out


def build_plan(rc: RunContext, f: Finding, cand: Candidate, attempt: int) -> RemediationPlan | None:
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    extra: list[str] = []
    ops = list(cand.ops)
    target = cand.target
    if cand.sha_lookup:
        action, ref = cand.sha_lookup
        out = call_tool(AGENT, "resolve_action_sha", None, ctx, store, audit, args={"action": action, "ref": ref})
        if out is None:
            return None
        sha = out.artifacts["action_sha"]
        target = sha
        extra.append(out.evidence[0].evidence_id)
        ops = [PatchOp(op="pin_action_sha", file_path=f.file_path, args={"action": action, "ref": ref, "sha": sha})]
        cand.claims.append((f"{action}@{ref} currently resolves to commit {sha}", "sha", sha))
    plan_id = new_id("pl")
    preview = call_tool(AGENT, "plan_preview", None, ctx, store, audit,
                        args={"plan_id": plan_id, "ops": [o.model_dump(mode="json") for o in ops]})
    if preview is None:
        return None
    extra.append(preview.evidence[0].evidence_id)
    files = sorted({o.file_path for o in ops})
    risk = f.initial_risk.value if f.initial_risk else "unknown"
    plan = RemediationPlan(
        plan_id=plan_id, plan_hash="", finding_id=f.finding_id, attempt=attempt, action=cand.action, ops=ops,
        target_version=target, rationale=_claims(rc, f, cand, extra),
        expected_risk_reduction=(f"{risk} -> resolved, if {cand.detector} re-run on the patched copy no longer "
                                 f"reports it and reports nothing new (Day-1 validation; risk-score delta in Day 2, D1-06)"),
        rollback=(f"Nothing is applied to the target: the patch lands in a fresh copy under runs/<run>/attempts/. "
                  f"Discard that folder to roll back; after adoption, revert the diff of {', '.join(files)}."),
        evidence_ids=[*f.evidence_ids, *extra],
    )
    plan.plan_hash = plan_hash(plan)
    return plan


def remediation_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    store, audit = rc.store, rc.audit
    queue = list(state.get("plan_queue") or [])
    current, attempt = state.get("current"), state.get("attempt") or 0
    if current is None:
        if not queue:
            return {"route": "next", "plan_id": None}
        current, attempt = queue.pop(0), 0
    f = store.get_finding(current)
    attempt += 1
    audit.emit(AGENT, "agent_start", f"Planning attempt {attempt} for: {f.title[:90]}", finding_id=f.finding_id,
               evidence_ids=f.evidence_ids,
               data={"last_validation": state.get("last_validation")} if state.get("last_validation") else {})

    tried = {ops_key(p.ops) for p in list_plans(rc.tool_ctx.run_dir) if p.finding_id == f.finding_id}
    plan = None
    if attempt <= MAX_ATTEMPTS:
        for cand in candidates(rc, f):
            if cand.ops and ops_key(cand.ops) in tried:
                continue
            plan = build_plan(rc, f, cand, attempt)
            if plan is not None and ops_key(plan.ops) in tried:  # resolved to an op we already tried
                plan = None
                continue
            if plan is not None:
                break
    if plan is None:
        f.status = FindingStatus.ESCALATED
        store.update_finding(f)
        why = "attempt limit reached (G5.4)" if attempt > MAX_ATTEMPTS else "no untried safe plan left"
        audit.emit("supervisor", "decision", f"Escalated for security review: {f.title[:80]} ({why})",
                   finding_id=f.finding_id)
        return {"plan_queue": queue, "current": None, "attempt": 0, "plan_id": None, "route": "next",
                "last_validation": None}

    save_plan(rc.tool_ctx.run_dir, plan)
    set_pending(rc.tool_ctx.run_dir, plan)
    f.status = FindingStatus.AWAITING_HUMAN
    store.update_finding(f)
    verified = sum(1 for c in plan.rationale if c.label is ClaimLabel.VERIFIED)
    audit.emit(AGENT, "agent_end", f"Plan {plan.plan_id}: {plan.action} ({len(plan.ops)} ops, {verified} verified / "
                                   f"{len(plan.rationale) - verified} inferred claims)",
               finding_id=f.finding_id, evidence_ids=plan.evidence_ids,
               data={"plan_id": plan.plan_id, "plan_hash": plan.plan_hash, "action": plan.action,
                     "target": plan.target_version})
    audit.emit("human_gate", "gate_wait", f"Waiting for a human decision on plan {plan.plan_id} "
                                         f"(guardian decide --run {state['run_id']} --plan {plan.plan_id} ...)",
               finding_id=f.finding_id, data={"plan_id": plan.plan_id, "plan_hash": plan.plan_hash})
    return {"plan_queue": queue, "current": current, "attempt": attempt, "plan_id": plan.plan_id,
            "decision": None, "route": "gate"}
