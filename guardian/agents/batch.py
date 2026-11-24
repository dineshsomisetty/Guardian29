"""Batch remediation (settings.remediation_mode == "batch"): every finding gets a recommendation, a human decides
on all of them together, and the approved fixes are validated together. Owner: Dev1.

Graph: risk_analyst -> recommend -> batch_gate -> record_batch -> validate_batch -> recommend (next round) | reporter

* `recommend_node` groups the findings (CVEs on the same package instance share one fix chosen to clear every
  advisory on it; everything else is its own item), builds a hash-bound plan per item from the existing
  `remediation.candidates` / `build_plan`, and writes recommendations.json + pending_batch.json. Items with no
  candidate say "no alternative" and why. In later rounds only the items whose fix was rejected or failed come back,
  with their next untried alternative (max 3 attempts per item, G5.4, then "needs a person").
* `batch_gate_node` contains ONLY `interrupt()` (like human_gate_node: a resume re-runs the node from its start).
* `record_batch_node` re-checks the whole set of decisions in code (every item decided, no extras, G5.1 hash, G5.2
  comment) before recording anything: a partial or mismatched set leaves the batch waiting.
* `validate_batch_node` validates the approved plans together (validator.validate_plans) and sets each item's outcome.
The state of the rounds lives in runs/<id>/recommendations.json, not in the graph state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from langgraph.types import interrupt
from pydantic import ValidationError

from guardian.agents.remediation import (
    MAX_ATTEMPTS,
    REASON_TYPES,
    Candidate,
    advisories_at,
    build_plan,
    candidates,
    child_floor_hits,
    dep_keys,
    ops_key,
    package_purl,
    steer,
)
from guardian.agents.validator import Item, validate_plans
from guardian.core.models import (
    Approval,
    ClaimLabel,
    Finding,
    FindingCategory,
    FindingStatus,
    ValidationResult,
    new_id,
)
from guardian.core.plans import (
    append_approval,
    get_pending_batch,
    list_plans,
    load_plan,
    load_risks,
    save_plan,
    set_pending_batch,
)
from guardian.core.recs import Alternative, Previous, Recommendation, load_recs, save_recs
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.approval import check_batch, check_decision
from guardian.tools.threat_intel import parse_purl, version_key

AGENT = "remediation"

_VERDICT_TEXT = {
    "failed_build": "the build failed",
    "failed_tests": "tests that passed before now fail",
    "timeout": "the sandbox run timed out",
    "not_resolved": "the finding is still reported after the fix",
    "interaction": "it verifies alone but fails together with the fixes already verified (interaction not resolved)",
}


def _set_status(rc: RunContext, finding_ids: list[str], status: FindingStatus) -> None:
    for fid in finding_ids:
        f = rc.store.get_finding(fid)
        if f is not None:
            f.status = status
            rc.store.update_finding(f)


# ---------------------------------------------------------------- grouping + candidates


def group_findings(findings: list[Finding], scores: dict[str, float]) -> list[list[Finding]]:
    """CVEs on the same package instance share one recommendation; every other finding is its own group.
    Members are ordered highest score first, groups too."""
    def key(f: Finding) -> tuple:
        return -scores.get(f.finding_id, 0), f.title, f.component_purl or "", f.file_path or "", f.line or 0

    by_purl: dict[str, list[Finding]] = {}
    groups: list[list[Finding]] = []
    for f in sorted(findings, key=key):
        if f.category is FindingCategory.CVE and f.component_purl:
            if f.component_purl not in by_purl:
                by_purl[f.component_purl] = []
                groups.append(by_purl[f.component_purl])
            by_purl[f.component_purl].append(f)
        else:
            groups.append([f])
    return groups


def _pkg(f: Finding) -> str:
    try:
        return parse_purl(f.component_purl)[0] if f.component_purl else (f.title or "the package")
    except ValueError:
        return f.component_purl or f.title


def summarise(cand: Candidate) -> Alternative:
    name = next((str(o.args["name"]) for o in cand.ops if "name" in o.args), None)
    if cand.action == "upgrade":
        text = f"upgrade {name} to {cand.target}" if name else f"upgrade to {cand.target}"
    elif cand.action == "replace":
        text = f"replace {name} with {cand.target}"
    elif cand.action == "remove":
        text = f"remove {name} from the manifest"
    elif cand.action == "block":
        text = f"remove {name} and add it to the denylist"
    elif cand.action == "mitigate":
        text = "accept the risk with a documented mitigation (nothing is changed)"
    else:
        text = cand.action.replace("_", " ") + (f" to {cand.target}" if cand.target else "")
    return Alternative(action=cand.action, target_version=cand.target, summary=text)


def no_alternative_reason(f: Finding) -> str:
    c = f.category
    if c is FindingCategory.CVE:
        name = _pkg(f)
        if not f.fixed_versions:
            return (f"No alternatives: no fixed version of {name} has been published for {f.vuln_id or 'this advisory'}, "
                    f"so an upgrade cannot remove it")
        if not (f.component_purl or "").startswith(("pkg:npm/", "pkg:pypi/")):
            return f"No alternatives: Guardian only patches npm and PyPI manifests, and {name} is neither"
        return (f"No alternatives: no safe upgrade path was found for {name} (every candidate version is "
                f"unavailable or still affected by another advisory, or the manifest does not declare it directly "
                f"and its parent cannot be moved)")
    if c is FindingCategory.INSTALL_SCRIPT:
        return "No alternatives: an install script is a property of the package; Guardian does not patch packages"
    if c is FindingCategory.POLICY_VIOLATION:
        return "No alternatives: no safe automatic change exists for this policy violation; it needs a person's decision"
    if c in (FindingCategory.UNEXPECTED_CHANGE, FindingCategory.INTEGRITY_CHANGE, FindingCategory.MAJOR_JUMP,
             FindingCategory.MAINTAINER_CHANGE):
        return "No alternatives: this is a change to review, not something Guardian can safely revert"
    if c in (FindingCategory.OUTDATED, FindingCategory.PROVENANCE_GAP):
        return "No alternatives: Guardian has no verified fix for this kind of finding"
    return "No alternatives: Guardian found no safe, evidence-backed fix for this finding"


@dataclass
class Prep:
    """A group's candidate fixes before any plan is built (so groups editing one dependency can be merged)."""

    rec: Recommendation | None
    members: list[Finding]  # highest score first
    attempt: int
    primary: Finding
    cands: list[Candidate]
    tried: set = field(default_factory=set)
    tried_noop: set = field(default_factory=set)
    absorbed: list[str] = field(default_factory=list)  # rec_ids merged into this one
    note: str | None = None  # why the human's rejection reason rules every remaining option out


def _vkey(c: Candidate):
    return version_key(c.target or "0")


def candidate_hits(rc: RunContext, cand: Candidate) -> list[str]:
    """Advisories a candidate upgrade still leaves: on the package at that version and, through the version's
    dependency ranges, on vulnerable children (advisories_at + child floor)."""
    if cand.action != "upgrade" or not cand.target:
        return []
    out: list[str] = []
    for _file, name in dep_keys(cand.ops):
        purl = package_purl(rc, name)
        if not purl:
            continue
        out += advisories_at(rc, name, parse_purl(purl)[2], cand.target)
        out += child_floor_hits(rc, purl, [cand.target]).get(cand.target, [])
    return out


def prepare(rc: RunContext, members: list[Finding], rec: Recommendation | None) -> Prep:
    """Candidates for a group, then steered by why the human rejected the last fix (if they did)."""
    prep = _prepare(rc, members, rec)
    prev = rec.previous if rec else None
    if prev is not None and prev.outcome == "rejected" and prep.cands:
        prep.cands, prep.note = steer(prep.cands, load_plan(rc.tool_ctx.run_dir, prev.plan_id), prev.reason_type)
        if prev.reason_type and prev.reason_type != "other":
            rc.audit.emit(AGENT, "decision",
                          f"Rejected as '{REASON_TYPES.get(prev.reason_type, prev.reason_type)}': "
                          + (f"{len(prep.cands)} option(s) fit that" if prep.cands else f"none fits ({prep.note})"),
                          finding_id=prep.primary.finding_id, data={"reason_type": prev.reason_type})
    return prep


def _prepare(rc: RunContext, members: list[Finding], rec: Recommendation | None) -> Prep:
    ctx = rc.tool_ctx
    if ctx.budget is not None:
        ctx.budget.window(AGENT)  # G3.6: the remediation tool budget applies per group, not per run
    ids = [m.finding_id for m in members]
    mine = [p for p in list_plans(ctx.run_dir) if p.finding_id in ids]
    tried = {ops_key(p.ops) for p in mine if p.ops}
    tried_noop = {p.action for p in mine if not p.ops}  # a rejected mitigation is not offered again
    attempt = max((p.attempt for p in mine), default=0) + 1
    prep = Prep(rec, members, attempt, members[0], [], tried, tried_noop)
    if attempt > MAX_ATTEMPTS:
        return prep

    def untried(cs: list[Candidate]) -> list[Candidate]:
        return [c for c in cs if not (ops_key(c.ops) in tried if c.ops else c.action in tried_noop)]

    per_member = [(m, untried(candidates(rc, m))) for m in members]
    if len({m.component_purl for m in members}) > 1:
        # a merged group (several packages whose fixes edit one dependency): pool every member's candidates for
        # that dependency, highest version first, versions that still leave an advisory last
        first = next((c for _m, cs in per_member for c in cs if c.action == "upgrade" and dep_keys(c.ops)), None)
        if first is not None:
            key = dep_keys(first.ops)
            pool = {ops_key(c.ops): c for _m, cs in per_member for c in cs if dep_keys(c.ops) == key}
            ordered = sorted(pool.values(), key=_vkey, reverse=True)
            clean = [c for c in ordered if not candidate_hits(rc, c)]
            prep.cands = clean + [c for c in ordered if c not in clean]
            return prep
    for m, cs in per_member:  # the highest-scoring member that has a fix is the one the plan is built for
        if cs:
            prep.primary, prep.cands = m, cs
            break
    return prep


def merge_preps(rc: RunContext, preps: list[Prep], scores: dict[str, float]) -> list[Prep]:
    """Groups whose first-choice fix edits the same (manifest, dependency) become ONE recommendation: the union of
    their findings, the highest version of the pooled candidates that no advisory still affects (checked with
    advisories_at and the child floor). Two plans editing one dependency never reach a combined run."""
    buckets: dict[frozenset, list[Prep]] = {}
    for p in preps:
        if p.cands and p.cands[0].action == "upgrade" and dep_keys(p.cands[0].ops):
            buckets.setdefault(dep_keys(p.cands[0].ops), []).append(p)
    merged_away: set[int] = set()
    out: list[Prep] = []
    for key, group in buckets.items():
        if len(group) < 2:
            continue
        members = sorted({m.finding_id: m for p in group for m in p.members}.values(),
                         key=lambda m: (-scores.get(m.finding_id, 0), m.title, m.finding_id))
        tried = set().union(*(p.tried for p in group))
        pool = {ops_key(c.ops): c for p in group for c in p.cands if dep_keys(c.ops) == key and ops_key(c.ops) not in tried}
        ordered = sorted(pool.values(), key=_vkey, reverse=True)
        clean = [c for c in ordered if not candidate_hits(rc, c)]
        cands = clean + [c for c in ordered if c not in clean]
        best = max(group, key=lambda p: scores.get(p.primary.finding_id, 0))
        rec = next((p.rec for p in sorted(group, key=lambda p: -scores.get(p.primary.finding_id, 0)) if p.rec), None)
        new = Prep(rec, members, max(p.attempt for p in group), members[0], cands, tried,
                   set().union(*(p.tried_noop for p in group)),
                   [p.rec.rec_id for p in group if p.rec and (rec is None or p.rec.rec_id != rec.rec_id)])
        name = next(iter(key))
        rc.audit.emit("supervisor", "decision",
                      f"Merged {len(group)} recommendations that all edit {name[1]} in {name[0]} into one: "
                      f"{len(members)} finding(s), fix {cands[0].target if cands else 'none'} (highest version no "
                      f"advisory still affects" + ("" if clean else "; NONE is clean, highest kept") + ")",
                      finding_id=best.primary.finding_id,
                      data={"dependency": list(name), "targets": [c.target for c in ordered],
                            "findings": [m.finding_id for m in members]})
        merged_away.update(id(p) for p in group)
        out.append(new)
    return [p for p in preps if id(p) not in merged_away] + out


def _claim_for(g: Finding) -> tuple[str, str | None, str | None]:
    what = g.vuln_id or g.title[:80]
    return (f"this fix also resolves {what} on {_pkg(g)}", "vuln_id" if g.vuln_id else None, g.vuln_id)


def finish(rc: RunContext, prep: Prep, round_no: int, scores: dict[str, float]) -> Recommendation:
    """The recommendation for a prepared group: its first buildable untried candidate as a plan, else "no alternatives"."""
    ctx, audit = rc.tool_ctx, rc.audit
    members, rec, primary, attempt, tried = prep.members, prep.rec, prep.primary, prep.attempt, prep.tried
    ids = [m.finding_id for m in members]
    plan, alternatives = None, []
    for cand in prep.cands:
        if plan is not None:
            alternatives.append(summarise(cand))
            continue
        if len(members) > 1:  # the rationale lists every finding this one fix addresses
            cand.claims = [*cand.claims, *(_claim_for(g) for g in members if g.finding_id != primary.finding_id)]
            cand.evidence_ids = list(dict.fromkeys([*cand.evidence_ids, *(e for g in members for e in g.evidence_ids)]))
        built = build_plan(rc, primary, cand, attempt)
        if built is not None and ops_key(built.ops) in tried and built.ops:
            continue
        plan = built
    base = dict(round=round_no, finding_ids=ids, primary_finding_id=primary.finding_id,
                score=scores.get(primary.finding_id, 0), attempt=attempt - 1 if plan is None else attempt)
    prev = rec.previous if rec else None
    if plan is None:
        if rec is None:
            reason = no_alternative_reason(primary)
            audit.emit("supervisor", "decision", f"No alternative for: {primary.title[:90]} ({reason})",
                       finding_id=primary.finding_id)
        else:
            reason = (f"No alternatives left: the previous fix was rejected as "
                      f"'{REASON_TYPES.get(prev.reason_type or '', prev.reason_type)}' and {prep.note}"
                      if prep.note and prev else
                      f"No alternatives left: the previous fix {prev.outcome if prev else 'did not work'}"
                      f"{' (' + prev.detail + ')' if prev else ''} and Guardian has no other safe fix"
                      if attempt <= MAX_ATTEMPTS else "Attempt limit reached (G5.4): a person must look at this")
            _set_status(rc, ids, FindingStatus.ESCALATED)
            audit.emit("supervisor", "decision", f"Escalated for security review: {primary.title[:80]} ({reason})",
                       finding_id=primary.finding_id)
        return Recommendation(rec_id=rec.rec_id if rec else new_id("rc"), kind="no_alternative", reason=reason,
                              previous=prev, outcome="no_alternative", **base)
    save_plan(ctx.run_dir, plan)
    _set_status(rc, ids, FindingStatus.AWAITING_HUMAN)
    verified = sum(1 for c in plan.rationale if c.label is ClaimLabel.VERIFIED)
    audit.emit(AGENT, "agent_end", f"Plan {plan.plan_id}: {plan.action} ({len(plan.ops)} ops, {verified} verified / "
                                   f"{len(plan.rationale) - verified} inferred claims) for {len(ids)} finding(s)",
               finding_id=primary.finding_id, evidence_ids=plan.evidence_ids,
               data={"plan_id": plan.plan_id, "plan_hash": plan.plan_hash, "action": plan.action,
                     "target": plan.target_version, "round": round_no})
    return Recommendation(rec_id=rec.rec_id if rec else new_id("rc"), kind="fix", plan_id=plan.plan_id,
                          plan_hash=plan.plan_hash, alternatives=alternatives,
                          reason=(f"Another alternative: the previous fix {prev.outcome} ({prev.detail})"
                                  if prev else None), previous=prev, outcome="awaiting_decision", **base)


# ---------------------------------------------------------------- nodes


def recommend_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    run_dir = ctx.run_dir
    saved = load_recs(run_dir)
    items: list[Recommendation] = saved["items"]
    undecided = [r for r in items if r.outcome == "awaiting_decision"]
    round_no = (saved["round"] or 0) + (0 if undecided else 1)  # a partial step does not start a new round
    step = saved["step"]
    scores = {fid: a.score for fid, a in load_risks(run_dir).items()}
    if not items:
        todo: list[tuple[Recommendation | None, list[Finding]]] = [
            (None, g) for g in group_findings(store.list_findings(), scores)]
        audit.emit("supervisor", "decision",
                   f"Round {round_no} started: {len(todo)} recommendation item(s) for "
                   f"{sum(len(g) for _, g in todo)} finding(s) (CVEs on one package share one fix)")
    else:
        todo = [(r, [m for m in (store.get_finding(i) for i in r.finding_ids) if m])
                for r in items if r.outcome in ("failed", "rejected")]
        audit.emit("supervisor", "decision",
                   (f"Step {step}: re-planning {len(todo)} item(s) with their next alternative; {len(undecided)} "
                    f"undecided item(s) keep their plans" if undecided else
                    f"Round {round_no} started: {len(todo)} item(s) come back with their next alternative "
                    f"(fix rejected or failed validation)"), data={"step": step, "round": round_no})
    by_id = {r.rec_id: r for r in items}  # insertion order = display order before sorting by score
    preps = merge_preps(rc, [prepare(rc, members, rec) for rec, members in todo], scores)
    for prep in preps:
        for rid in prep.absorbed:  # merged into another item: one recommendation per dependency
            by_id.pop(rid, None)
        new = finish(rc, prep, round_no, scores)
        by_id[new.rec_id] = new
    items = list(by_id.values())
    fixes = [r for r in items if r.outcome == "awaiting_decision"]
    none = [r for r in items if r.round == round_no and r.kind == "no_alternative"]
    audit.emit("supervisor", "decision",
               f"Round {round_no}: {len(fixes)} recommendation(s) with a fix, {len(none)} with no alternative")
    if not fixes:
        save_recs(run_dir, round_no, "done", None, items)
        audit.emit("supervisor", "decision", "Nothing waits for a decision -> reporter", data={"step": step})
        return {"round": round_no, "batch_id": None, "route": "report"}
    batch_id = new_id("bt")
    set_pending_batch(run_dir, {"batch_id": batch_id, "round": round_no,
                                "items": [{"plan_id": r.plan_id, "plan_hash": r.plan_hash, "rec_id": r.rec_id}
                                          for r in fixes]})
    save_recs(run_dir, round_no, "awaiting_decisions", batch_id, items)
    audit.emit("human_gate", "gate_wait",
               f"Waiting for decisions on {len(fixes)} fix(es) (batch {batch_id}): validation starts only when every "
               f"one has a decision (guardian decide-batch --run {state['run_id']} --batch {batch_id} ...)",
               data={"batch_id": batch_id, "round": round_no, "step": step, "plan_ids": [r.plan_id for r in fixes]})
    return {"round": round_no, "batch_id": batch_id, "batch_decision": None, "route": "gate"}


def batch_gate_node(state: GraphState) -> dict:
    return {"batch_decision": interrupt({"batch_id": state.get("batch_id"), "round": state.get("round")})}


def record_batch_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    run_dir, audit = rc.tool_ctx.run_dir, rc.audit
    saved = load_recs(run_dir)
    pending = get_pending_batch(run_dir)
    decision = state.get("batch_decision") or {}
    approvals: list[Approval] = []
    partial = False
    try:
        approvals = [Approval.model_validate(a) for a in decision.get("decisions", [])]
        partial = bool(decision.get("partial"))
        reason = check_batch(pending, str(decision.get("batch_id")), approvals, partial=partial)
        for a in approvals if reason is None else []:  # the plan on disk, not just the hash in the pending file
            plan = load_plan(run_dir, a.plan_id)
            reason = check_decision(plan, a) if plan else f"unknown plan {a.plan_id}"
            if reason:
                break
    except ValidationError as exc:
        reason = f"malformed decision: {exc.errors()[0].get('msg')}"
    if reason:
        rule = "G5.2" if "comment" in reason else "G5.1"
        audit.emit("guardrail", "guardrail", f"{rule} batch decision refused: {reason} -> still waiting",
                   data={"rule": rule, "batch_id": state.get("batch_id")})
        return {"batch_decision": None, "route": "gate"}

    by_plan = {a.plan_id: a for a in approvals}
    for r in saved["items"]:
        a = by_plan.get(r.plan_id or "")
        if a is None or r.outcome != "awaiting_decision":
            continue
        plan = load_plan(run_dir, a.plan_id)
        append_approval(run_dir, a)
        audit.record("approval", a.model_dump(mode="json"))
        audit.emit("human_gate", "gate_resume",
                   f"{a.decision.upper()} by {a.decided_by} for plan {a.plan_id}" + (f": {a.comment}" if a.comment else ""),
                   finding_id=r.primary_finding_id, data={"plan_id": a.plan_id, "decision": a.decision,
                                                          "batch_id": pending["batch_id"]})
        r.decision = a.decision  # type: ignore[assignment]
        if a.decision == "approve":
            r.outcome = "validating"
            _set_status(rc, r.finding_ids, FindingStatus.VALIDATING)
        elif a.decision == "accept_risk":
            r.outcome = "accepted"
            _set_status(rc, r.finding_ids, FindingStatus.ACCEPTED)
        else:  # reject: comes back with the next alternative, unless the attempt limit (G5.4) is reached
            r.previous = Previous(plan_id=a.plan_id, outcome="rejected", detail=(a.comment or "").strip()[:300],
                                  reason_type=a.reason_type)
            if plan.attempt >= MAX_ATTEMPTS:
                r.outcome = "needs_person"
                r.reason = "Attempt limit reached (G5.4): a person must look at this"
                _set_status(rc, r.finding_ids, FindingStatus.ESCALATED)
            else:
                r.outcome = "rejected"
                _set_status(rc, r.finding_ids, FindingStatus.PLANNED)
    set_pending_batch(run_dir, None)
    items = saved["items"]
    step = saved["step"] + 1
    approved = [r for r in items if r.outcome == "validating"]
    retry = [r for r in items if r.outcome in ("failed", "rejected")]
    waiting = [r for r in items if r.outcome == "awaiting_decision"]  # undecided (one at a time)
    route = "validate" if approved else "recommend" if (retry or waiting) else "report"
    save_recs(run_dir, saved["round"], "validating" if approved else ("done" if route == "report" else "awaiting_decisions"),
              None, items, step=step)
    n_rej = sum(1 for a in approvals if a.decision == "reject")
    n_acc = sum(1 for a in approvals if a.decision == "accept_risk")
    if partial:
        what = "; ".join(f"{a.decision} of {a.plan_id}" + (f" as '{a.reason_type}'" if a.reason_type else "")
                         for a in approvals[:3]) + (" ..." if len(approvals) > 3 else "")
        msg = (f"Step {step} (one at a time): {len(approvals)} decision(s) - {what}; {len(approved)} to validate; "
               f"{n_rej} re-planned; {len(waiting)} still waiting")
    else:
        msg = (f"Step {step}: batch {pending['batch_id']} decided: {len(approved)} approved, {n_rej} rejected, "
               f"{n_acc} risk accepted -> "
               + {"validate": "validate the approved fixes together", "recommend": "next round with new alternatives",
                  "report": "reporter"}[route])
    audit.emit("supervisor", "decision", msg, data={"step": step, "round": saved["round"], "partial": partial,
                                                    "decisions": len(approvals), "to_validate": len(approved),
                                                    "re_planned": n_rej, "waiting": len(waiting)})
    return {"route": route, "batch_id": None}


def _recorded_approvals(run_dir) -> dict[str, Approval]:
    path = run_dir / "approvals.jsonl"
    out: dict[str, Approval] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                a = Approval.model_validate_json(line)
            except ValueError:
                continue
            if a.decision == "approve":
                out[a.plan_id] = a
    return out


def _detail(res: ValidationResult, alone: bool) -> str:
    text = (f"it introduced new findings: {', '.join(res.new_findings[:3])}" if res.verdict == "regressed"
            else _VERDICT_TEXT.get(res.verdict, res.verdict))
    return text + (" (found by testing it alone)" if alone else "")


def validate_batch_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    run_dir = ctx.run_dir
    saved = load_recs(run_dir)
    round_no = saved["round"]
    items: list[Recommendation] = saved["items"]
    by_plan_approval = {a["plan_id"]: Approval.model_validate(a)
                        for a in (state.get("batch_decision") or {}).get("decisions", [])}
    todo: list[tuple[Recommendation, Item]] = []
    for r in items:
        if r.outcome != "validating" or r.plan_id not in by_plan_approval:
            continue
        members = [m for m in (store.get_finding(i) for i in r.finding_ids) if m]
        members.sort(key=lambda m: m.finding_id != r.primary_finding_id)
        todo.append((r, Item(load_plan(run_dir, r.plan_id), by_plan_approval[r.plan_id], members)))
    # plans verified in earlier rounds are applied underneath, each under its own recorded approval
    recorded = _recorded_approvals(run_dir)
    carried: list[Item] = []
    for r in items:
        if r.outcome == "verified" and r.plan_id and r.plan_id in recorded:
            members = [m for m in (store.get_finding(i) for i in r.finding_ids) if m]
            members.sort(key=lambda m: m.finding_id != r.primary_finding_id)
            carried.append(Item(load_plan(run_dir, r.plan_id), recorded[r.plan_id], members))
    by_rec = {id(it): r for r, it in todo}
    by_rec.update({id(it): next(r for r in items if r.plan_id == it.plan.plan_id) for it in carried})
    carried_ids = {it.plan.plan_id for it in carried}
    n = len(todo)

    def settle(it: Item, res: ValidationResult | None, interaction: bool = False, dropped: bool = False) -> None:
        r = by_rec[id(it)]
        ids = r.finding_ids
        if dropped:  # another approved fix edits the same dependency: back for the next alternative
            r.previous = Previous(plan_id=it.plan.plan_id, outcome="failed",
                                  detail="another approved fix edits the same dependency; only the higher version "
                                         "was validated")
            r.outcome = "needs_person" if it.plan.attempt >= MAX_ATTEMPTS else "failed"
            _set_status(rc, ids, FindingStatus.ESCALATED if r.outcome == "needs_person" else FindingStatus.PLANNED)
            return
        if it.plan.plan_id in carried_ids and (res.combined or res.verdict == "verified"):
            return  # an earlier fix changes outcome only when it fails on its own (isolation culprit)
        if interaction:
            res = res.model_copy(update={"verdict": "interaction"})
        if res.verdict == "verified":
            r.outcome = "verified"
            _set_status(rc, ids, FindingStatus.VERIFIED)
        elif res.verdict == "mitigated":
            r.outcome = "accepted"
            _set_status(rc, ids, FindingStatus.ACCEPTED)
        else:
            r.previous = Previous(plan_id=it.plan.plan_id, outcome="failed",
                                  detail=_detail(res, alone=n > 1 and not res.combined))
            if it.plan.attempt >= MAX_ATTEMPTS:
                r.outcome = "needs_person"
                r.reason = "Attempt limit reached (G5.4): a person must look at this"
                _set_status(rc, ids, FindingStatus.ESCALATED)
            else:
                r.outcome = "failed"
                _set_status(rc, ids, FindingStatus.PLANNED)

    audit.emit("supervisor", "decision", f"Validating {n} approved fix(es) together (round {round_no})")
    validate_plans(rc, [it for _, it in todo], round_no, settle, carried)
    retry = [r for r in items if r.outcome in ("failed", "rejected")]
    waiting = [r for r in items if r.outcome == "awaiting_decision"]
    if retry or waiting:
        save_recs(run_dir, round_no, "awaiting_decisions", None, items)
        audit.emit("supervisor", "decision",
                   f"{len(retry)} fix(es) failed validation or were rejected, {len(waiting)} still undecided -> "
                   f"new alternatives for the former, a new pending batch for all awaiting a decision",
                   data={"step": saved["step"], "round": round_no})
        return {"route": "recommend"}
    save_recs(run_dir, round_no, "done", None, items)
    audit.emit("supervisor", "decision", "Every fix is verified, accepted or needs a person -> reporter (once)")
    return {"route": "report"}
