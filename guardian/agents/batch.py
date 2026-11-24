"""Batch remediation (settings.remediation_mode == "batch"): every finding gets a recommendation, a human decides
on all of them together, and the approved fixes are validated together. Owner: Dev1.

Graph: risk_analyst -> recommend -> batch_gate -> record_batch -> validate_batch -> recommend (next round) | reporter

Round vs step: a round is one full pass in which every open item gets a recommendation; a step is one submitted
set of decisions (the whole batch, or one item at a time), so a round can contain several steps.
Approvals are held until EVERY fix is decided; only then are the approved ones validated together.

* `recommend_node` groups the findings (CVEs on the same package instance share one fix chosen to clear every
  advisory on it; everything else is its own item), builds a hash-bound plan per item from the existing
  `remediation.candidates` / `build_plan`, and writes recommendations.json + pending_batch.json. Items with no
  candidate say "no alternative" and why. In later rounds only the items whose fix was rejected or failed come back,
  with their next untried alternative (max 3 attempts per item, G5.4, then "needs a person").
* `batch_gate_node` contains ONLY `interrupt()` (like human_gate_node: a resume re-runs the node from its start).
* `record_batch_node` re-checks the whole set of decisions in code (every item decided, no extras, G5.1 hash, G5.2
  comment) before recording anything: a partial or mismatched set leaves the batch waiting.
* "Validate now": a resume with {"validate_now": [plan_id...]} makes `record_batch_node` validate the chosen HELD
  approvals right away (together if several); the others keep waiting and a new batch is opened afterwards.
* `validate_batch_node` validates the approved plans together (validator.validate_plans) and sets each item's outcome.
The state of the rounds lives in runs/<id>/recommendations.json, not in the graph state.

Role in the pipeline
  Batch mode replaces the sequential remediation -> human_gate -> record_decision -> validator loop. Planning is
  still done by agents/remediation.py (candidates, build_plan, steering); validation is still done by
  agents/validator.py (validate_plans). This module is the coordinator between them and the human: it decides
  *which* findings share a fix, *when* the human is asked, and *when* validation may start.

Inputs
  Graph state: run_id, batch_id, round, batch_decision (the decisions the human submitted at resume time).
  Files: risk.json (score per finding, for ordering), recommendations.json (the round / step state, see
  core/recs.py), pending_batch.json (what the human is currently asked to decide, with each plan's hash), plans/
  (every plan ever proposed: the memory that stops a fix being offered twice), approvals.jsonl (every recorded
  decision; approvals are held across steps and read back here when validation finally starts).

Outputs
  State keys: round, batch_id, batch_decision and `route` ("gate" | "recommend" | "validate" | "report").
  Files: recommendations.json (rewritten after every step), pending_batch.json (set when a batch opens, cleared when
  decisions are recorded), plans/<plan_id>.json (new plans), approvals.jsonl (one line per decision, via
  append_approval). Validation results are written by the validator. Audit events: decision (supervisor), gate_wait /
  gate_resume (human_gate), guardrail (refused batch), agent_end (a plan was built).

Tools and LLM
  This module calls no tool directly: tool calls happen inside `build_plan` (lookups, dry-run preview) and inside
  `validate_plans` (apply_plan, resolve_lockfiles, rescan_patched, sandbox_validate, local_fix_branch).
  The only model call is remediation.interpret_rejection, reached through `steer_rejection` after a rejection.

Guardrails
  G5.1 every decision carries the hash of the plan the human saw (check_batch / check_decision, re-checked in code
  here: a partial or altered set is refused and the batch keeps waiting). G5.2 a reject or accepted risk needs a
  comment. G5.4 at most MAX_ATTEMPTS plans per item, then the item is "needs a person" and escalated. G3.3 is
  enforced downstream: the validator writes only under an approval that matches the plan, and only approvals read
  from approvals.jsonl count. G3.6 resets the remediation tool budget per group, not per run.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from langgraph.types import interrupt
from pydantic import ValidationError

from guardian.agents.remediation import (
    MAX_ATTEMPTS,
    REASON_TYPES,
    Candidate,
    build_plan,
    candidate_hits,
    candidates,
    dep_keys,
    ops_key,
    steer_rejection,
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
    read_approvals,
    voided_plan_ids,
    save_plan,
    set_pending_batch,
)
from guardian.core.recs import Alternative, Previous, Recommendation, load_recs, save_recs
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.approval import check_batch, check_decision, check_write
from guardian.tools.threat_intel import parse_purl, version_key

AGENT = "remediation"

# Plain-language reason shown to the human when a validated fix comes back (keyed by ValidationResult.verdict).
# "regressed" is not listed: _detail builds that text from the new findings. "interaction" is not a validator verdict:
# settle() assigns it when a fix passes alone but fails in the combined run with earlier verified fixes.
_VERDICT_TEXT = {
    "failed_build": "the build failed",
    "failed_tests": "tests that passed before now fail",
    "timeout": "the sandbox run timed out",
    "still_imported": "the package is still imported by the source",
    "not_resolved": "the finding is still reported after the fix",
    "interaction": "it verifies alone but fails together with the fixes already verified (interaction not resolved)",
}


def _set_status(rc: RunContext, finding_ids: list[str], status: FindingStatus) -> None:
    """Move every finding of a recommendation to `status` in the store (a recommendation may cover several findings).
    Findings that no longer exist are skipped silently. Side effect: store.update_finding per finding."""
    for fid in finding_ids:
        f = rc.store.get_finding(fid)
        if f is not None:
            f.status = status
            rc.store.update_finding(f)


# ---------------------------------------------------------------- grouping + candidates


def group_findings(findings: list[Finding], scores: dict[str, float]) -> list[list[Finding]]:
    """CVEs on the same package instance share one recommendation; every other finding is its own group.
    Members are ordered highest score first, groups too.

    `scores` maps finding_id -> risk score (risk.json); a missing score counts as 0. Grouping by purl means one
    upgrade of that package can clear every advisory on it, instead of one plan per CVE that would fight each other.
    Ties break on title / purl / file / line so the order, and so the ids shown to the human, is stable between runs."""
    def key(f: Finding) -> tuple:
        return -scores.get(f.finding_id, 0), f.title, f.component_purl or "", f.file_path or "", f.line or 0

    by_purl: dict[str, list[Finding]] = {}  # package instance (purl incl. version) -> its group, shared with `groups`
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
    """Package name for messages; falls back to the purl or title when the purl cannot be parsed."""
    try:
        return parse_purl(f.component_purl)[0] if f.component_purl else (f.title or "the package")
    except ValueError:
        return f.component_purl or f.title


def summarise(cand: Candidate) -> Alternative:
    """One-line description of a candidate fix, shown as an alternative the human may be offered later.
    Pure formatting: the alternative is information only (it is not hash-bound until it is built into a plan)."""
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
    """Why Guardian has no fix to offer for this finding (shown instead of a recommendation).
    Picks the most specific honest reason from the category and the finding's data; it never promises a fix. The
    text is shown to the human and stored in the Recommendation, so a person knows what is left for them to do."""
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

    rec: Recommendation | None  # the existing recommendation being re-planned; None in the first round
    members: list[Finding]  # highest score first
    attempt: int  # 1-based number of this attempt for the group (capped by MAX_ATTEMPTS, G5.4)
    primary: Finding  # the member the plan is built for (its first candidate fix)
    cands: list[Candidate]  # untried fixes, best first; the first buildable one becomes the plan
    tried: set = field(default_factory=set)  # ops_key of every plan already proposed for these findings
    tried_noop: set = field(default_factory=set)  # actions of op-less plans already proposed (e.g. mitigate)
    absorbed: list[str] = field(default_factory=list)  # rec_ids merged into this one
    note: str | None = None  # why the human's rejection reason rules every remaining option out
    steer_note: str | None = None  # how the rejection reason was read
    steer_source: str | None = None  # "llm" | "rules"


def _vkey(c: Candidate):
    """Sort key: the candidate's target version (so sorted(..., reverse=True) puts the highest first).
    version_key compares numerically (1.10 > 1.9); a candidate without a target sorts as "0", i.e. last."""
    return version_key(c.target or "0")


def _live_previous(run_dir, rec: Recommendation | None) -> Previous | None:
    """`rec.previous`, unless it points at a rejection the user withdrew (then the item has no rejected history)."""
    prev = rec.previous if rec else None
    if prev is not None and prev.outcome == "rejected" and prev.plan_id in voided_plan_ids(run_dir):
        return None
    return prev


def prepare(rc: RunContext, members: list[Finding], rec: Recommendation | None) -> Prep:
    """Candidates for a group, then steered by why the human rejected the last fix (if they did).

    `rec` is the group's existing recommendation (None in round 1). Steering happens only after a *rejection*: a fix
    that failed validation is simply replaced by the next untried candidate, since there is no human reason to read.
    Side effects: those of `_prepare` and of `steer_rejection` (an LLM call, audit lines when a comment exists)."""
    prep = _prepare(rc, members, rec)
    # after a rejection, the human's reason (and its type) may drop or reorder the remaining candidates
    prev = _live_previous(rc.tool_ctx.run_dir, rec)
    if prev is not None and prev.outcome == "rejected" and prep.cands:
        st = steer_rejection(rc, prep.primary, load_plan(rc.tool_ctx.run_dir, prev.plan_id), prev.detail,
                             prev.reason_type, prep.cands, hits=lambda c: candidate_hits(rc, c))
        prep.cands, prep.note, prep.steer_note, prep.steer_source = st.cands, st.note, st.reading, st.source
    return prep


def _prepare(rc: RunContext, members: list[Finding], rec: Recommendation | None) -> Prep:
    """Untried candidate fixes for a group, with no steering applied yet.

    `members` are the group's findings (highest score first); `rec` the recommendation being re-planned or None.
    `attempt` = highest attempt number among the group's saved plans + 1, so it survives restarts (the plans on disk are
    the memory). Past MAX_ATTEMPTS (G5.4) no candidates are produced and `finish` reports the limit. Side effects:
    the candidate lookups (tool calls) made by `candidates`."""
    ctx = rc.tool_ctx
    if ctx.budget is not None:
        ctx.budget.window(AGENT)  # G3.6: the remediation tool budget applies per group, not per run
    ids = [m.finding_id for m in members]
    voided = voided_plan_ids(ctx.run_dir) - {rec.plan_id if rec else None}  # built on a withdrawn rejection: not memory
    mine = [p for p in list_plans(ctx.run_dir) if p.finding_id in ids and p.plan_id not in voided]
    tried = {ops_key(p.ops) for p in mine if p.ops}  # fixes proposed before are never offered again
    tried_noop = {p.action for p in mine if not p.ops}  # a rejected mitigation is not offered again
    attempt = max((p.attempt for p in mine), default=0) + 1
    prep = Prep(rec, members, attempt, members[0], [], tried, tried_noop)
    if attempt > MAX_ATTEMPTS:
        return prep  # no candidates: finish() turns this into "attempt limit reached"

    def untried(cs: list[Candidate]) -> list[Candidate]:
        # a candidate counts as tried when its ops (or, for an op-less one, its action) were already proposed
        return [c for c in cs if not (ops_key(c.ops) in tried if c.ops else c.action in tried_noop)]

    per_member = [(m, untried(candidates(rc, m))) for m in members]
    # more than one purl in a group only happens after merge_preps joined groups; round-1 groups share one purl
    if len({m.component_purl for m in members}) > 1:
        # a merged group (several packages whose fixes edit one dependency): pool every member's candidates for
        # that dependency, highest version first, versions that still leave an advisory last (a still-affected
        # version must never outrank a clean one)
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
    advisories_at and the child floor). Two plans editing one dependency never reach a combined run.

    Why merge: two findings can lead to the same edit (e.g. two CVEs on different versions of one package that are both
    fixed by the same manifest entry). Applying both plans would let the last edit win and test neither. One merged
    item with the highest clean version fixes all of them and gives the human a single decision.
    Returns the preps with merged ones replaced by one new Prep whose `absorbed` lists the recommendations it
    swallowed (the caller drops those). Side effect: one "decision" audit line per merge."""
    buckets: dict[frozenset, list[Prep]] = {}  # (manifest, dependency) set -> preps whose first choice edits it
    for p in preps:
        if p.cands and p.cands[0].action == "upgrade" and dep_keys(p.cands[0].ops):
            buckets.setdefault(dep_keys(p.cands[0].ops), []).append(p)
    merged_away: set[int] = set()  # id() of every Prep that was folded into a merged one
    out: list[Prep] = []
    for key, group in buckets.items():
        if len(group) < 2:
            continue  # a bucket of one needs no merge
        members = sorted({m.finding_id: m for p in group for m in p.members}.values(),
                         key=lambda m: (-scores.get(m.finding_id, 0), m.title, m.finding_id))
        tried = set().union(*(p.tried for p in group))  # a fix any member already tried is not offered again
        pool = {ops_key(c.ops): c for p in group for c in p.cands if dep_keys(c.ops) == key and ops_key(c.ops) not in tried}
        ordered = sorted(pool.values(), key=_vkey, reverse=True)
        clean = [c for c in ordered if not candidate_hits(rc, c)]  # versions no known advisory still affects
        cands = clean + [c for c in ordered if c not in clean]  # a still-affected version is a last resort only
        best = max(group, key=lambda p: scores.get(p.primary.finding_id, 0))
        # the merged item keeps the recommendation (and id) of the highest-scoring member that already had one
        rec = next((p.rec for p in sorted(group, key=lambda p: -scores.get(p.primary.finding_id, 0)) if p.rec), None)
        new = Prep(rec, members, max(p.attempt for p in group), members[0], cands, tried,
                   set().union(*(p.tried_noop for p in group)),
                   [p.rec.rec_id for p in group if p.rec and (rec is None or p.rec.rec_id != rec.rec_id)])
        src = next((p for p in group if p.steer_source), None)
        if src is not None:
            new.steer_note, new.steer_source = src.steer_note, src.steer_source
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
    """Rationale claim (text, key, value) that a merged fix also resolves finding `g`.
    With a vuln_id the claim is checkable against the scanner evidence (so it can be labelled VERIFIED); without
    one it stays an unchecked INFERRED statement."""
    what = g.vuln_id or g.title[:80]
    return (f"this fix also resolves {what} on {_pkg(g)}", "vuln_id" if g.vuln_id else None, g.vuln_id)


def finish(rc: RunContext, prep: Prep, round_no: int, scores: dict[str, float]) -> Recommendation:
    """The recommendation for a prepared group: its first buildable untried candidate as a plan, else "no alternatives".

    The first candidate that `build_plan` accepts (guardrails G4.5 and tools allowing) becomes the plan; the candidates
    after it are listed as `alternatives` for information only. With no buildable candidate the item becomes a
    "no_alternative" recommendation: first time that is simply stated, on a re-plan it escalates the findings
    (rejected and nothing left, a failed fix with no other safe one, or the G5.4 attempt limit).
    Side effects: save_plan, finding status changes, audit events (agent_end, supervisor decisions)."""
    ctx, audit = rc.tool_ctx, rc.audit
    members, rec, primary, attempt, tried = prep.members, prep.rec, prep.primary, prep.attempt, prep.tried
    ids = [m.finding_id for m in members]
    plan, alternatives = None, []  # alternatives: the candidates after the chosen plan, shown for information
    for cand in prep.cands:
        if plan is not None:
            alternatives.append(summarise(cand))
            continue
        if len(members) > 1:  # the rationale lists every finding this one fix addresses
            cand.claims = [*cand.claims, *(_claim_for(g) for g in members if g.finding_id != primary.finding_id)]
            cand.evidence_ids = list(dict.fromkeys([*cand.evidence_ids, *(e for g in members for e in g.evidence_ids)]))
        built = build_plan(rc, primary, cand, attempt)
        # build_plan resolves SHAs / digests, so the final ops can equal an earlier plan even if the candidate looked new
        if built is not None and ops_key(built.ops) in tried and built.ops:
            continue  # build_plan may normalise to a fix that was already proposed: skip it
        plan = built
    # fields shared by both kinds of recommendation; with no plan, `attempt` stays at the attempts already spent
    base = dict(round=round_no, finding_ids=ids, primary_finding_id=primary.finding_id,
                score=scores.get(primary.finding_id, 0), attempt=attempt - 1 if plan is None else attempt)
    prev = _live_previous(rc.tool_ctx.run_dir, rec)
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
                              previous=prev, outcome="no_alternative", steer_note=prep.steer_note,
                              steer_source=prep.steer_source, **base)
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
                                  if prev else None), previous=prev, outcome="awaiting_decision", steer_note=prep.steer_note,
                          steer_source=prep.steer_source, **base)


# ---------------------------------------------------------------- nodes


def recommend_node(state: GraphState) -> dict:
    """Build (or rebuild) the recommendations and open a pending batch for every fix awaiting a decision.
    Routes to "gate" (wait for the human), "validate" (all decided, approved fixes held) or "report" (nothing left).

    Reads recommendations.json (the saved round / step / items) and risk.json. Round 1 groups every finding; later
    calls re-plan only items whose fix was rejected or failed, keeping undecided and approved items untouched (so a
    partial, one-at-a-time step does not restart the round). Side effects: new plans on disk, recommendations.json,
    pending_batch.json (the hash-bound list the human must decide), finding statuses, supervisor / gate_wait events."""
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    run_dir = ctx.run_dir
    saved = load_recs(run_dir)
    items: list[Recommendation] = saved["items"]
    undecided = [r for r in items if r.outcome == "awaiting_decision"]  # fixes the human has not decided yet
    # a round only ends when nothing is left undecided; a partial (one-at-a-time) step keeps the same round number
    round_no = (saved["round"] or 0) + (0 if undecided else 1)
    step = saved["step"]  # a step = one submitted set of decisions; counts across the whole run
    scores = {fid: a.score for fid, a in load_risks(run_dir).items()}
    # todo: (existing recommendation or None, its findings) to plan now; only failed/rejected items come back
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
    # every group is prepared first, then merged, so two groups editing one dependency become one item before any plan
    # is built (plans are hash-bound and cannot be merged afterwards)
    preps = merge_preps(rc, [prepare(rc, members, rec) for rec, members in todo], scores)
    for prep in preps:
        for rid in prep.absorbed:  # merged into another item: one recommendation per dependency
            by_id.pop(rid, None)
        new = finish(rc, prep, round_no, scores)
        by_id[new.rec_id] = new
    items = list(by_id.values())
    fixes = [r for r in items if r.outcome == "awaiting_decision"]  # these go into the pending batch
    none = [r for r in items if r.round == round_no and r.kind == "no_alternative"]
    audit.emit("supervisor", "decision",
               f"Round {round_no}: {len(fixes)} recommendation(s) with a fix, {len(none)} with no alternative")
    if not fixes:  # nothing left to ask a human about
        held = [r for r in items if r.outcome == "approved"]  # approved fixes waiting for the rest to be decided
        if held:  # the last open items ran out of alternatives: every fix is decided, validate the approved ones
            for r in held:
                r.outcome = "validating"
                _set_status(rc, r.finding_ids, FindingStatus.VALIDATING)
            save_recs(run_dir, round_no, "validating", None, items)
            audit.emit("supervisor", "decision", f"Every fix has a decision -> validate {len(held)} approved fix(es) "
                                                 f"together", data={"step": step})
            return {"round": round_no, "batch_id": None, "route": "validate"}
        save_recs(run_dir, round_no, "done", None, items)
        audit.emit("supervisor", "decision", "Nothing waits for a decision -> reporter", data={"step": step})
        return {"round": round_no, "batch_id": None, "route": "report"}
    # the pending batch lists plan id + hash per fix: record_batch refuses any decision that does not match it (G5.1)
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
    """Pause the run until the human submits decisions (interrupt only: a resume re-runs this node from its start).
    Returns {"batch_decision": <what the caller resumed with>}; `record_batch_node` validates it. No other side
    effect is allowed here, or it would run twice on resume."""
    return {"batch_decision": interrupt({"batch_id": state.get("batch_id"), "round": state.get("round")})}


def record_batch_node(state: GraphState) -> dict:
    """Check the submitted decisions in code, record them, and route: re-plan rejected/failed items, keep waiting
    for undecided ones, validate the held approvals, or finish.

    `batch_decision` = {"batch_id", "decisions": [Approval...], "partial": bool}. The whole set is refused (nothing
    recorded, route "gate") when the batch id, the plan set, a plan hash (G5.1) or a required comment (G5.2) is wrong.
    Accepted decisions are appended to approvals.jsonl one by one. Outcomes per item: approve -> "approved" (held),
    accept_risk -> "accepted", reject -> "rejected" (or "needs_person" at the G5.4 limit). Routing: any rejected /
    failed / undecided item -> "recommend", else any held approval -> "validate", else "report"."""
    rc = get_ctx(state["run_id"])
    run_dir, audit = rc.tool_ctx.run_dir, rc.audit
    saved = load_recs(run_dir)
    pending = get_pending_batch(run_dir)
    decision = state.get("batch_decision") or {}
    if "validate_now" in decision:  # "validate now": test held approvals while the rest keep waiting
        return _validate_now(rc, saved, pending, decision)
    approvals: list[Approval] = []
    partial = False  # True when the human decides one item at a time instead of the whole batch
    try:
        approvals = [Approval.model_validate(a) for a in decision.get("decisions", [])]
        partial = bool(decision.get("partial"))
        # check_batch compares against pending_batch.json (ids, hashes, every item decided unless partial);
        # the loop below then re-checks each decision against the plan file itself
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
        append_approval(run_dir, a)  # recorded now even if validation starts steps later: the approval is the permission
        audit.record("approval", a.model_dump(mode="json"))
        audit.emit("human_gate", "gate_resume",
                   f"{a.decision.upper()} by {a.decided_by} for plan {a.plan_id}" + (f": {a.comment}" if a.comment else ""),
                   finding_id=r.primary_finding_id, data={"plan_id": a.plan_id, "decision": a.decision,
                                                          "batch_id": pending["batch_id"]})
        r.decision = a.decision  # type: ignore[assignment]
        if a.decision == "approve":
            r.outcome = "approved"  # held: validation starts only once no fix is left undecided
            _set_status(rc, r.finding_ids, FindingStatus.AWAITING_HUMAN)
        elif a.decision == "accept_risk":
            r.outcome = "accepted"
            _set_status(rc, r.finding_ids, FindingStatus.ACCEPTED)
        else:  # reject: comes back with the next alternative, unless the attempt limit (G5.4) is reached
            # the reviewer's words travel with the item so the next recommend round can steer by them (<= 300 chars)
            r.previous = Previous(plan_id=a.plan_id, outcome="rejected", detail=(a.comment or "").strip()[:300],
                                  reason_type=a.reason_type)
            if plan.attempt >= MAX_ATTEMPTS:
                r.outcome = "needs_person"
                r.reason = "Attempt limit reached (G5.4): a person must look at this"
                _set_status(rc, r.finding_ids, FindingStatus.ESCALATED)
            else:
                r.outcome = "rejected"
                _set_status(rc, r.finding_ids, FindingStatus.PLANNED)
    set_pending_batch(run_dir, None)  # the batch is consumed; recommend opens a new one if anything is still undecided
    items = saved["items"]
    step = saved["step"] + 1
    retry = [r for r in items if r.outcome in ("failed", "rejected")]  # need a new alternative, then a new decision
    waiting = [r for r in items if r.outcome == "awaiting_decision"]  # undecided (one at a time)
    held = [r for r in items if r.outcome == "approved"]  # approved, not validated yet
    # Validation starts only when EVERY fix has a decision: rejected ones first get (and need) a new decision,
    # undecided ones keep waiting; approvals are held until then and validated together.
    route = "recommend" if (retry or waiting) else "validate" if held else "report"
    approved = held if route == "validate" else []  # only now do held approvals become "validating"
    for r in approved:
        r.outcome = "validating"
        _set_status(rc, r.finding_ids, FindingStatus.VALIDATING)
    save_recs(run_dir, saved["round"], "validating" if approved else ("done" if route == "report" else "awaiting_decisions"),
              None, items, step=step)
    n_rej = sum(1 for a in approvals if a.decision == "reject")
    n_acc = sum(1 for a in approvals if a.decision == "accept_risk")
    if partial:
        what = "; ".join(f"{a.decision} of {a.plan_id}" + (f" as '{a.reason_type}'" if a.reason_type else "")
                         for a in approvals[:3]) + (" ..." if len(approvals) > 3 else "")
        msg = (f"Step {step} (one at a time): {len(approvals)} decision(s) - {what}; {len(held)} approved and held "
               f"until every fix is decided; {n_rej} re-planned; {len(waiting)} still waiting"
               + ("; all decided -> validate the approved fixes together" if approved else ""))
    else:
        msg = (f"Step {step}: batch {pending['batch_id']} decided: {len(approved)} approved, {n_rej} rejected, "
               f"{n_acc} risk accepted -> "
               + {"validate": "validate the approved fixes together", "recommend": "next round with new alternatives",
                  "report": "reporter"}[route])
    audit.emit("supervisor", "decision", msg, data={"step": step, "round": saved["round"], "partial": partial,
                                                    "decisions": len(approvals), "to_validate": len(approved),
                                                    "re_planned": n_rej, "waiting": len(waiting)})
    return {"route": route, "batch_id": None}


def check_validate_now(run_dir, pending: dict | None, batch_id: str, plan_ids: list[str] | None
                       ) -> tuple[int, str] | list[str]:
    """Check a "validate now" request (the held approved fixes to test before every fix is decided).

    Returns the plan ids to validate (all held ones when `plan_ids` is empty/None), or (http_status, reason):
    409 when no batch waits, the batch id is stale or nothing is held; 400 when a plan is not a held, approved fix,
    or its recorded approval is missing / withdrawn / bound to another hash (G5.1, G3.3)."""
    if not pending:
        return 409, "no batch is waiting for decisions"
    if batch_id != pending.get("batch_id"):
        return 409, f"batch {batch_id} is not the pending batch ({pending.get('batch_id')}): reload and try again"
    held = {r.plan_id: r for r in load_recs(run_dir)["items"] if r.outcome == "approved" and r.plan_id}
    if not held:
        return 409, "no approved fix is held: nothing to validate now"
    ids = list(plan_ids or held)
    if len(set(ids)) != len(ids):
        return 400, "a plan is listed twice"
    approvals = _recorded_approvals(run_dir)  # withdrawn approvals are not in here
    for pid in ids:
        r, a = held.get(pid), approvals.get(pid)
        if r is None:
            return 400, f"plan {pid} is not an approved fix waiting to be validated"
        plan = load_plan(run_dir, pid)
        if a is None or plan is None:
            return 400, f"plan {pid} has no recorded approval (G5.1)"
        if check_write(plan, a) or a.plan_hash != r.plan_hash:
            return 400, f"the recorded approval of plan {pid} does not match the plan (G5.1)"
    return ids


def _validate_now(rc: RunContext, saved: dict, pending: dict | None, decision: dict) -> dict:
    """record_batch_node branch for a "validate now" resume: move the chosen held approvals to "validating" and
    route to validate_batch. Everything else (undecided, other held approvals) is untouched; after validation the
    run returns through recommend, which opens a fresh batch (new id) for the items still awaiting a decision."""
    run_dir, audit = rc.tool_ctx.run_dir, rc.audit
    checked = check_validate_now(run_dir, pending, str(decision.get("batch_id")), list(decision.get("validate_now") or []))
    if isinstance(checked, tuple):
        audit.emit("guardrail", "guardrail", f"G5.1 validate-now refused: {checked[1]} -> still waiting",
                   data={"rule": "G5.1", "batch_id": decision.get("batch_id")})
        return {"batch_decision": None, "route": "gate"}
    items, step = saved["items"], saved["step"] + 1
    chosen = [r for r in items if r.plan_id in checked]
    for r in chosen:
        r.outcome = "validating"
        _set_status(rc, r.finding_ids, FindingStatus.VALIDATING)
    set_pending_batch(run_dir, None)  # consumed: recommend opens a new batch for what is still undecided
    save_recs(run_dir, saved["round"], "validating", None, items, step=step)
    who = str(decision.get("requested_by") or "human")
    audit.emit("human_gate", "validate_now", f"VALIDATE NOW requested by {who} for {len(chosen)} approved fix(es): "
               f"{', '.join(checked)} (the other fixes keep waiting)",
               data={"plan_ids": checked, "requested_by": who, "batch_id": decision.get("batch_id"), "step": step})
    audit.emit("supervisor", "decision", f"Step {step}: validate {len(chosen)} approved fix(es) now; "
               f"{sum(1 for r in items if r.outcome == 'awaiting_decision')} still waiting for a decision",
               data={"step": step, "round": saved["round"], "to_validate": len(chosen)})
    return {"route": "validate", "batch_id": None}


def _recorded_approvals(run_dir) -> dict[str, Approval]:
    """plan_id -> its recorded "approve" decision, read from approvals.jsonl (the record on disk).
    Used so validation relies on what was durably recorded (G3.3), not on graph state that a restart could lose.
    Unparseable lines are skipped; a later line for the same plan overrides an earlier one."""
    out: dict[str, Approval] = {}
    for rec in read_approvals(run_dir):  # withdrawn decisions no longer count
        try:
            a = Approval.model_validate(rec)
        except ValueError:
            continue
        if a.decision == "approve":
            out[a.plan_id] = a
    return out


def _detail(res: ValidationResult, alone: bool) -> str:
    """Why a validated fix failed, in words for the human; `alone` marks a failure found by testing it on its own
    (isolation after a failed combined run). A "regressed" verdict names up to three of the new findings."""
    text = (f"it introduced new findings: {', '.join(res.new_findings[:3])}" if res.verdict == "regressed"
            else res.reason if res.verdict == "still_imported" and res.reason
            else _VERDICT_TEXT.get(res.verdict, res.verdict))
    return text + (" (found by testing it alone)" if alone else "")


def validate_batch_node(state: GraphState) -> dict:
    """Validate the approved fixes together (on top of earlier verified ones) and set each item's outcome.
    Failed items go back to "recommend" for their next alternative; otherwise the run goes to the reporter.

    Builds two lists of `Item`s: `todo` (items marked "validating" that have a recorded approval) and `carried` (items
    verified in earlier rounds, applied again underneath so the final set is tested as one). `validate_plans` does the
    sandbox work (apply_plan, resolve_lockfiles, rescan_patched, sandbox_validate, local_fix_branch) and calls
    `settle` for each item. Returns {"route": "recommend" | "report"}. Side effects: recommendations.json,
    finding statuses, validation results and evidence (written by the validator), supervisor audit events."""
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    run_dir = ctx.run_dir
    saved = load_recs(run_dir)
    round_no = saved["round"]
    items: list[Recommendation] = saved["items"]
    # approvals were held across steps: every approval on record counts, not only the last submission's
    by_plan_approval = _recorded_approvals(run_dir)
    todo: list[tuple[Recommendation, Item]] = []  # the fixes under test this round
    for r in items:
        if r.outcome != "validating" or r.plan_id not in by_plan_approval:
            continue
        members = [m for m in (store.get_finding(i) for i in r.finding_ids) if m]
        members.sort(key=lambda m: m.finding_id != r.primary_finding_id)  # False sorts first: primary leads the list
        todo.append((r, Item(load_plan(run_dir, r.plan_id), by_plan_approval[r.plan_id], members)))
    # plans verified in earlier rounds are applied underneath, each under its own recorded approval
    recorded = _recorded_approvals(run_dir)
    carried: list[Item] = []  # earlier verified fixes: applied again as the base, judged only if one fails alone
    for r in items:
        if r.outcome == "verified" and r.plan_id and r.plan_id in recorded:
            members = [m for m in (store.get_finding(i) for i in r.finding_ids) if m]
            members.sort(key=lambda m: m.finding_id != r.primary_finding_id)
            carried.append(Item(load_plan(run_dir, r.plan_id), recorded[r.plan_id], members))
    # Item has no id of its own, so identity (id()) links an Item the validator hands back to its Recommendation
    by_rec = {id(it): r for r, it in todo}  # Item (by identity) -> the Recommendation it belongs to
    by_rec.update({id(it): next(r for r in items if r.plan_id == it.plan.plan_id) for it in carried})
    carried_ids = {it.plan.plan_id for it in carried}
    n = len(todo)

    def settle(it: Item, res: ValidationResult | None, interaction: bool = False, dropped: bool = False) -> None:
        """Callback from validate_plans: record the final outcome of one item (verified / accepted / failed).
        `interaction`: passes alone but breaks the combined run; `dropped`: lost a clash over one dependency.
        A failed item stores a `Previous` (why it failed) so the next round can explain "another alternative"."""
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
            # an earlier verified fix must not be demoted just because a new one broke the combination
            return  # an earlier fix changes outcome only when it fails on its own (isolation culprit)
        if interaction:
            res = res.model_copy(update={"verdict": "interaction"})
        if res.verdict == "verified":
            r.outcome = "verified"
            _set_status(rc, ids, FindingStatus.VERIFIED)
        elif res.verdict == "mitigated":  # a no-op plan: nothing was fixed, the risk is accepted and reported as such
            r.outcome = "accepted"
            _set_status(rc, ids, FindingStatus.ACCEPTED)
        else:
            r.previous = Previous(plan_id=it.plan.plan_id, outcome="failed",
                                  detail=_detail(res, alone=n > 1 and not res.combined and res.verdict != "still_imported"))
            if it.plan.attempt >= MAX_ATTEMPTS:
                r.outcome = "needs_person"
                r.reason = "Attempt limit reached (G5.4): a person must look at this"
                _set_status(rc, ids, FindingStatus.ESCALATED)
            else:
                r.outcome = "failed"
                _set_status(rc, ids, FindingStatus.PLANNED)

    audit.emit("supervisor", "decision", f"Validating {n} approved fix(es) together (round {round_no})",
               data={"plan_ids": [it.plan.plan_id for _, it in todo]})
    validate_plans(rc, [it for _, it in todo], round_no, settle, carried)
    # settle() has now set every item's outcome; failed ones go back for a new alternative, undecided ones are re-asked
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
