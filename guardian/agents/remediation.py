"""Remediation agent (Day-1 form): build one concrete, evidence-backed plan per attempt. Owner: Dev1.

Deterministic on purpose for Day 1: candidates come from the finding's evidence (similar-name evidence for a
typosquat, the workflow line for an action, the resolved lockfile for a missing lockfile) and every target
(replacement name, commit SHA, lockfile) is itself evidence (G4.5). The LLM choice between candidates and the
CVE upgrade path are D1-07 (Day 2). A retry never repeats an earlier plan for the same finding: after a reject
or a failed validation the next candidate is used, and when none is left the finding is escalated (G5.4).

CVE findings get upgrade candidates (D1-07): `safe_version_lookup` (OSV + scanner fixed versions + registry latest)
and `compat_hint` evidence. A direct dependency is moved to a fixed version (lowest first, then later ones on
retry); a transitive one is fixed by upgrading its direct parent. `target_version` must appear in the
safe_version_lookup evidence the plan cites (G4.5, enforced in `build_plan`). When no untried candidate is left
the finding is escalated. `expected_risk_reduction` comes from `scoring.simulate_after`, never from an LLM.

Heuristic findings (typosquat, malicious indicator) only get replace / remove / block / escalate (G5.3).
Base images tagged without a digest (UNTRUSTED_IMAGE, D2-07b) get `pin` (digest from `resolve_image_digest`
evidence) and, only when the finding's evidence lists a newer tag (`newer_tags`), `update_base_image`; the digest,
the new tag and a blocked package name are checked against evidence in `build_plan` (G4.5).
A CVE with no upgrade candidate whose package is never imported (risk factor R = not_imported) gets a no-op
`mitigate` plan: it changes nothing, does not claim a fix, and once approved the finding is recorded as ACCEPTED
(validator verdict "mitigated"); the report lists it as remaining, accepted risk.
The plan, its dry-run diff and its hash are fixed *before* the human gate (C6), so the approval binds to the
exact change that will be applied.

This module serves both modes: `remediation_node` plans one finding at a time (sequential mode), and the batch
code (agents/batch.py) reuses `candidates` / `build_plan` / `steer_rejection` / `candidate_hits` for a whole run.

Where it sits in the pipeline
  Sequential mode: risk_analyst -> remediation_node -> human_gate -> record_decision -> validator -> (next finding |
  replan | reporter). After a reject or a failed validation the graph routes back here with `last_validation` set.
  Batch mode: `recommend_node` (agents/batch.py) calls the helpers below for every finding, then batch_gate ->
  record_batch -> validate_batch. Only the *planning* lives here; applying a plan is the validator's job (G3.3).

Inputs
  Graph state (sequential): run_id, plan_queue (finding ids still to plan), current, attempt (plans already made for
  `current`), last_validation ({"rejected", "plan_id", "reason_type"} after a reject, {"verdict", ...} after a failed
  validation). Run files: plans/<plan_id>.json (earlier plans, so nothing is proposed twice), risk.json (scores for
  `simulate_after` and the reachability tier for a mitigation). The store: findings and the evidence they cite.

Outputs
  State keys returned: plan_queue, current, attempt, plan_id, decision, last_validation and `route` ("gate" to wait
  for the human, "next" when nothing is left to plan). Files: plans/<plan_id>.json and pending_plan.json (the plan the
  human is being asked about, with its hash). Evidence kinds created through tools: osv (safe_version_lookup),
  compat (compat_hint), registry_metadata (resolve_image_digest / resolve_action_sha), plan preview (the dry-run
  diff). Audit events: agent_start / agent_end, decision, gate_wait, guardrail, llm_call, error.

Tools (always through `call_tool`, so each call is allow-listed, audited and stored as evidence)
  safe_version_lookup, compat_hint, resolve_action_sha, resolve_image_digest, plan_preview. Nothing here writes to
  the target repository: `plan_preview` only computes a diff, the patch itself is applied later by the validator.

LLM use
  Only `interpret_rejection` calls the model, and only to read a reviewer's free-text rejection reason and reorder or
  drop the remaining candidates. Everything else (candidates, targets, scores) is deterministic code.

Guardrails in play
  G4.5 every target (version, digest, tag, package name, commit SHA) must appear in tool evidence, so the model can
  never invent one. G5.3 heuristic findings (typosquat etc.) may only be replaced, removed, blocked or escalated.
  G5.4 at most MAX_ATTEMPTS (3) plans per finding, then it is escalated to a person. G5.1 the plan hash is computed
  here, so an approval can bind to exactly this plan. G2.3 / G4.1 / G3.6 protect the optional LLM step: the
  reviewer comment is wrapped as untrusted text, an answer naming unknown candidates is ignored, and an exhausted
  token budget makes the rules read the rejection instead.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from guardian.core.models import (
    Claim,
    ClaimLabel,
    CompatHint,
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    PatchOp,
    RemediationPlan,
    new_id,
)
from guardian.core.plans import list_plans, load_plan, load_risks, save_plan, set_pending
from guardian.core.scoring import simulate_after
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.approval import plan_hash
from guardian.guardrails.grounding import value_matches
from guardian.tools.registry import call_tool
from guardian.tools.threat_intel import parse_purl, version_key

AGENT = "remediation"
MAX_ATTEMPTS = 3  # G5.4: at most 3 plans per finding (per group in batch mode); the next attempt escalates instead
# G5.3: a heuristic detector can be wrong, so such a finding is never "upgraded" or "pinned"; it can only be
# swapped for the popular package, dropped, blocked, or sent to a person
HEURISTIC_ACTIONS = {"replace", "remove", "block", "escalate"}
# categories produced by heuristics (name similarity, indicators) rather than by an advisory database
HEURISTIC = {FindingCategory.TYPOSQUAT, FindingCategory.MALICIOUS_INDICATOR, FindingCategory.DEPENDENCY_CONFUSION}


@dataclass
class Candidate:
    """One possible fix for a finding, before it becomes a hash-bound RemediationPlan (`build_plan` does that).

    Candidates are cheap and deterministic; several exist per finding (e.g. one per fixed version) and the first one
    that survives the guardrails and has not been tried yet becomes the plan. Fields that are None / empty are
    filled in by `build_plan` from tool output (a commit SHA, an image digest, a preview diff)."""

    action: str  # upgrade | replace | remove | block | pin | update_base_image | mitigate
    ops: list[PatchOp]  # the concrete edits; empty for a no-op (mitigate) or while a SHA / digest is still unresolved
    target: str | None  # the version / name / tag the fix moves to (must come from evidence, G4.5)
    claims: list[tuple[str, str | None, str | None]]  # (text, field, value) citing the finding's evidence
    detector: str  # who re-checks the fix after it is applied (the detector that must stop reporting the finding)
    evidence_ids: list[str] = field(default_factory=list)  # evidence the plan will cite besides the finding's own
    sha_lookup: tuple[str, str] | None = None  # (action, ref) resolved just before the plan is fixed
    image: dict | None = None  # {file, image, tag, new_tag?}: digest resolved just before the plan is fixed
    compat: CompatHint | None = None


def ops_key(ops: list[PatchOp]) -> str:
    """Stable identity of a set of patch ops, used to recognise a fix that was already proposed."""
    return json.dumps([o.model_dump(mode="json") for o in ops], sort_keys=True)


def _facts(rc: RunContext, f: Finding) -> tuple[dict, Evidence | None]:
    """Facts dict (and the evidence row) of the first evidence the finding cites that still exists in the store.
    Returns ({}, None) when the finding cites none. Read-only."""
    for eid in f.evidence_ids:
        ev = rc.store.get_evidence(eid)
        if ev is not None:
            return ev.facts, ev
    return {}, None


def _manifest_declares(rc: RunContext, rel: str, name: str) -> bool:
    """True when manifest `rel` (relative to the target repo) lists `name` as a dependency of its own, i.e. the
    manifest can be edited directly. A transitive package is not declared, so its direct parent is upgraded instead."""
    try:
        text = (rc.tool_ctx.repo / rel).read_text(encoding="utf-8")
    except OSError:
        return False
    return re.search(rf'"{re.escape(name)}"\s*:\s*"', text) is not None


def _lookup(rc: RunContext, purl: str, vuln_ids: list[str], fixed: list[str], *, child: str | None = None,
            child_fixed: str | None = None) -> Evidence | None:
    """Run the `safe_version_lookup` tool for `purl` and return its evidence (None when the tool failed).

    The evidence lists candidate versions (OSV + scanner `fixed` versions + registry latest) and, when `child` is
    given, the dependency ranges of each parent version on that child (used to prove a parent upgrade pulls in a
    fixed child). Side effects: one audited tool call, one evidence row. The [:50] caps keep the arguments small."""
    ctx = rc.tool_ctx
    args = {"purl": purl, "vuln_ids": vuln_ids[:50], "scanner_fixed": fixed[:50]}
    if child and child_fixed:
        args |= {"child": child, "child_fixed": child_fixed}
    out = call_tool(AGENT, "safe_version_lookup", None, ctx, rc.store, rc.audit, args=args)
    return out.evidence[0] if out and out.evidence else None


def _compat(rc: RunContext, purl: str, cur: str, to: str) -> Evidence | None:
    """Run the `compat_hint` tool for the move `cur` -> `to` of package `purl`; returns its evidence or None.
    The evidence carries the semver delta, engine / peer-dependency changes and a risk level (a hint, not a proof)."""
    out = call_tool(AGENT, "compat_hint", None, rc.tool_ctx, rc.store, rc.audit,
                    args={"purl": purl, "from_version": cur, "to_version": to})
    return out.evidence[0] if out and out.evidence else None


def _upgrade(rc: RunContext, f: Finding, purl: str, pkg_file: str, why: list, lookup: Evidence, target: str,
             *, via: str | None = None, op: str = "set_dependency_version", spec: str = "^") -> Candidate | None:
    """Build one upgrade Candidate moving package `purl` to `target` in manifest `pkg_file`.

    `why` are the rationale claims already collected, `lookup` is the safe_version_lookup evidence the target comes
    from (cited, so G4.5 can check `target` against it). `via` is the direct parent's name when the vulnerable
    package is transitive (adds an honest "not proven until rescan" claim). `op` / `spec` pick npm
    (`set_dependency_version`, caret range "^x") or pip (`set_requirement_version`, exact "==x" pin).
    Side effect: one compat_hint tool call; the compatibility hint is optional (the plan is built without it)."""
    name, cur, _ = parse_purl(purl)
    compat = _compat(rc, purl, cur or "0.0.0", target)
    claims = list(why)
    claims.append((f"{target} is a candidate version from safe_version_lookup", "candidates", target))
    ev_ids = [lookup.evidence_id]
    hint = None
    if compat is not None:
        ev_ids.append(compat.evidence_id)
        fx = compat.facts
        hint = CompatHint(from_version=fx["from_version"], to_version=fx["to_version"], semver_delta=fx["semver_delta"],
                          engines_ok=fx.get("engines_ok"), peer_dep_changes=fx.get("peer_dep_changes", []),
                          deprecated_target=fx.get("deprecated_target"), level=fx["level"])
        claims.append((f"{name} {cur} -> {target} is a {fx['semver_delta']} version change "
                       f"(compatibility risk {fx['level']})", "semver_delta", fx["semver_delta"]))
    if via:
        claims.append((f"the vulnerable package is transitive; upgrading its direct parent {via} is not proven "
                       f"to pull a fixed version until the sandbox rebuild and rescan", None, None))
    # npm gets a caret range (^1.2.3); a pip pin is the bare version because the op writes "==" itself
    version = f"{spec}{target}" if spec != "==" else target
    return Candidate("upgrade", [PatchOp(op=op, file_path=pkg_file, args={"name": name, "version": version})],
                     target, claims, "scanner re-scan", evidence_ids=ev_ids, compat=hint)


# ---------------------------------------------------------------- steering after a rejection

# The reasons a reviewer can pick when rejecting a fix (id -> label shown in the UI/CLI); they steer the next
# alternative. guardrails/approval.py validates the same ids (it cannot import this module), keep them in step.
REASON_TYPES = {
    "too_big": "The change is too big",
    "too_new": "The package version is too new",
    "breaks_app": "It would break the app",
    "different_approach": "Use a different kind of fix",
    "other": "Other reason",
}
# how the rules read each reason type (shown when no model interpretation is used)
RULE_READING = {
    "too_big": "prefer a smaller change than the rejected one",
    "too_new": "prefer an older version than the rejected one that no advisory still affects",
    "breaks_app": "avoid the same kind of change in the same version line",
    "different_approach": "use a different kind of fix",
}
# how invasive each kind of change is (0 = touches nothing, 5 = package gone and denylisted); "too big" only moves
# down this scale (or to a lower version of the same upgrade). Unknown actions count as 2 (an upgrade).
_SIZE = {"mitigate": 0, "pin": 1, "update_base_image": 2, "upgrade": 2, "replace": 3, "remove": 4, "block": 5}


def _major(v: str | None) -> str | None:
    """Major version number of `v` ("v2.3.1" -> "2"), or None when there is none."""
    m = re.match(r"v?(\d+)", v or "")
    return m.group(1) if m else None


def candidate_hits(rc: RunContext, cand: Candidate) -> list[str]:
    """Advisories a candidate upgrade still leaves: on the package at that version and, through the version's
    dependency ranges, on vulnerable children (advisories_at + child floor). Returns advisory ids / "child id" strings;
    empty means the candidate leaves nothing behind that this scan knows about. Read-only apart from the lookup tool."""
    if cand.action != "upgrade" or not cand.target:
        return []  # only an upgrade can leave other advisories behind
    out: list[str] = []
    for _file, name in dep_keys(cand.ops):
        purl = package_purl(rc, name)
        if not purl:
            continue
        out += advisories_at(rc, name, parse_purl(purl)[2], cand.target)
        out += child_floor_hits(rc, purl, [cand.target]).get(cand.target, [])
    return out


def steer(cands: list[Candidate], rejected: RemediationPlan | None, reason_type: str | None,
          hits=None) -> tuple[list[Candidate], str | None]:
    """Reorder or filter the remaining candidates by why the human rejected the last fix.
    Returns the candidates and, when the reason rules every one out, a plain-language note why.
    `hits(cand)` lists the advisories a candidate still leaves (None: unknown, all treated as clean).
    Rules: too_new -> older clean versions first; too_big -> only smaller changes; breaks_app -> not the same kind
    of change in the same major line; different_approach -> not the same action; other -> unchanged."""
    if rejected is None or reason_type in (None, "", "other"):
        return cands, None  # no reason that can be turned into a rule: keep the original order
    rv = rejected.target_version  # the version the human found too new / too big (None for non-upgrades)
    if reason_type == "too_new":
        def older(c: Candidate) -> bool:  # an upgrade to a version below the rejected one
            return c.action == "upgrade" and bool(c.target and rv) and version_key(c.target) < version_key(rv)

        olds = sorted((c for c in cands if older(c)), key=lambda c: version_key(c.target), reverse=True)
        clean = [c for c in olds if not (hits(c) if hits else [])]
        dirty = [c for c in olds if c not in clean]
        # other kinds of fix, least invasive first; upgrades that are not older are dropped (they are "too new")
        rest = sorted((c for c in cands if not older(c) and not (c.action == "upgrade" and c.target and rv)),
                      key=lambda c: _SIZE.get(c.action, 2))
        out = clean + dirty + rest  # the closest older clean version first, then other kinds of fix
        return out, None if out else "no older version and no other kind of fix is available"
    if reason_type == "too_big":
        size = _SIZE.get(rejected.action, 2)

        def smaller(c: Candidate) -> bool:  # a lower version of the same upgrade, or a less invasive kind of fix
            if c.action == rejected.action == "upgrade" and c.target and rv:
                return version_key(c.target) < version_key(rv)
            return _SIZE.get(c.action, 2) < size

        out = sorted([c for c in cands if smaller(c)],
                     key=lambda c: (_SIZE.get(c.action, 2), version_key(c.target or "0")))
        return out, None if out else "no smaller change than the rejected one is available"
    if reason_type == "breaks_app":
        major = _major(rv) if rejected.action == "upgrade" else None
        out = [c for c in cands if c.action != rejected.action or (major is not None and _major(c.target) != major)]
        return out, None if out else "every remaining option is the same kind of change in the same version line"
    if reason_type == "different_approach":
        out = [c for c in cands if c.action != rejected.action]
        return out, None if out else f"Guardian has no fix other than a{'n' if rejected.action[0] in 'aeiou' else ''} {rejected.action}"
    return cands, None


# ---------------------------------------------------------------- reading the human's reason (optional LLM)

# The model only sees the reviewer's comment (wrapped as untrusted text) and the remaining candidates as C1..Cn, and
# may only reorder or drop them; the answer is checked in `interpret_rejection` and anything off falls back to rules.
# Because the model returns ids and never package names or versions, it cannot invent a fix (G4.1 / G4.5).
_STEER_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "remediation_steer.md"
STEER_AGENT = "remediation_steer"  # name the LLM provider records this call under (cost / replay keys)
# JSON the model must return: "order" = candidate ids best first (an id left out is dropped), "reading" = one sentence
STEER_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["order", "reading"],
                "properties": {"order": {"type": "array", "items": {"type": "string"}},
                               "reading": {"type": "string"}}}


@dataclass
class Steered:
    """Result of reading a rejection: the reordered candidates plus how that was decided (for the audit and the UI)."""

    cands: list[Candidate]
    note: str | None = None  # why nothing is left
    source: str | None = None  # "llm" | "rules" | None (no reason given)
    reading: str | None = None  # one sentence: how the reason was read
    order: list[str] = field(default_factory=list)  # the model's order as "C<n>" ids, for the audit


def _change(c: Candidate) -> str:
    """Short text for a candidate, e.g. "upgrade lodash 4.17.21" (used in prompts and audit lines)."""
    name = next((str(o.args["name"]) for o in c.ops if "name" in o.args), None)
    return f"{c.action} {name or ''} {c.target or ''}".replace("  ", " ").strip()


def interpret_rejection(rc: RunContext, rejected: RemediationPlan, comment: str, reason_type: str | None,
                        cands: list[Candidate], hits=None) -> tuple[list[Candidate], str, list[str]] | None:
    """Ask the model how to read the human's free-text reason and which remaining candidate fits best. It may only
    reorder or drop the given candidates (C1..Cn); anything else, or any failure, returns None (rules take over).

    Returns (candidates in the model's order, one-sentence reading, the ids in that order) or None.
    Side effects: one LLM call (tokens charged to the run budget, G3.6) and audit events for the call, for
    injection-like comment text (G2.3), for an invalid answer (G4.1) and for a corrected ranking (G4.5)."""
    from guardian.guardrails.untrusted import SYSTEM_RULE, wrap
    from guardian.llm.provider import LLMError

    audit, budget = rc.audit, rc.tool_ctx.budget
    # G3.6: a run has a token budget for all LLM calls; once it is spent, the deterministic rules decide
    if budget is not None and budget.tokens_left() <= 0:
        audit.emit("guardrail", "guardrail", "G3.6 LLM token budget exhausted -> rules read the rejection",
                   data={"rule": "G3.6"})
        return None
    ids = {f"C{i + 1}": c for i, c in enumerate(cands)}  # the model sees C1..Cn, never real names to invent
    leaves = {cid: (hits(c) if hits else []) for cid, c in ids.items()}  # advisories each candidate still leaves
    imp = rejected.compatibility_impact
    rejected_view = {"action": rejected.action, "target_version": rejected.target_version,
                     "from_version": imp.from_version if imp else None,
                     "semver_delta": imp.semver_delta if imp else None,
                     "compatibility_risk": imp.level if imp else None}
    cand_view = {cid: {"action": c.action, "target_version": c.target,
                       "semver_delta": c.compat.semver_delta if c.compat else None,
                       "compatibility_risk": c.compat.level if c.compat else None,
                       "still_affected_by": leaves[cid][:5], "change": _change(c),
                       **({"released": d} if (d := _release_date(rc, c)) else {})} for cid, c in ids.items()}
    # the comment is attacker-controllable text: it is fenced as untrusted data and capped at 2000 characters (G2.3)
    block, found = wrap("reviewer_comment", comment[:2000])
    if found:
        audit.emit("guardrail", "guardrail", f"G2.3 injection-like text in the reviewer comment: {found[:3]}",
                   data={"rule": "G2.3", "hits": found[:10]})
    user = ("The reviewer rejected this change:\n" + json.dumps(rejected_view, sort_keys=True, indent=1)
            + f"\n\nReason type the reviewer chose: {reason_type or 'other'}\n\nTheir comment:\n{block}\n\n"
            + "Remaining candidates:\n" + json.dumps(cand_view, sort_keys=True, indent=1))
    system = _STEER_PROMPT.read_text(encoding="utf-8").replace("{untrusted_rule}", SYSTEM_RULE)
    audit.emit("remediation", "llm_call", f"Reading the rejection reason against {len(ids)} candidate(s)",
               data={"model": rc.llm.model, "mode": rc.llm.mode, "reason_type": reason_type})
    try:
        resp = rc.llm.complete_json(STEER_AGENT, system, user, STEER_SCHEMA)
    except LLMError as exc:
        audit.emit("remediation", "error", f"LLM unavailable for the rejection ({type(exc).__name__}: "
                                           f"{str(exc)[:160]}) -> rules")
        return None
    if budget is not None and resp.usage:
        budget.charge_tokens(resp.usage.get("input_tokens", 0) + resp.usage.get("output_tokens", 0))
    try:
        data = json.loads(resp.text)
        order = [str(x) for x in data["order"]]
        reading = str(data.get("reading") or "").strip()[:300]  # shown in the UI / audit, so kept short
    except (ValueError, KeyError, TypeError):
        return None  # not the agreed JSON shape: ignore the model
    if not order or any(i not in ids for i in order):  # it may only reorder / drop the given ids
        audit.emit("guardrail", "guardrail", "G4.1 rejection reading named unknown or no candidates -> ignored",
                   data={"rule": "G4.1", "order": order[:10]})
        return None
    order = list(dict.fromkeys(order))
    # a version that still has an advisory may never outrank a clean one, whatever the model said (stable sort)
    fixed = sorted(order, key=lambda i: bool(leaves[i]))
    if fixed != order:
        audit.emit("guardrail", "guardrail", "A candidate with a remaining advisory was ranked above a clean one: "
                                             "corrected", data={"rule": "G4.5", "order": order, "corrected": fixed})
    return [ids[i] for i in fixed], reading or "(no reading given)", fixed


def steer_rejection(rc: RunContext, f: Finding, rejected: RemediationPlan | None, comment: str | None,
                    reason_type: str | None, cands: list[Candidate], hits=None) -> Steered:
    """Order the remaining candidates after a rejection: the deterministic rules by reason type, then (when a model is
    available and the human wrote a comment) the model's reading of it, validated; any failure keeps the rules.

    `rejected` is the plan the human said no to (None on a first attempt: nothing to steer), `comment` their free
    text, `reason_type` one of REASON_TYPES, `hits(cand)` lists advisories a candidate still leaves. Returns a
    `Steered` with the new order. Side effect: one "decision" audit line saying how the reason was read."""
    rules, note = steer(cands, rejected, reason_type, hits)
    known = reason_type not in (None, "", "other")
    out = Steered(rules, note, "rules" if known else None, RULE_READING.get(reason_type or "") if known else None)
    if rejected is None:
        return out
    # the model is only worth a call when a model exists, the human wrote words, and the rules left something to rank
    if rc.llm is not None and (comment or "").strip() and rules:
        got = interpret_rejection(rc, rejected, comment, reason_type, rules, hits)
        if got is not None:
            out = Steered(got[0], None, "llm", got[1], got[2])
        else:
            rc.audit.emit(AGENT, "decision", "Could not use the model's reading of the rejection -> rules"
                          if known else "Could not use the model's reading of the rejection -> candidates unchanged",
                          finding_id=f.finding_id, data={"reason_type": reason_type, "source": "rules"})
    if out.source is not None:
        label = (reason_type or "other").replace("_", " ")
        nxt = _change(out.cands[0]) if out.cands else f"nothing fits ({out.note or 'no candidate left'})"
        rc.audit.emit(AGENT, "decision", f"Read the rejection '{label}' as: {out.reading} -> next: {nxt}",
                      finding_id=f.finding_id,
                      data={"reason_type": reason_type, "reading": out.reading, "source": out.source,
                            "order": out.order or [_change(c) for c in out.cands]})
    return out


def _release_date(rc: RunContext, c: Candidate) -> str | None:
    """Release date of the candidate's target version from the lookup evidence, if known (a hint for "too new")."""
    for eid in c.evidence_ids:
        e = rc.store.get_evidence(eid)
        d = (e.facts.get("release_dates") or {}).get(c.target) if e is not None else None
        if d:
            return str(d)
    return None


# ---------------------------------------------------------------- other advisories on a candidate version

# One comparator of an advisory range ("<=5.3.3", ">=8.0.0"); in_range ANDs the comma-separated parts.
# A range using anything else (OR, wildcards, "||") is not understood and is treated as "unknown", never as a match.
_CMP = re.compile(r"^\s*(<=|>=|<|>|==|=)?\s*v?(\d[^\s,]*)\s*$")
_OPS = {"<": lambda a, b: a < b, "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
        "=": lambda a, b: a == b, "==": lambda a, b: a == b}


def in_range(version: str, rng: str | None) -> bool | None:
    """True when `version` is inside an advisory's affected range such as `<=5.3.3` or `>=8.0.0,<8.21.0`;
    None when the range is missing or not in that simple comparator form (then nothing is assumed)."""
    if not rng or not version:
        return None
    for part in rng.split(","):
        m = _CMP.match(part)
        if not m:
            return None
        if not _OPS[m.group(1) or "="](version_key(version), version_key(m.group(2))):
            return False
    return True


def lowest_allowed(spec: str | None) -> str | None:
    """The lowest version a dependency range like `^8.1.0` or `>=4.2.2 <5` lets npm pick."""
    m = re.search(r"\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.]+)?", spec or "")
    return m.group(0) if m else None


def advisories_at(rc: RunContext, name: str, eco: str, version: str | None) -> list[str]:
    """Advisories found in this scan that still affect `name` at `version` (any instance of the package).
    `eco` is the purl ecosystem ("npm"/"pypi") so same-named packages of different ecosystems do not mix.
    Returns sorted advisory ids (or finding ids when the finding has no vuln id). Only advisories this scan
    reported are known: a version with an unreported advisory looks clean."""
    if not version:
        return []
    hits = set()
    for g in rc.store.list_findings():
        if g.category is not FindingCategory.CVE or not g.component_purl:
            continue
        try:
            n, _v, e = parse_purl(g.component_purl)
        except ValueError:
            continue
        if n == name and e == eco and in_range(version, g.affected_range):
            hits.add(g.vuln_id or g.finding_id)
    return sorted(hits)


def _clear_first(rc: RunContext, f: Finding, scored: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
    """Candidate versions that clear every known advisory first; versions still affected by another advisory are
    dropped, unless no version clears them all (then they stay, and the plan says what it leaves behind).
    `scored` is [(version, advisories it still leaves)]. Writes one audit "decision" line when versions are skipped,
    so a human can see why the lowest fixing version was not chosen."""
    clean = [(v, hit) for v, hit in scored if not hit]
    dirty = [(v, hit) for v, hit in scored if hit]
    if dirty:
        rc.audit.emit(AGENT, "decision",
                      "Skipping versions still affected by other advisories: "
                      + "; ".join(f"{v} ({', '.join(h[:3])}{'...' if len(h) > 3 else ''})" for v, h in dirty)
                      + ("" if clean else " - no version clears them all, so they stay as a last resort"),
                      finding_id=f.finding_id, data={"skipped": {v: h for v, h in dirty}, "kept_dirty": not clean})
    return clean or dirty


# ops that edit exactly one dependency of a manifest; two plans that edit the same one would overwrite each other,
# so batch mode merges them and the validator drops clashing ones
DEP_OPS = {"set_dependency_version", "set_requirement_version", "replace_dependency", "remove_dependency",
           "block_package"}


def dep_keys(ops: list[PatchOp]) -> frozenset[tuple[str, str]]:
    """(manifest, dependency name) pairs the ops edit: two plans sharing one cannot be applied together."""
    return frozenset((o.file_path, str(o.args["name"])) for o in ops if o.op in DEP_OPS and "name" in o.args)


def package_purl(rc: RunContext, name: str) -> str | None:
    """The purl of package `name` as the scan saw it (a finding on it, or a direct parent in a dependency path)."""
    for g in rc.store.list_findings():
        for purl in [g.component_purl, *(p[1] for p in g.dependency_paths if len(p) > 1)]:
            try:
                if purl and purl.startswith("pkg:npm/") and parse_purl(purl)[0] == name:
                    return purl
            except ValueError:
                continue
    return None


def child_floor_hits(rc: RunContext, parent_purl: str, versions: list[str]) -> dict[str, list[str]]:
    """Advisories still affecting the LOWEST version of a vulnerable child that each candidate version of
    `parent_purl` lets in (express-jwt 6.0.0 allows jsonwebtoken ^8, which other advisories still affect).
    Only children the scan found vulnerable, only versions whose dependency range is known.
    Returns {parent version: ["child advisory", ...]}. Makes one safe_version_lookup call per vulnerable child
    (at most 5, to bound tool use); the "lowest allowed" version is the worst case npm may pick under the range."""
    if not parent_purl.startswith("pkg:npm/"):
        return {}
    eco = parse_purl(parent_purl)[2]
    children: dict[str, list[str]] = {}  # vulnerable child purl -> its fixed versions, for children under this parent
    for g in rc.store.list_findings():
        if g.category is FindingCategory.CVE and g.component_purl:
            for path in g.dependency_paths:
                # a path is [root, direct dependency, ..., package]: parent at index 1, child directly below it
                if len(path) >= 3 and path[1] == parent_purl and path[2] == g.component_purl:
                    children.setdefault(g.component_purl, []).extend(g.fixed_versions)
    out: dict[str, list[str]] = {}
    for cpurl, fixed in list(children.items())[:5]:
        cname = parse_purl(cpurl)[0]
        if not fixed:
            continue
        lk = _lookup(rc, parent_purl, [], [], child=cname, child_fixed=min(fixed, key=version_key))
        ranges = (lk.facts.get("child_ranges") if lk is not None else None) or {}
        for v in versions:
            if ranges.get(v):
                out.setdefault(v, []).extend(f"{cname} {a}" for a in
                                             advisories_at(rc, cname, eco, lowest_allowed(ranges[v])))
    return out


def cve_candidates(rc: RunContext, f: Finding) -> list[Candidate]:
    """Upgrade candidates, safest first. Direct dependency: each fixed version; transitive: the direct parent.
    Versions that other advisories still affect (on the package or on a child it pulls in) come after clean ones.
    Returns Candidates (each cites the safe_version_lookup evidence its target came from); [] when the package is not
    npm / pip, the manifest does not declare it, or no lookup could be made. Side effects: tool calls only."""
    purl = f.component_purl
    if purl and purl.startswith("pkg:pypi/"):
        return pip_candidates(rc, f)
    if not purl or not purl.startswith("pkg:npm/"):
        return []
    name, cur, _ = parse_purl(purl)
    pkg_file = "package.json" if f.project in (None, "root") else f"{f.project}/package.json"
    ids = [i for i in [f.vuln_id, *f.aliases] if i]  # every id the advisory is known by (CVE, GHSA, ...)
    out: list[Candidate] = []
    # direct: the package itself is in the manifest, so the manifest entry is edited; otherwise its parent is
    direct = any(len(p) == 2 for p in f.dependency_paths) or not f.dependency_paths
    if direct and _manifest_declares(rc, pkg_file, name):
        lk = _lookup(rc, purl, ids, f.fixed_versions)
        if lk is not None:
            # checkable against the scanner evidence (vuln_id), so grounding can mark it a verified fact
            why = [(f"{f.vuln_id} affects {name} {cur}; affected range {lk.facts.get('affected_range') or f.affected_range}",
                    "vuln_id", f.vuln_id)]
            eco = parse_purl(purl)[2]
            scored = [(v, advisories_at(rc, name, eco, v)) for v in lk.facts.get("candidates", [])]
            floor = child_floor_hits(rc, purl, [v for v, _ in scored])  # what the version lets in underneath
            scored = [(v, hit + floor.get(v, [])) for v, hit in scored]  # (version, advisories it still leaves)
            for v, still in _clear_first(rc, f, scored):
                extra = [(f"{name} {v} is still affected by {', '.join(still)}", None, None)] if still else []
                c = _upgrade(rc, f, purl, pkg_file, why + extra, lk, v)
                if c:
                    out.append(c)
        return out
    for path in f.dependency_paths:
        if len(path) < 3 or not path[1].startswith("pkg:npm/"):
            continue
        parent = path[1]
        pname, pcur, _ = parse_purl(parent)
        if not _manifest_declares(rc, pkg_file, pname):
            continue
        child_fixed = min(f.fixed_versions, key=version_key) if f.fixed_versions else None
        lk = _lookup(rc, parent, [], [], child=name if child_fixed else None, child_fixed=child_fixed)
        if lk is None:
            continue
        why = [(f"{f.vuln_id} affects {name} {cur}, which is pulled in by {pname} {pcur}", "vuln_id", f.vuln_id)]
        ranges = lk.facts.get("child_ranges") or {}
        # safest first: the smallest parent upgrade whose dependency range provably excludes the vulnerable
        # child; then the parent's registry latest. A failed attempt moves on to the next (G5.4: max 3).
        order = [*lk.facts.get("pulls_fixed_child", []), *lk.facts.get("candidates", [])[-1:]]
        # a parent version is only worth proposing if neither it nor the child it lets in has another known
        # advisory: express-jwt 3.4.0 clears the jsonwebtoken advisory but is itself affected (<=5.3.3)
        eco = parse_purl(parent)[2]
        scored = [(v, advisories_at(rc, pname, eco, v)
                   + [f"{name} {a}" for a in advisories_at(rc, name, eco, lowest_allowed(ranges.get(v)))])
                  for v in dict.fromkeys(order)]
        for v, still in _clear_first(rc, f, scored):
            extra = [(f"{pname} {v} still leaves {', '.join(still)}", None, None)] if still else []
            if v in ranges:
                extra.append((f"{pname} {v} depends on {name} {ranges[v]}, whose lowest allowed version is at or "
                              f"above the fixed {child_fixed}", "child_ranges", ranges[v]))
            c = _upgrade(rc, f, parent, pkg_file, why + extra, lk, v, via=None if v in ranges else pname)
            if c and ops_key(c.ops) not in {ops_key(o.ops) for o in out}:
                out.append(c)
    return out


def _requirement_pins(rc: RunContext, rel: str, name: str) -> str | None:
    """The exact `==` pin of `name` in requirements file `rel`, or None if it is not pinned there."""
    from guardian.adapters.pypi import requirement_pins

    try:
        pins = requirement_pins(confined_path(rc, rel))
    except (OSError, ValueError):
        return None
    norm = re.sub(r"[-_.]+", "-", name).lower()
    return next((v for n, v, _s, _l in pins if re.sub(r"[-_.]+", "-", n).lower() == norm and v), None)


def confined_path(rc: RunContext, rel: str):
    """Resolve `rel` inside the target repo, refusing any path that escapes it (.. or absolute): a finding's
    file_path is data from a scanner, so it is never trusted to stay inside the repo."""
    from guardian.tools.patching import confined

    return confined(rc.tool_ctx.repo, rel)


def pip_candidates(rc: RunContext, f: Finding) -> list[Candidate]:
    """pip: every package in requirements*.txt is pinned directly, so the fix is a new `==` pin in the file the
    scanner located, at a version from safe_version_lookup evidence (G4.5), lowest fixing version first."""
    name, cur, _ = parse_purl(f.component_purl)
    rel = (f.file_path or "").replace("\\", "/")
    if not rel.endswith(".txt") or _requirement_pins(rc, rel, name) is None:
        return []
    ids = [i for i in [f.vuln_id, *f.aliases] if i]
    lk = _lookup(rc, f.component_purl, ids, f.fixed_versions)
    if lk is None:
        return []
    why = [(f"{f.vuln_id} affects {name} {cur}, pinned in {rel}", "vuln_id", f.vuln_id)]
    out = []
    for v in lk.facts.get("candidates", []):
        c = _upgrade(rc, f, f.component_purl, rel, why, lk, v, op="set_requirement_version", spec="==")
        if c:
            out.append(c)
    return out


def _pname(f: Finding) -> str | None:
    """Package name from the finding's purl, or None when it has none or it is not a purl."""
    try:
        return parse_purl(f.component_purl)[0] if f.component_purl else None
    except ValueError:  # e.g. an image reference, not a purl
        return None


def mitigation_candidate(rc: RunContext, f: Finding) -> Candidate | None:
    """No upgrade exists and the package is never imported in production paths: a no-op, explicitly-not-a-fix
    plan a human can accept. Needs the reachability evidence the risk analyst cited for factor R."""
    risk = load_risks(rc.tool_ctx.run_dir).get(f.finding_id)
    if risk is None or risk.factors.R.tier != "not_imported" or not risk.factors.R.evidence_ids:
        return None
    name = parse_purl(f.component_purl)[0] if f.component_purl else "the package"
    return Candidate("mitigate", [], None,
                     [(f"{name} is not imported in production paths (reachability tier not_imported)", "tier",
                       "not_imported"),
                      ("no fixed version could be taken from safe_version_lookup evidence, so nothing is upgraded",
                       None, None),
                      ("the vulnerable package stays installed: this accepts the risk, it does not fix it", None,
                       None)],
                     "scanner re-scan", evidence_ids=list(risk.factors.R.evidence_ids))


def _image_candidates(f: Finding, facts: dict) -> list[Candidate]:
    """Candidates for an UNTRUSTED_IMAGE finding (a base image referenced by tag only): always `pin` (tag -> digest),
    plus `update_base_image` for up to two newer tags the finding's evidence lists. The digest itself is looked up
    later in `build_plan` (resolve_image_digest), so the candidate only carries the file, image and tag."""
    image, raw_tag = facts.get("image"), str(facts.get("tag") or "latest")
    if not image or not f.file_path:
        return []
    tag = "latest" if raw_tag.startswith("latest") else raw_tag  # "latest (implicit)" etc. all mean the latest tag
    why = [(f"{image}:{tag} is referenced by tag only in {f.file_path}", "tag", raw_tag),
           ("a tag can be re-pointed by whoever controls the registry repository, a digest cannot", None, None)]
    out = [Candidate("pin", [], None, why, "detector:image_pin",
                     image={"file": f.file_path, "image": image, "tag": tag})]
    newer = facts.get("newer_tags") or ([facts["newer_tag"]] if facts.get("newer_tag") else [])
    for nt in [str(t) for t in newer][:2]:  # only tags a tool put into the evidence (G4.5)
        out.append(Candidate("update_base_image", [], nt,
                             [*why, (f"{image}:{nt} is a newer tag listed in the finding's evidence", "newer_tags", nt)],
                             "detector:image_pin", image={"file": f.file_path, "image": image, "tag": tag,
                                                          "new_tag": nt}))
    return out


# source files scanned for imports of a package that is being renamed (typosquat replace)
SOURCE_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


def importing_files(repo, manifest_rel: str, name: str, limit: int = 500) -> list[str]:
    """Source files of the manifest's project that import `name` (tests included: they must still compile)."""
    from pathlib import Path

    from guardian.tools.patching import _module_spec

    root = Path(repo)
    project = (root / manifest_rel).parent
    pat = re.compile(_module_spec(name), re.M)
    out = []
    for p in sorted(project.rglob("*")):
        rel = p.relative_to(root)
        if p.suffix not in SOURCE_EXT or not p.is_file() or "node_modules" in rel.parts or "dist" in rel.parts:
            continue
        try:
            if pat.search(p.read_text(encoding="utf-8", errors="replace")):
                out.append(rel.as_posix())
        except OSError:
            continue
        if len(out) >= limit:
            break
    return out


def candidates(rc: RunContext, f: Finding) -> list[Candidate]:
    """All fixes Guardian can offer for finding `f`, best first (the caller skips ones already tried).

    By category: CVE -> upgrade candidates, else a no-op `mitigate` when the package is never imported;
    UNTRUSTED_IMAGE -> pin / update_base_image; TYPOSQUAT and MALICIOUS_INDICATOR -> replace (only when the popular
    package is known and every importing file fits in one plan), remove, block; LOCKFILE -> generate the lockfile;
    UNPINNED_CI -> pin the action to a commit SHA. Heuristic categories are cut to HEURISTIC_ACTIONS (G5.3).
    Returns [] when there is nothing safe to offer (the caller then escalates). Side effects: tool calls for CVEs."""
    facts, _ = _facts(rc, f)
    out: list[Candidate] = []
    if f.category is FindingCategory.CVE:
        out = cve_candidates(rc, f)
        if not out and (m := mitigation_candidate(rc, f)):
            out.append(m)
        return out
    if f.category is FindingCategory.UNTRUSTED_IMAGE:
        return _image_candidates(f, facts)
    pname = facts.get("name") or (_pname(f))
    if f.category in (FindingCategory.TYPOSQUAT, FindingCategory.MALICIOUS_INDICATOR) and pname and f.file_path:
        name, popular = pname, facts.get("similar_to")
        why = (f"'{name}' differs from the popular package '{popular}' by {facts.get('distance')} edit(s)",
               "similar_to", popular) if f.category is FindingCategory.TYPOSQUAT else (
            f"'{name}' was flagged by {f.detector}: {f.title[:100]}", None, None)
        renames: list[str] = []
        if popular and not facts.get("legacy_manifest"):
            renames = importing_files(rc.tool_ctx.repo, f.file_path, name)
        from guardian.tools.patching import MAX_PLAN_OPS

        # replace = rename the dependency AND every import of it; a legacy manifest cannot be edited safely
        if popular and not facts.get("legacy_manifest") and len(renames) < MAX_PLAN_OPS:
            # never a partial rename: more importing files than one plan may hold -> no replace candidate
            out.append(Candidate("replace", [PatchOp(op="replace_dependency", file_path=f.file_path,
                                                     args={"name": name, "new_name": popular}),
                                             *(PatchOp(op="rename_import", file_path=r,
                                                       args={"name": name, "new_name": popular}) for r in renames)],
                                 popular, [why, (f"declared in {f.file_path} as {facts.get('range')}", "range",
                                                 facts.get("range")),
                                           (f"version range {facts.get('range')} is kept; API compatibility of "
                                            f"'{popular}' is not verified until the sandbox build (Day 2)", None,
                                            None)],
                                 "detector:typosquat"))
        out.append(Candidate("remove", [PatchOp(op="remove_dependency", file_path=f.file_path, args={"name": name})],
                             None, [why, ("removing it drops the suspicious package from the manifest; code that "
                                          "imports it would break", None, None)], "detector:typosquat"))
        out.append(Candidate("block", [PatchOp(op="block_package", file_path=f.file_path, args={"name": name})],
                             None, [why, ("the name is removed from the manifest and added to "
                                          ".guardian/denylist.txt so it is not reinstalled", None, None)],
                             "detector:typosquat"))
    elif f.category is FindingCategory.LOCKFILE:
        # the lockfile content comes from discovery's resolved locks at validation time, so the op only names the
        # projects (root plus any sub-project without a lock) and the file that disabled lockfile generation
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
    """Turn a candidate's (text, field, value) claims into the plan's rationale (G4.4 grounding).

    A claim is VERIFIED only when its value is found in the cited evidence under that field (`value_matches`);
    otherwise it is INFERRED, so the human can see which statements were checked and which are the agent's reasoning.
    `extra` are the additional evidence ids (lookup, preview, SHA / digest) the plan cites besides the finding's own."""
    cited = [e for e in (rc.store.get_evidence(i) for i in [*f.evidence_ids, *extra]) if e]
    out = []
    for text, fld, value in cand.claims:
        label = ClaimLabel.VERIFIED if value is not None and value_matches(cited, fld, str(value)) else ClaimLabel.INFERRED
        out.append(Claim(text=text, field=fld, value=None if value is None else str(value),
                         evidence_ids=[e.evidence_id for e in cited], label=label))
    return out


def ungrounded_target(rc: RunContext, f: Finding, ops: list[PatchOp], evidence_ids: list[str]) -> str | None:
    """G4.5 for image and block ops: why a digest, tag or package name is not backed by tool evidence, else None.

    A digest must match a registry_metadata evidence from resolve_image_digest (not a plain `git ls-remote`), a new
    tag must be listed in the finding's own evidence, and a package to block must be the one the finding is about.
    `evidence_ids` are the extra evidence the plan cites. Read-only; the caller turns a reason into a guardrail event."""
    cited = [e for e in (rc.store.get_evidence(i) for i in dict.fromkeys([*f.evidence_ids, *evidence_ids])) if e]
    own = [e for e in (rc.store.get_evidence(i) for i in f.evidence_ids) if e]
    for o in ops:
        a = o.args
        if o.op in ("pin_image_digest", "update_base_image"):
            want_tag = a.get("new_tag") or a.get("tag")
            if not any(e.kind == "registry_metadata" and e.source_tool != "git ls-remote"
                       and e.facts.get("digest") == a.get("digest") and e.facts.get("image") == a.get("image")
                       and e.facts.get("tag") == want_tag for e in cited):
                return f"digest {a.get('digest')} for {a.get('image')}:{want_tag} is not in resolve_image_digest evidence"
            if o.op == "update_base_image":
                newer = {str(t) for e in own for t in [*(e.facts.get("newer_tags") or []), e.facts.get("newer_tag")] if t}
                if a.get("new_tag") not in newer:
                    return f"new tag {a.get('new_tag')} is not listed in the finding's evidence"
        elif o.op == "block_package":
            names = {e.facts.get("name") for e in own} | {_pname(f)}
            if a.get("name") not in names:
                return f"package {a.get('name')} to block is not the one in the finding's evidence"
    return None


def _files_phrase(files: list[str]) -> str:
    """'a and b', or 'frontend/package.json and 35 source files' for a long list (the diff lists them all)."""
    if len(files) <= 3:
        return ", ".join(files)
    manifests = [f for f in files if f.endswith(("package.json", "requirements.txt", "Dockerfile", ".yml", ".yaml"))]
    rest = len(files) - len(manifests)
    return (", ".join(manifests) + (" and " if manifests else "")) + f"{rest} source files (listed in the diff)"


def build_plan(rc: RunContext, f: Finding, cand: Candidate, attempt: int) -> RemediationPlan | None:
    """Turn a Candidate into a complete, hash-bound RemediationPlan, or None when a guardrail or tool refuses.

    Steps: (1) G4.5 check that an upgrade target is in safe_version_lookup evidence; (2) resolve a commit SHA or an
    image digest through tools and add them to the ops; (3) `ungrounded_target` G4.5 check on digests / tags / names;
    (4) `plan_preview` dry-run so the diff exists *before* the human decides; (5) expected risk reduction from
    `simulate_after` (code, never an LLM); (6) rationale claims, rollback text, and finally `plan_hash` (G5.1/C6).
    `attempt` is the 1-based number of this try for the finding. Returns None (with a guardrail audit event or a
    failed tool call) when the plan cannot be grounded; the caller then tries the next candidate.
    Side effects: tool calls (evidence rows), audit events; the plan is NOT saved here."""
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    extra: list[str] = list(cand.evidence_ids)
    if cand.action == "upgrade":  # G4.5: the target version must come from safe_version_lookup evidence
        allowed = {v for i in cand.evidence_ids if (e := store.get_evidence(i)) and e.kind == "osv"
                   for v in e.facts.get("candidates", [])}
        if cand.target not in allowed:
            audit.emit("guardrail", "guardrail", f"G4.5 blocked upgrade target {cand.target}: not in "
                       f"safe_version_lookup evidence", finding_id=f.finding_id, data={"rule": "G4.5"})
            return None
    ops = list(cand.ops)
    target = cand.target
    # a mutable CI ref (v3, main) is resolved to the commit it points at *now*, and that commit becomes the pin
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
    # a base image tag is resolved to its immutable digest; with `new_tag` the Dockerfile also moves to that tag
    if cand.image:
        img = cand.image
        new_tag = img.get("new_tag")
        out = call_tool(AGENT, "resolve_image_digest", None, ctx, store, audit,
                        args={"image": img["image"], "tag": new_tag or img["tag"]})
        if out is None:
            return None
        digest = out.artifacts["image_digest"]
        extra.append(out.evidence[0].evidence_id)
        a = {"image": img["image"], "tag": img["tag"], "digest": digest}
        if new_tag:
            ops = [PatchOp(op="update_base_image", file_path=img["file"], args={**a, "new_tag": new_tag})]
            target = f"{new_tag}@{digest}"
        else:
            ops = [PatchOp(op="pin_image_digest", file_path=img["file"], args=a)]
            target = digest
        cand.claims.append((f"{img['image']}:{new_tag or img['tag']} currently resolves to {digest}", "digest", digest))
    why = ungrounded_target(rc, f, ops, extra)
    if why:
        audit.emit("guardrail", "guardrail", f"G4.5 blocked {cand.action}: {why}",
                   finding_id=f.finding_id, data={"rule": "G4.5"})
        return None
    plan_id = new_id("pl")
    # the dry-run diff is computed now, so the approval binds to the exact change that would be applied (C6)
    if ops:
        preview = call_tool(AGENT, "plan_preview", None, ctx, store, audit,
                            args={"plan_id": plan_id, "ops": [o.model_dump(mode="json") for o in ops]})
        if preview is None:
            return None
        extra.append(preview.evidence[0].evidence_id)
    files = sorted({o.file_path for o in ops})  # files the plan touches, named in the rollback text
    before = load_risks(rc.tool_ctx.run_dir).get(f.finding_id)
    after_score, after_band = simulate_after(before, cand.action)
    reduction = (f"score {before.score} ({before.band.value}) -> {after_score} ({after_band.value}) once the "
                 f"patched copy re-scans clean (simulate_after, section 7)" if before else
                 f"{f.initial_risk.value if f.initial_risk else 'unknown'} -> resolved if {cand.detector} no longer "
                 f"reports it on the patched copy")
    plan = RemediationPlan(
        plan_id=plan_id, plan_hash="", finding_id=f.finding_id, attempt=attempt, action=cand.action, ops=ops,
        target_version=target, rationale=_claims(rc, f, cand, extra),
        expected_risk_reduction=reduction, compatibility_impact=cand.compat,
        rollback=(f"Nothing is applied to the target: the patch lands in a fresh copy under runs/<run>/attempts/. "
                  f"Discard that folder to roll back; after adoption, revert the diff of {_files_phrase(files)}."
                  if files else "Nothing is changed by this plan. Re-open the finding to withdraw the acceptance."),
        evidence_ids=[*f.evidence_ids, *extra],
    )
    plan.plan_hash = plan_hash(plan)  # hash over the finished plan; any later change invalidates the approval (G5.1)
    return plan


def remediation_node(state: GraphState) -> dict:
    """Sequential mode: plan the next untried fix for the current finding (or take the next from the queue) and send
    it to the human gate; when nothing is left (or G5.4's attempt limit is hit) escalate the finding instead.

    Reads state: plan_queue, current, attempt, last_validation. Returns the next state: {"route": "gate", plan_id, ...}
    when a plan is waiting for a human, {"route": "next"} when the queue is empty or the finding was escalated.
    Side effects: saves plans/<plan_id>.json and pending_plan.json, moves the finding to AWAITING_HUMAN (or ESCALATED),
    and emits agent_start / agent_end / decision / gate_wait audit events."""
    rc = get_ctx(state["run_id"])
    store, audit = rc.store, rc.audit
    queue = list(state.get("plan_queue") or [])
    current, attempt = state.get("current"), state.get("attempt") or 0  # attempt: plans already made for `current`
    if current is None:
        if not queue:
            return {"route": "next", "plan_id": None}
        current, attempt = queue.pop(0), 0
    f = store.get_finding(current)
    attempt += 1
    audit.emit(AGENT, "agent_start", f"Planning attempt {attempt} for: {f.title[:90]}", finding_id=f.finding_id,
               evidence_ids=f.evidence_ids,
               data={"last_validation": state.get("last_validation")} if state.get("last_validation") else {})

    # plans on disk are the memory of earlier attempts: they keep a retry from repeating a rejected / failed fix
    mine = [p for p in list_plans(rc.tool_ctx.run_dir) if p.finding_id == f.finding_id]
    tried = {ops_key(p.ops) for p in mine}  # fixes already proposed for this finding: never proposed twice
    tried_noop = {p.action for p in mine if not p.ops}  # a rejected mitigation is not offered again
    plan = None
    if attempt <= MAX_ATTEMPTS:  # G5.4: past the limit no plan is built and the finding goes to a person
        cands = candidates(rc, f)
        lv = state.get("last_validation") or {}
        if lv.get("rejected") is not None and lv.get("plan_id"):  # a rejection: steer by why the human said no
            st = steer_rejection(rc, f, load_plan(rc.tool_ctx.run_dir, lv["plan_id"]), lv.get("rejected"),
                                 lv.get("reason_type"), cands, hits=lambda c: candidate_hits(rc, c))
            cands = st.cands
            if st.note:
                audit.emit(AGENT, "decision", f"Rejection reason leaves no option: {st.note}", finding_id=f.finding_id)
        for cand in cands:
            if cand.ops and ops_key(cand.ops) in tried:
                continue
            if not cand.ops and cand.action in tried_noop:
                continue
            plan = build_plan(rc, f, cand, attempt)
            if plan is not None and ops_key(plan.ops) in tried:  # resolved to an op we already tried
                plan = None
                continue
            if plan is not None:
                break
    if plan is None:  # out of candidates, or every remaining one was refused by a guardrail or a tool
        f.status = FindingStatus.ESCALATED
        store.update_finding(f)
        why = "attempt limit reached (G5.4)" if attempt > MAX_ATTEMPTS else "no untried safe plan left"
        audit.emit("supervisor", "decision", f"Escalated for security review: {f.title[:80]} ({why})",
                   finding_id=f.finding_id)
        return {"plan_queue": queue, "current": None, "attempt": 0, "plan_id": None, "route": "next",
                "last_validation": None}

    # the plan is written once and never edited; pending_plan.json tells the gate / CLI which plan (and hash) to expect
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
    # decision is cleared so a stale answer from an earlier plan can never be read as this plan's approval
    return {"plan_queue": queue, "current": current, "attempt": attempt, "plan_id": plan.plan_id,
            "decision": None, "route": "gate"}
