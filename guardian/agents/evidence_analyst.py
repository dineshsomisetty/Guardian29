"""Evidence analyst agent (LLM): per finding, explanation + initial risk, every claim grounded. Owner: Dev1.

Role: third node. For each Finding it writes a short explanation, an initial risk (critical/high/medium/low) and
a list of Claims. This is the first LLM agent; the LLM proposes, code disposes (section 4 guardrails).

Flow per batch of findings:
  build prompt (untrusted content in <data> blocks, G2) -> LLM structured JSON -> parse (G4.1, 1 repair retry)
  -> ground each claim against evidence facts (G4.2-G4.4, G4.6) -> update Finding.

Inputs:  state `run_id`, `finding_ids`; the Findings and their Evidence from the store; the system prompt in
         guardian/prompts/evidence_analyst.md (with the untrusted-data rule appended).
Outputs: the same Findings updated in place (`store.update_finding`): `initial_risk`, `initial_risk_source`
         ("llm" or "rule"), `explanation`, `claims`, `status` (ASSESSED, or ESCALATED when the LLM output stayed
         invalid). No new evidence is created and no file other than findings.json changes. State: `status`.
Audit:   `agent_start`/`agent_end`, a supervisor `decision` when the LLM budget excludes findings, `llm_call` and
         `llm_result` per batch/finding, and `guardrail` events (G2.3 injection-like text, G3.6 token budget,
         G4.x grounding / schema issues).
Grounding: claim labels are assigned by code in guardrails/grounding.py, never by the LLM. A claim is VERIFIED only
         when it cites real evidence ids and its field/value matches a fact in that evidence; otherwise it is
         INFERRED, or rejected when it cites an unknown id (an alias that does not map back is still rejected).
         Finding/evidence text is attacker-controlled, so it only ever appears inside <data> blocks.
Failure: findings beyond GUARDIAN_MAX_LLM_FINDINGS, or when the LLM is unavailable, get the rule-based initial risk
(labelled initial_risk_source="rule"), so the pipeline always completes.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from guardian.core.models import Evidence, Finding, FindingCategory, FindingStatus, Priority
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.grounding import (
    RawAssessment,
    SchemaError,
    batch_json_schema,
    ground_assessment,
    parse_batch,
)
from guardian.guardrails.untrusted import SYSTEM_RULE, wrap
from guardian.llm.provider import LLMError
from guardian.tools.registry import INITIAL_RISK_RULE, ToolUnavailable, resolve

# Name used in audit events and as the key for per-agent tool/LLM budgets.
AGENT = "evidence_analyst"
# Findings per LLM call: small enough for the model to give each one attention and to keep the
# JSON output bounded, large enough to amortise the system prompt.
BATCH_SIZE = 8
# Batches analysed in parallel threads (LLM calls are I/O bound).
WORKERS = 4
# Sort rank of a risk band (0 = most urgent); None (no risk yet) sorts last.
_RANK = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3, None: 4}
# System prompt template; contains an {untrusted_rule} placeholder filled in by system_prompt().
_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "evidence_analyst.md"

# Default initial risk of non-CVE categories when no scoring rule is available: these have no
# CVSS, so the category itself carries the severity.
_CATEGORY_DEFAULT = {
    FindingCategory.TYPOSQUAT: Priority.HIGH,
    FindingCategory.MALICIOUS_INDICATOR: Priority.CRITICAL,
    FindingCategory.DEPENDENCY_CONFUSION: Priority.HIGH,
    FindingCategory.INTEGRITY_CHANGE: Priority.HIGH,
}


def fallback_rule(f: Finding) -> Priority:
    """Built-in initial-risk rule, used only if the shared scoring rule is not registered.

    Maps CVSS to a band (>=9 critical, >=7 high, >=4 medium, else low); with no CVSS falls back to the advisory
    severity text for CVEs, then to a per-category default (medium for anything unlisted).
    Args: f - the finding. Returns: a Priority.
    """
    if f.cvss is not None:
        if f.cvss >= 9:
            return Priority.CRITICAL
        if f.cvss >= 7:
            return Priority.HIGH
        if f.cvss >= 4:
            return Priority.MEDIUM
        return Priority.LOW
    if f.category is FindingCategory.CVE and f.severity:
        sev = f.severity.lower()
        return {"critical": Priority.CRITICAL, "high": Priority.HIGH, "medium": Priority.MEDIUM}.get(sev, Priority.LOW)
    return _CATEGORY_DEFAULT.get(f.category, Priority.MEDIUM)


def rule_risk(f: Finding) -> Priority:
    """Rule-based initial risk of a finding (no LLM): the registered scoring rule, else `fallback_rule`.

    Used for findings that do not reach the LLM, for LLM failures, and to rank findings for the LLM budget.
    Any error in the registered rule also degrades to `fallback_rule`, so this never raises.
    """
    try:
        return Priority(resolve(INITIAL_RISK_RULE)(f))
    except (ToolUnavailable, Exception):  # noqa: BLE001
        return fallback_rule(f)


def system_prompt() -> str:
    """Load the evidence-analyst system prompt and insert the standing "data is untrusted" rule (G2)."""
    return _PROMPT.read_text(encoding="utf-8").replace("{untrusted_rule}", SYSTEM_RULE)


def _finding_view(f: Finding) -> dict:
    """The finding fields the LLM may see, as a JSON-safe dict (no claims, no internal status).

    An allowlist (`include`) is used so new Finding fields do not leak into prompts by accident, and the prompt
    stays stable across runs, which record/replay depends on.
    """
    return f.model_dump(
        mode="json",
        include={"finding_id", "category", "title", "detector", "component_purl", "scope", "project", "file_path",
                 "line", "dependency_paths", "vuln_id", "aliases", "cvss", "severity", "fixed_versions",
                 "affected_range"},
    )


# Fact keys that record where data was fetched from (not what it says).
_FETCH_KEYS = ("source", "scripts_source")


def _prompt_facts(facts: dict) -> dict:
    """Facts as the LLM sees them. Where a fact was fetched from ("cache" vs "registry.npmjs.org") stays in the
    Evidence for the audit trail, but is left out of the prompt: it is the only thing that differs between a
    live run and its offline replay, and it would make replay miss its cache (G7.3)."""
    def fetch_note(v) -> bool:
        return isinstance(v, str) and (v == "cache" or v.startswith(("registry.", "api.", "github.com"))
                                       or v.endswith((".org", ".com", ".io", ".dev", ".gov")))
    return {k: v for k, v in facts.items() if not (k in _FETCH_KEYS and fetch_note(v))}


def _evidence_view(ev: Evidence) -> dict:
    """One Evidence record as the LLM sees it: id, kind, tool, location, facts (JSON text), excerpt.

    Facts are serialised with sorted keys for a stable prompt and truncated to 3000 chars; the source excerpt is cut
    to 600 chars. Both limits bound prompt size (and cost) per evidence record.
    """
    facts = json.dumps(_prompt_facts(ev.facts), default=str, sort_keys=True)
    # Cap per-evidence prompt size; the full record stays in the store.
    if len(facts) > 3000:
        facts = facts[:3000] + "...(truncated)"
    return {"evidence_id": ev.evidence_id, "kind": ev.kind, "source_tool": ev.source_tool,
            "file_path": ev.file_path, "line": ev.line, "facts": facts,
            "excerpt": (ev.excerpt or "")[:600] or None}


class Aliases:
    """Stable short ids (F1.., E1..) in place of per-run ULIDs.

    The prompt must be identical across runs of the same target so LLM record/replay (section 5.3) can serve a
    fresh run offline; it also saves tokens. Aliases are mapped back to real ids before grounding, so an
    unknown alias is still rejected by G4.2.
    """

    def __init__(self) -> None:
        """Start empty. `to_alias` maps real id -> alias, `to_real` maps alias -> real id."""
        self.to_alias: dict[str, str] = {}
        self.to_real: dict[str, str] = {}

    def of(self, real: str, prefix: str) -> str:
        """Return the alias for a real id, creating the next one for that prefix ("F" findings, "E" evidence)."""
        if real not in self.to_alias:
            alias = f"{prefix}{sum(1 for a in self.to_real if a.startswith(prefix)) + 1}"
            self.to_alias[real], self.to_real[alias] = alias, real
        return self.to_alias[real]

    def real(self, alias: str) -> str:
        """Map an alias back to the real id; an unknown alias is returned unchanged so grounding rejects it."""
        return self.to_real.get(alias, alias)


def build_user_prompt(findings: list[Finding], rc: RunContext, aliases: Aliases | None = None) -> tuple[str, list[str]]:
    """Build the user message for one batch of findings.

    Each finding and its evidence is rendered as JSON inside an untrusted-data block (`wrap`), with ids replaced by
    aliases (F1.., E1..) so the prompt is identical between runs.
    Args: findings - the batch; rc - run context (for the evidence store); aliases - alias table to reuse, or None.
    Returns: (prompt text, list of injection-like phrases found in the data, reported as G2.3).
    """
    aliases = aliases or Aliases()
    blocks, hits = [], []
    for f in findings:
        fa = aliases.of(f.finding_id, "F")
        evs = [rc.store.get_evidence(e) for e in f.evidence_ids]
        fview = {**_finding_view(f), "finding_id": fa}
        eviews = [{**_evidence_view(e), "evidence_id": aliases.of(e.evidence_id, "E")} for e in evs if e]
        block, h = wrap(f"finding {fa}", {"finding": fview, "evidence": eviews})
        blocks.append(block)
        hits.extend(h)
    ids = ", ".join(aliases.of(f.finding_id, "F") for f in findings)
    text = (f"Assess these {len(findings)} findings (ids: {ids}). Return one assessment per finding.\n\n"
            + "\n\n".join(blocks))
    return text, hits


def _unalias(assessments: list[RawAssessment], aliases: Aliases) -> list[RawAssessment]:
    """Rewrite the LLM's finding/evidence aliases back to real ids, in place, before grounding.

    Ids that are not known aliases stay as they are and are later rejected by the grounding checks (G4.2).
    """
    for a in assessments:
        a.finding_id = aliases.real(a.finding_id)
        for c in a.claims:
            c.evidence_ids = [aliases.real(e) for e in c.evidence_ids]
    return assessments


def _call_with_repair(rc: RunContext, system: str, user: str) -> tuple[list[RawAssessment] | None, str | None]:
    """Call the LLM for a batch and parse its JSON, with one repair retry (G4.1).

    Charges the tokens used against the run's LLM budget. On a schema error the validation message is fed back to
    the model once; a second failure gives up.
    Returns: (assessments, None) on success, or (None, last error text) after two invalid answers.
    Raises: LLMError if the provider is unavailable (handled by the caller).
    """
    schema = batch_json_schema()
    prompt = user
    last_err = None
    for attempt in (1, 2):  # G4.1: one repair retry
        resp = rc.llm.complete_json(AGENT, system, prompt, schema)
        budget = rc.tool_ctx.budget
        if budget is not None and resp.usage:
            budget.charge_tokens(resp.usage.get("input_tokens", 0) + resp.usage.get("output_tokens", 0))
        try:
            return parse_batch(resp.text).assessments, None
        except SchemaError as exc:
            last_err = str(exc)
            rc.audit.emit("guardrail", "guardrail", f"G4.1 schema validation failed (attempt {attempt})",
                          data={"rule": "G4.1", "error": last_err[:300]})
            prompt = (user + "\n\nYour previous output failed schema validation:\n" + last_err[:800]
                      + "\nReturn only valid JSON matching the schema.")
    return None, last_err


def _apply_rule(f: Finding) -> Finding:
    """Give a finding the rule-based initial risk and label it as such (initial_risk_source="rule")."""
    f.initial_risk = rule_risk(f)
    f.initial_risk_source = "rule"
    return f


def analyse_batch(rc: RunContext, findings: list[Finding], system: str) -> list[Finding]:
    """Assess one batch of findings with the LLM and ground the answer; never raises on LLM trouble.

    Each finding ends in one of these states: LLM assessment grounded and stored on the finding (status ASSESSED);
    rule-based risk (token budget spent G3.6, LLM unavailable, or no assessment returned for it); or rule-based
    risk plus status ESCALATED when the output was invalid twice (G4.1), meaning a human should look.
    Args: rc - run context; findings - the batch; system - the system prompt.
    Returns: the same findings, mutated. The caller persists them.
    Side effects: audit events (llm_call, llm_result, guardrail), LLM token budget charges.
    """
    audit, store = rc.audit, rc.store
    aliases = Aliases()
    user, hits = build_user_prompt(findings, rc, aliases)
    # Injection-like phrases (e.g. "ignore previous instructions") were seen. They stay wrapped as data;
    # the hit is only surfaced for the audit trail and UI.
    if hits:  # G2.3: still wrapped, but surfaced
        audit.emit("guardrail", "guardrail", f"G2.3 injection-like text in untrusted data: {hits[:3]}",
                   data={"rule": "G2.3", "hits": hits[:10]})
    audit.emit(AGENT, "llm_call", f"Assessing {len(findings)} findings",
               evidence_ids=sorted({e for f in findings for e in f.evidence_ids})[:50],
               data={"model": rc.llm.model, "mode": rc.llm.mode, "findings": [f.finding_id for f in findings]})
    budget = rc.tool_ctx.budget
    if budget is not None and budget.tokens_left() <= 0:  # G3.6: stop spending, keep the rule risk
        audit.emit("guardrail", "guardrail", f"G3.6 LLM token budget exhausted ({budget.llm_tokens} tokens) "
                                             f"-> rule-based risk for {len(findings)} findings",
                   data={"rule": "G3.6", "llm_tokens": budget.llm_tokens, "max": budget.max_llm_tokens})
        return [_apply_rule(f) for f in findings]
    try:
        assessments, err = _call_with_repair(rc, system, user)
    except LLMError as exc:
        audit.emit(AGENT, "error", f"LLM unavailable ({type(exc).__name__}: {str(exc)[:200]}) -> rule-based risk")
        return [_apply_rule(f) for f in findings]

    if assessments is None:  # G4.1 failed twice -> escalate, keep a rule risk so the UI still has one
        out = []
        for f in findings:
            _apply_rule(f)
            f.status = FindingStatus.ESCALATED
            audit.emit("guardrail", "guardrail", "G4.1 output invalid after repair -> finding escalated",
                       finding_id=f.finding_id, data={"rule": "G4.1"})
            out.append(f)
        return out

    # Index the LLM answers by (real) finding id. `lookup` = all evidence by id, so grounding can
    # verify that every cited id exists and its facts match.
    by_id = {a.finding_id: a for a in _unalias(assessments, aliases)}
    lookup = {e.evidence_id: e for e in store.list_evidence()}
    out = []
    for f in findings:
        raw = by_id.get(f.finding_id)
        if raw is None:
            audit.emit("guardrail", "guardrail", "LLM returned no assessment for finding -> rule-based risk",
                       finding_id=f.finding_id, data={"rule": "G4.1"})
            out.append(_apply_rule(f))
            continue
        # The finding's own evidence; grounding checks claims against these facts first.
        fev = [lookup[e] for e in f.evidence_ids if e in lookup]
        # Code decides each claim's label (verified / inferred) and drops unsupported ones; issues are
        # audited as guardrail events with their rule code (G4.2-G4.6).
        g = ground_assessment(raw, fev, lookup, finding_facts=_finding_view(f))
        for issue in g.issues:
            audit.emit("guardrail", "guardrail", f"{issue.rule}: {issue.detail}", finding_id=f.finding_id,
                       data={"rule": issue.rule})
        f.initial_risk = g.initial_risk
        f.initial_risk_source = "llm"
        f.explanation = g.explanation
        f.claims = g.claims
        f.status = FindingStatus.ASSESSED
        labels = [c.label.value for c in g.claims]
        audit.emit(AGENT, "llm_result",
                   f"{f.initial_risk.value.upper()}: {f.title[:80]} "
                   f"({labels.count('verified')} verified, {labels.count('inferred')} inferred, "
                   f"{len(g.rejected)} rejected)",
                   finding_id=f.finding_id, evidence_ids=sorted({e for c in g.claims for e in c.evidence_ids}))
        out.append(f)
    return out


def evidence_analyst_node(state: GraphState) -> dict:
    """LangGraph node: choose which findings go to the LLM, analyse them, and store the results.

    Ranking: non-CVE anomalies first (no advisory text, so the explanation matters most), then by rule risk, then by
    descending CVSS. The first GUARDIAN_MAX_LLM_FINDINGS go to the LLM in batches of BATCH_SIZE, run in parallel on
    WORKERS threads; the rest, and everything when there is no LLM, get the rule-based initial risk.
    Args: state - graph state with `run_id` and `finding_ids`.
    Returns: {"status": "analysing"}. Findings are updated in the store as a side effect, plus audit events.
    """
    rc = get_ctx(state["run_id"])
    audit, store = rc.audit, rc.store
    findings = [store.get_finding(i) for i in state.get("finding_ids", [])]
    findings = [f for f in findings if f is not None]
    audit.emit(AGENT, "agent_start", f"Explaining {len(findings)} findings and assigning initial risk")

    # Supply-chain anomalies (non-CVE) always go to the analyst first: they have no advisory text, so the
    # explanation matters most there; CVEs then fill the budget by rule risk and CVSS.
    # Sort key: (is a CVE, risk rank, -cvss); False sorts before True, so anomalies lead.
    ranked = sorted(findings, key=lambda f: (f.category is FindingCategory.CVE, _RANK[rule_risk(f)], -(f.cvss or 0)))
    # Number of findings the LLM may analyse this run; 0 when no LLM is configured.
    limit = rc.tool_ctx.settings.max_llm_findings if rc.llm is not None else 0
    to_llm, rest = ranked[:limit], ranked[limit:]
    if rest:
        audit.emit("supervisor", "decision",
                   f"{len(to_llm)} highest-ranked findings -> LLM; {len(rest)} get rule-based initial risk "
                   f"(budget GUARDIAN_MAX_LLM_FINDINGS={limit})")

    updated: list[Finding] = [_apply_rule(f) for f in rest]
    if to_llm:
        system = system_prompt()
        batches = [to_llm[i:i + BATCH_SIZE] for i in range(0, len(to_llm), BATCH_SIZE)]
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for result in pool.map(lambda b: analyse_batch(rc, b, system), batches):
                updated.extend(result)
    for f in updated:
        store.update_finding(f)

    by_risk: dict[str, int] = {}
    for f in updated:
        by_risk[f.initial_risk.value] = by_risk.get(f.initial_risk.value, 0) + 1
    llm_n = sum(1 for f in updated if f.initial_risk_source == "llm")
    audit.emit(AGENT, "agent_end", f"Initial risk assigned: {by_risk} ({llm_n} by LLM, {len(updated) - llm_n} by rule)",
               data={"by_risk": by_risk})
    return {"status": "analysing"}
