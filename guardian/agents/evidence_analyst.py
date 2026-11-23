"""Evidence analyst agent (LLM): per finding, explanation + initial risk, every claim grounded. Owner: Dev1.

Flow per batch of findings:
  build prompt (untrusted content in <data> blocks, G2) -> LLM structured JSON -> parse (G4.1, 1 repair retry)
  -> ground each claim against evidence facts (G4.2-G4.4, G4.6) -> update Finding.

Findings beyond GUARDIAN_MAX_LLM_FINDINGS, or when the LLM is unavailable, get the rule-based initial risk
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

AGENT = "evidence_analyst"
BATCH_SIZE = 8
WORKERS = 4
_RANK = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3, None: 4}
_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "evidence_analyst.md"

_CATEGORY_DEFAULT = {
    FindingCategory.TYPOSQUAT: Priority.HIGH,
    FindingCategory.MALICIOUS_INDICATOR: Priority.CRITICAL,
    FindingCategory.DEPENDENCY_CONFUSION: Priority.HIGH,
    FindingCategory.INTEGRITY_CHANGE: Priority.HIGH,
}


def fallback_rule(f: Finding) -> Priority:
    """Used only if Dev4's scoring.initial_risk is not available yet. Same bands as §7 / D4-02."""
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
    try:
        return Priority(resolve(INITIAL_RISK_RULE)(f))
    except (ToolUnavailable, Exception):  # noqa: BLE001
        return fallback_rule(f)


def system_prompt() -> str:
    return _PROMPT.read_text(encoding="utf-8").replace("{untrusted_rule}", SYSTEM_RULE)


def _finding_view(f: Finding) -> dict:
    return f.model_dump(
        mode="json",
        include={"finding_id", "category", "title", "detector", "component_purl", "scope", "project", "file_path",
                 "line", "dependency_paths", "vuln_id", "aliases", "cvss", "severity", "fixed_versions",
                 "affected_range"},
    )


def _evidence_view(ev: Evidence) -> dict:
    facts = json.dumps(ev.facts, default=str, sort_keys=True)
    if len(facts) > 3000:
        facts = facts[:3000] + "...(truncated)"
    return {"evidence_id": ev.evidence_id, "kind": ev.kind, "source_tool": ev.source_tool,
            "file_path": ev.file_path, "line": ev.line, "facts": facts,
            "excerpt": (ev.excerpt or "")[:600] or None}


class Aliases:
    """Stable short ids (F1.., E1..) in place of per-run ULIDs.

    The prompt must be identical across runs of the same target so LLM record/replay (§5.3) can serve a
    fresh run offline; it also saves tokens. Aliases are mapped back to real ids before grounding, so an
    unknown alias is still rejected by G4.2.
    """

    def __init__(self) -> None:
        self.to_alias: dict[str, str] = {}
        self.to_real: dict[str, str] = {}

    def of(self, real: str, prefix: str) -> str:
        if real not in self.to_alias:
            alias = f"{prefix}{sum(1 for a in self.to_real if a.startswith(prefix)) + 1}"
            self.to_alias[real], self.to_real[alias] = alias, real
        return self.to_alias[real]

    def real(self, alias: str) -> str:
        return self.to_real.get(alias, alias)


def build_user_prompt(findings: list[Finding], rc: RunContext, aliases: Aliases | None = None) -> tuple[str, list[str]]:
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
    for a in assessments:
        a.finding_id = aliases.real(a.finding_id)
        for c in a.claims:
            c.evidence_ids = [aliases.real(e) for e in c.evidence_ids]
    return assessments


def _call_with_repair(rc: RunContext, system: str, user: str) -> tuple[list[RawAssessment] | None, str | None]:
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
    f.initial_risk = rule_risk(f)
    f.initial_risk_source = "rule"
    return f


def analyse_batch(rc: RunContext, findings: list[Finding], system: str) -> list[Finding]:
    audit, store = rc.audit, rc.store
    aliases = Aliases()
    user, hits = build_user_prompt(findings, rc, aliases)
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
        fev = [lookup[e] for e in f.evidence_ids if e in lookup]
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
    rc = get_ctx(state["run_id"])
    audit, store = rc.audit, rc.store
    findings = [store.get_finding(i) for i in state.get("finding_ids", [])]
    findings = [f for f in findings if f is not None]
    audit.emit(AGENT, "agent_start", f"Explaining {len(findings)} findings and assigning initial risk")

    # Supply-chain anomalies (non-CVE) always go to the analyst first: they have no advisory text, so the
    # explanation matters most there; CVEs then fill the budget by rule risk and CVSS.
    ranked = sorted(findings, key=lambda f: (f.category is FindingCategory.CVE, _RANK[rule_risk(f)], -(f.cvss or 0)))
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
