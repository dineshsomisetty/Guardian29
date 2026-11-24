"""Investigator (D1-08): bounded ReAct loop over non-CVE heuristic findings. Owner: Dev1.

For each heuristic finding (typosquat, install_script, unexpected_change, integrity_change, major_jump,
malicious_indicator) the LLM picks the next read-only tool from the investigator allowlist
(registry_metadata, file_excerpt, manifest_diff), sees the result as untrusted <data> (G2), and finally emits
a conclusion as structured JSON. Everything it adds is grounded in code (G4): claim labels are set by
`ground_assessment`, never by the LLM, and the conclusion Claim text starts with "Conclusion:".

Limits: every tool call goes through `call_tool`, so the per-agent budget (8 tool calls per run, G3.6)
and the allowlist / typed-args checks (G3.1, G3.2) apply. With no LLM (None, replay miss, error, token budget)
the node runs a fixed plan (registry_metadata -> file_excerpt, or manifest_diff -> file_excerpt) and writes
an INFERRED conclusion, so the pipeline is deterministic offline.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ValidationError

from guardian.agents.evidence_analyst import Aliases, _evidence_view, _finding_view
from guardian.core.models import Claim, ClaimLabel, Evidence, Finding, FindingCategory
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.budgets import DEFAULT_LIMITS
from guardian.guardrails.grounding import RawAssessment, RawClaim, ground_assessment
from guardian.guardrails.untrusted import SYSTEM_RULE, wrap
from guardian.llm.provider import LLMError
from guardian.tools.registry import allowed_tools, call_tool

AGENT = "investigator"
HEURISTICS = [FindingCategory.MALICIOUS_INDICATOR, FindingCategory.TYPOSQUAT, FindingCategory.INTEGRITY_CHANGE,
              FindingCategory.UNEXPECTED_CHANGE, FindingCategory.MAJOR_JUMP, FindingCategory.INSTALL_SCRIPT]
MAX_FINDINGS = 4  # findings investigated per run; the rest keep their detector evidence only
_RISK_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, None: 4}
TOOLS = ("registry_metadata", "file_excerpt", "manifest_diff")

SYSTEM = (
    "You are the Investigator in a software supply-chain guardian. You examine ONE suspicious finding "
    "(typosquat, install script, unexpected change, ...) with read-only tools and then conclude.\n"
    "Each turn answer with one JSON object. To look something up set action=\"call_tool\" and name the tool:\n"
    "  registry_metadata(name, version?)   npm registry metadata of a package\n"
    "  file_excerpt(path, line, context)   lines around a location in the project\n"
    "  manifest_diff()                     what changed against the baseline\n"
    "To finish set action=\"conclude\" and give `conclusion` (text, optional field/value, evidence_ids). Cite "
    "only evidence ids shown to you (E1, E2, ...). Do not invent versions, CVE ids or package names. "
    "You have a small tool budget; stop as soon as you can conclude.\n" + SYSTEM_RULE
)


class Step(BaseModel):
    action: Literal["call_tool", "conclude"]
    tool: str | None = None
    name: str | None = None
    version: str | None = None
    path: str | None = None
    line: int | None = None
    context: int | None = None
    conclusion: RawClaim | None = None
    claims: list[RawClaim] = []


def step_schema() -> dict[str, Any]:
    ns = {"anyOf": [{"type": "string"}, {"type": "null"}]}
    ni = {"anyOf": [{"type": "integer"}, {"type": "null"}]}
    claim = {"type": "object",
             "properties": {"text": {"type": "string"}, "field": ns, "value": ns,
                            "evidence_ids": {"type": "array", "items": {"type": "string"}}},
             "required": ["text", "field", "value", "evidence_ids"], "additionalProperties": False}
    props = {"action": {"type": "string", "enum": ["call_tool", "conclude"]},
             "tool": {"anyOf": [{"type": "string", "enum": list(TOOLS)}, {"type": "null"}]},
             "name": ns, "version": ns, "path": ns, "line": ni, "context": ni,
             "conclusion": {"anyOf": [claim, {"type": "null"}]},
             "claims": {"type": "array", "items": claim}}
    return {"type": "object", "properties": props, "required": list(props), "additionalProperties": False}


# ---------------------------------------------------------------- helpers


def package_name(f: Finding, evidence: list[Evidence]) -> str | None:
    for ev in evidence:
        for key in ("name", "package"):
            if isinstance(ev.facts.get(key), str):
                return ev.facts[key]
    purl = f.component_purl or ""
    m = re.match(r"pkg:npm/((?:%40|@)?[^@/]+(?:/[^@/]+)?)@", purl) or re.match(r"pkg:npm/([^@]+)$", purl)
    return m.group(1).replace("%40", "@") if m else None


def _selected(findings: list[Finding]) -> list[Finding]:
    rank = {c: i for i, c in enumerate(HEURISTICS)}
    hs = [f for f in findings if f.category in rank]
    return sorted(hs, key=lambda f: (rank[f.category], _RISK_RANK[f.initial_risk.value if f.initial_risk else None],
                                     f.title))


def _tool_args(tool: str, step: Step) -> dict | None:
    if tool == "registry_metadata":
        return {"name": step.name or "", **({"version": step.version} if step.version else {})}
    if tool == "file_excerpt":
        return {"path": step.path or "", "line": step.line or 1,
                "context": 5 if step.context is None else step.context}
    return None


def _plan(f: Finding, name: str | None) -> list[tuple[str, dict | None]]:
    """The fixed deterministic plan used without an LLM."""
    plan: list[tuple[str, dict | None]] = []
    if f.category is FindingCategory.UNEXPECTED_CHANGE or not name:
        plan.append(("manifest_diff", None))
    else:
        plan.append(("registry_metadata", {"name": name}))
    if f.file_path:
        plan.append(("file_excerpt", {"path": f.file_path, "line": f.line or 1, "context": 5}))
    return plan


def _observation(ev: Evidence, aliases: Aliases) -> dict:
    return {**_evidence_view(ev), "evidence_id": aliases.of(ev.evidence_id, "E")}


def _summarise(ev: Evidence) -> str:
    f = ev.facts
    if ev.kind == "registry_metadata":
        if not f.get("available"):
            return f"registry metadata for {f.get('package')} was not available ({f.get('source')})"
        if f.get("exists") is False:
            return f"{f.get('package')} does not exist on the npm registry"
        return (f"registry lists {f.get('package')} {f.get('version')} (maintainers: "
                f"{', '.join(f.get('maintainers') or []) or 'unknown'}; install hooks: "
                f"{', '.join(f.get('install_hooks') or []) or 'none'})")
    if ev.kind == "file_excerpt":
        return f"{f.get('path')} around line {f.get('line')} was read"
    if ev.kind == "diff":
        if not f.get("available"):
            return "no baseline was available for a manifest diff"
        return (f"manifest diff vs baseline: {len(f.get('added') or [])} added, {len(f.get('removed') or [])} "
                f"removed, {len(f.get('changed') or [])} changed")
    return ev.kind


# ---------------------------------------------------------------- per-finding loop


class Investigation:
    def __init__(self, rc: RunContext, f: Finding, cap: int | None):
        self.rc, self.f, self.cap = rc, f, cap
        self.base = [e for e in (rc.store.get_evidence(i) for i in f.evidence_ids) if e]
        self.new: list[Evidence] = []
        self.calls = 0
        self.exhausted = False
        self.aliases = Aliases()
        self.name = package_name(f, self.base)

    def run_tool(self, tool: str, args: dict | None) -> Evidence | None:
        rc = self.rc
        self.calls += 1
        out = call_tool(AGENT, tool, None, rc.tool_ctx, rc.store, rc.audit, args=args)
        budget = rc.tool_ctx.budget
        if out is None and budget is not None and budget.tool_calls.get(AGENT, 0) >= DEFAULT_LIMITS[AGENT].tool_calls:
            self.exhausted = True  # call_tool refused it (G3.6): the next LLM turn could only be refused too
        if out is None or not out.evidence:
            return None
        self.new.extend(out.evidence)
        return out.evidence[0]

    def prompt(self, steps_left: int) -> tuple[str, list[str]]:
        view = {**_finding_view(self.f), "finding_id": self.aliases.of(self.f.finding_id, "F")}
        base = [_observation(e, self.aliases) for e in self.base]
        seen = [_observation(e, self.aliases) for e in self.new]
        block, hits = wrap("investigation", {"finding": view, "evidence": base, "tool_results": seen})
        text = (f"Investigate finding {view['finding_id']}. Tool calls left for this finding: {steps_left}. "
                f"Allowed tools: {', '.join(sorted(allowed_tools(AGENT)))}.\n\n{block}")
        return text, hits

    def next_step(self, steps_left: int) -> Step | None:
        """One LLM turn. None means: no usable LLM answer, fall back to the deterministic plan."""
        rc = self.rc
        if rc.llm is None:
            return None
        budget = rc.tool_ctx.budget
        if budget is not None and budget.tokens_left() <= 0:
            rc.audit.emit("guardrail", "guardrail", "G3.6 LLM token budget exhausted -> deterministic plan",
                          data={"rule": "G3.6", "agent": AGENT})
            return None
        user, hits = self.prompt(steps_left)
        if hits:
            rc.audit.emit("guardrail", "guardrail", f"G2.3 injection-like text in untrusted data: {hits[:3]}",
                          data={"rule": "G2.3", "hits": hits[:10]})
        rc.audit.emit(AGENT, "llm_call", f"Next step for {self.f.title[:80]}", finding_id=self.f.finding_id,
                      data={"model": rc.llm.model, "mode": rc.llm.mode})
        prompt = user
        for attempt in (1, 2):  # G4.1: one repair retry
            try:
                resp = rc.llm.complete_json(AGENT, SYSTEM, prompt, step_schema())
            except LLMError as exc:
                rc.audit.emit(AGENT, "error", f"LLM unavailable ({type(exc).__name__}: {str(exc)[:160]}) "
                                              "-> deterministic plan", finding_id=self.f.finding_id)
                return None
            if budget is not None and resp.usage:
                budget.charge_tokens(resp.usage.get("input_tokens", 0) + resp.usage.get("output_tokens", 0))
            try:
                step = Step.model_validate(json.loads(resp.text))
            except (json.JSONDecodeError, ValidationError) as exc:
                err = str(exc)[:600]
                rc.audit.emit("guardrail", "guardrail", f"G4.1 schema validation failed (attempt {attempt})",
                              data={"rule": "G4.1", "error": err[:300], "agent": AGENT})
                prompt = user + "\n\nYour previous output failed schema validation:\n" + err + "\nReturn only valid JSON."
                continue
            for c in [step.conclusion, *step.claims]:
                if c is not None:
                    c.evidence_ids = [self.aliases.real(e) for e in c.evidence_ids]
            return step
        return None

    def react(self) -> Step | None:
        """LLM-driven loop. Returns the concluding Step, or None if the LLM could not finish the job."""
        audit = self.rc.audit
        for turn in range(DEFAULT_LIMITS[AGENT].tool_calls + 2):
            left = DEFAULT_LIMITS[AGENT].tool_calls if self.cap is None else self.cap
            step = self.next_step(max(0, left - self.calls))
            if step is None:
                return None
            if step.action == "conclude":
                audit.emit(AGENT, "decision", f"D1-08 conclude after {self.calls} tool call(s) (LLM)",
                           finding_id=self.f.finding_id)
                return step
            tool = step.tool or ""
            args = _tool_args(tool, step)
            audit.emit(AGENT, "decision", f"D1-08 next tool: {tool or '(none)'} (LLM, turn {turn + 1})",
                       finding_id=self.f.finding_id, data={"tool": tool, "args": args})
            if self.cap is not None and self.calls >= self.cap:
                audit.emit(AGENT, "decision", f"per-finding share of {self.cap} tool calls used -> conclude",
                           finding_id=self.f.finding_id)
                return Step(action="conclude")
            self.run_tool(tool, args)  # blocked / invalid calls are logged by call_tool; the loop goes on
            if self.exhausted:
                audit.emit(AGENT, "decision", "tool budget spent -> conclude with what was collected",
                           finding_id=self.f.finding_id)
                return Step(action="conclude")
        return Step(action="conclude")

    def deterministic(self) -> None:
        self.rc.audit.emit(AGENT, "decision", "D1-08 deterministic plan (no LLM answer): "
                           + " -> ".join(t for t, _ in _plan(self.f, self.name)), finding_id=self.f.finding_id)
        for tool, args in _plan(self.f, self.name):
            if (self.cap is not None and self.calls >= self.cap) or self.exhausted:
                break
            self.run_tool(tool, args)

    def conclude(self, step: Step | None) -> list[Claim]:
        rc, f = self.rc, self.f
        lookup = {e.evidence_id: e for e in rc.store.list_evidence()}
        lookup.update({e.evidence_id: e for e in self.new})
        ev_all = [*self.base, *self.new]
        claims: list[Claim] = []
        if step is not None and (step.conclusion is not None or step.claims):
            raws = []
            if step.conclusion is not None and step.conclusion.text.strip():
                c = step.conclusion
                text = c.text.strip()
                if not text.lower().startswith("conclusion:"):
                    text = f"Conclusion: {text}"
                raws.append(RawClaim(text=text, field=c.field, value=c.value,
                                     evidence_ids=c.evidence_ids or [*f.evidence_ids[:1],
                                                                     *(e.evidence_id for e in self.new)]))
            raws.extend(step.claims)
            risk = f.initial_risk.value if f.initial_risk else "medium"
            g = ground_assessment(RawAssessment(finding_id=f.finding_id, initial_risk=risk, explanation="",
                                                claims=raws),
                                  ev_all, lookup, finding_facts=_finding_view(f))
            for issue in g.issues:
                rc.audit.emit("guardrail", "guardrail", f"{issue.rule}: {issue.detail}", finding_id=f.finding_id,
                              data={"rule": issue.rule, "agent": AGENT})
            claims = g.claims
        if not any(c.text.startswith("Conclusion:") for c in claims):
            claims.append(self.fallback_conclusion())
        return claims

    def fallback_conclusion(self) -> Claim:
        """Code-written, INFERRED: used with no LLM, or when the LLM's conclusion failed grounding."""
        seen = "; ".join(_summarise(e) for e in self.new) or "no additional evidence could be collected"
        what = {FindingCategory.TYPOSQUAT: "possible typosquat", FindingCategory.INSTALL_SCRIPT: "install script",
                FindingCategory.UNEXPECTED_CHANGE: "unexpected change"}.get(
                    self.f.category, self.f.category.value.replace("_", " "))
        ids = [*self.f.evidence_ids[:1], *(e.evidence_id for e in self.new)]
        return Claim(text=f"Conclusion: {what} for {self.name or self.f.title[:60]} stays suspicious "
                          f"pending human review; {seen}.",
                     evidence_ids=ids, label=ClaimLabel.INFERRED)


def investigate(rc: RunContext, f: Finding, cap: int | None) -> Finding:
    inv = Investigation(rc, f, cap)
    step = inv.react() if rc.llm is not None else None
    if step is None:
        inv.deterministic()
    claims = inv.conclude(step)
    f.claims = [*f.claims, *claims]
    f.evidence_ids = [*f.evidence_ids, *(e.evidence_id for e in inv.new if e.evidence_id not in f.evidence_ids)]
    rc.store.update_finding(f)
    concl = next(c for c in claims if c.text.startswith("Conclusion:"))
    rc.audit.emit(AGENT, "llm_result" if step is not None else "decision",
                  f"{concl.label.value.upper()}: {concl.text[:140]}", finding_id=f.finding_id,
                  evidence_ids=sorted({e for c in claims for e in c.evidence_ids}),
                  data={"tool_calls": inv.calls, "claims": len(claims),
                        "mode": "llm" if step is not None else "deterministic"})
    return f


def investigator_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    audit = rc.audit
    findings = [f for f in (rc.store.get_finding(i) for i in state.get("finding_ids", [])) if f]
    todo = _selected(findings)
    if not todo:
        audit.emit(AGENT, "decision", "D1-08 no non-CVE heuristic findings -> investigator is a no-op")
        return {"status": "investigating"}
    chosen = todo[:MAX_FINDINGS]
    audit.emit(AGENT, "agent_start", f"Investigating {len(chosen)} of {len(todo)} heuristic findings")
    if len(todo) > len(chosen):
        audit.emit(AGENT, "decision", f"{len(todo) - len(chosen)} lower-ranked heuristic findings keep their "
                                      f"detector evidence only (limit {MAX_FINDINGS} per run)")
    total = DEFAULT_LIMITS[AGENT].tool_calls
    per_finding = max(2, total // len(chosen))
    done = 0
    for i, f in enumerate(chosen):
        budget = rc.tool_ctx.budget
        if budget is not None and budget.tool_calls.get(AGENT, 0) >= total:
            audit.emit(AGENT, "decision", f"tool budget ({total}) spent: {len(chosen) - done} finding(s) "
                                          "not investigated")
            break
        investigate(rc, f, per_finding if i < len(chosen) - 1 else None)  # last one gets what is left
        done += 1
    used = rc.tool_ctx.budget.tool_calls.get(AGENT, 0) if rc.tool_ctx.budget else 0
    audit.emit(AGENT, "agent_end", f"Investigated {done} finding(s) with {used} tool call(s)")
    audit.emit(AGENT, "handoff", f"{done} investigated finding(s) -> risk_analyst")
    return {"status": "investigating"}
