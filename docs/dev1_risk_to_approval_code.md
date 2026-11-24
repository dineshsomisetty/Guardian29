# Dev1 code: risk prioritisation, remediation, recommendation, human approval

Extracted verbatim from the working tree (line ranges in each heading).

## 1. Risk prioritisation: the risk analyst agent

`guardian/agents/risk_analyst.py` lines 1-402

```python
"""Risk analyst (D1-06): evidence -> RiskFactors -> section-7 score, in code. Owner: Dev1.

For every finding the analyst gathers EPSS/KEV (CVE only), reachability (import search in production paths),
exposure (Dockerfile EXPOSE + server-path import), scope (dependency graph) and provenance evidence through the
registry tools, builds `RiskFactors` in deterministic Python and calls `scoring.compute` (weights, bands, KEV
override, confidence). The LLM only writes the `summary` and structured claims, which are grounded by
guardrails/grounding.py; with no LLM, a replay miss or an ungrounded answer a template summary is used. The score
never depends on the LLM. Output: `risk.json` (list[RiskAssessment], highest score first).

It then picks what enters the remediation loop (GUARDIAN_MAX_PLANS): one finding per non-CVE category we can patch
and verify (typosquat, lockfile, unpinned CI) plus the top CVE findings by score that have a fixed version.
"""

from __future__ import annotations

import re

from guardian.agents.evidence_analyst import Aliases, _evidence_view, _finding_view
from guardian.core.models import (
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    RiskAssessment,
    RiskFactors,
)
from guardian.core.plans import save_risks
from guardian.core.scoring import (
    CATEGORY_SEVERITY,
    EXPOSURE,
    PROVENANCE_BONUS,
    REACHABILITY,
    SCOPE,
    compute,
    factor,
)
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.grounding import SchemaError, batch_json_schema, ground_assessment, parse_batch
from guardian.guardrails.untrusted import SYSTEM_RULE, wrap
from guardian.llm.provider import LLMError
from guardian.tools.registry import call_tool
from guardian.tools.threat_intel import parse_purl

AGENT = "risk_analyst"
PLANNABLE = [FindingCategory.TYPOSQUAT, FindingCategory.LOCKFILE, FindingCategory.UNPINNED_CI,
             FindingCategory.UNTRUSTED_IMAGE]
LLM_TOP = 8  # findings whose summary the LLM writes; the rest get the template
PROVENANCE_TOP = 25
NOT_APPLICABLE = {FindingCategory.UNPINNED_CI, FindingCategory.LOCKFILE, FindingCategory.UNTRUSTED_IMAGE,
                  FindingCategory.POLICY_VIOLATION}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

SYSTEM = (
    "You are the Risk Analyst in Guardian, a software supply-chain security system. The risk score, band and "
    "confidence of each finding were computed by code from tool evidence; you do NOT change them. For each finding "
    "write `explanation` (2-3 sentences: why it ranks where it does, naming the dominant factors and whether the "
    "evidence is unknown for any factor) and structured `claims`. Every claim cites evidence ids shown to you; "
    "put a fact name in `field` and its exact value in `value` only when the evidence states it. Never mention a "
    "CVE, GHSA, purl or version that is not in the evidence. Set `initial_risk` to the band you were given.\n"
    + SYSTEM_RULE
)


# ---------------------------------------------------------------- identity helpers


def cve_ids(f: Finding) -> list[str]:
    return sorted({i.upper() for i in [f.vuln_id, *f.aliases] if i and _CVE.match(i)})


def package_of(f: Finding, store) -> tuple[str, str] | None:
    """(name, ecosystem) of the package a finding is about."""
    if f.component_purl:
        try:
            name, _, eco = parse_purl(f.component_purl)
            # the real ecosystem: treating every non-pip package as npm made Maven packages "not imported"
            return name, eco.lower()
        except ValueError:
            pass
    for eid in f.evidence_ids:
        ev = store.get_evidence(eid)
        if ev and isinstance(ev.facts.get("name"), str):
            return ev.facts["name"], "npm"
    return None


# ---------------------------------------------------------------- factor construction (deterministic)


class Gathered:
    def __init__(self) -> None:
        self.epss: dict[str, Evidence] = {}
        self.kev: dict[str, Evidence] = {}
        self.reach: dict[tuple[str, str], Evidence] = {}
        self.exposure: dict[tuple[str, str], Evidence] = {}
        self.scope: dict[str, Evidence] = {}
        self.prov: dict[str, Evidence] = {}


def build_factors(f: Finding, pkg: tuple[str, str] | None, g: Gathered) -> RiskFactors:
    fev = list(f.evidence_ids)
    is_cve = f.category is FindingCategory.CVE
    # S severity
    if is_cve:
        S = (factor(max(0.0, min(f.cvss, 10.0)) / 10, "cvss", fev) if f.cvss is not None
             else factor(0.5, "unknown", fev, unknown=True))
    else:
        S = factor(CATEGORY_SEVERITY.get(f.category, 0.5), f.category.value, fev)
    # E exploitability
    cves = cve_ids(f)
    kev = next((g.kev[c] for c in cves if c in g.kev and g.kev[c].facts.get("listed")), None)
    epss = [g.epss[c] for c in cves if c in g.epss]
    if kev is not None:
        E = factor(1.0, "kev", [kev.evidence_id])
    elif is_cve and epss:
        top = max(epss, key=lambda e: e.facts["percentile"])
        E = factor(top.facts["percentile"], "epss", [top.evidence_id])
    elif is_cve:
        E = factor(0.5, "unknown", fev, unknown=True)
    elif f.category is FindingCategory.MALICIOUS_INDICATOR:
        E = factor(1.0, "malicious_evidence", fev)
    else:
        E = factor(0.5, "no_exploit_evidence", fev)
    # R reachability
    if f.category in NOT_APPLICABLE:
        R = factor(REACHABILITY["not_applicable"], "not_applicable", fev)
    else:
        ev = g.reach.get(pkg) if pkg else None
        tier = ev.facts["tier"] if ev else "unknown"
        if ev is not None and tier == "imported" and called_for(ev.facts.get("called") or [], f):
            tier = "called"  # a reviewed rule names the vulnerable function and production code calls it
        R = factor(REACHABILITY.get(tier, 0.5), tier, [ev.evidence_id] if ev else [], unknown=tier == "unknown")
    # P production scope
    sev = g.scope.get(f.component_purl or "")
    if sev is not None:
        P = factor(SCOPE[sev.facts["scope"]], sev.facts["scope"], [sev.evidence_id])
    elif f.scope.value in ("prod", "dev"):
        P = factor(SCOPE[f.scope.value], f.scope.value, fev)
    elif f.category in NOT_APPLICABLE:  # CI / lockfile / image files ship with the project
        P = factor(SCOPE["prod"], "prod", fev)
    else:
        P = factor(SCOPE["unknown"], "unknown", [], unknown=True)
    # X exposure
    xev = g.exposure.get(pkg) if pkg else None
    xt = xev.facts["tier"] if xev else "unknown"
    X = (factor(EXPOSURE[xt], xt, [xev.evidence_id]) if xt in ("network", "internal")
         else factor(EXPOSURE["unknown"], "unknown", [], unknown=True))
    # provenance modifier
    pv = g.prov.get(f.component_purl or "")
    failed = pv is not None and bool(pv.facts.get("score_modifier"))
    return RiskFactors(S=S, E=E, R=R, P=P, X=X, provenance_modifier=PROVENANCE_BONUS if failed else 0.0,
                       provenance_evidence_ids=[pv.evidence_id] if failed else [])


def template_summary(f: Finding, a: RiskAssessment) -> str:
    fx = a.factors
    parts = [f"{f.title[:100]}: score {a.score} ({a.band.value}, {a.confidence.value} confidence)."]
    bits = [f"S={fx.S.value} ({fx.S.tier})", f"E={fx.E.value} ({fx.E.tier})", f"R={fx.R.value} ({fx.R.tier})",
            f"P={fx.P.value} ({fx.P.tier})", f"X={fx.X.value} ({fx.X.tier})"]
    parts.append("Factors: " + ", ".join(bits) + ".")
    unknown = [k for k in "SERPX" if getattr(fx, k).unknown]
    if unknown:
        parts.append(f"Unknown (default used): {', '.join(unknown)}.")
    if a.override_applied:
        parts.append("KEV override: listed as actively exploited, reachable in production, so at least high.")
    if fx.provenance_modifier:
        parts.append(f"Provenance check failed: +{fx.provenance_modifier:g} points.")
    return " ".join(parts)


# ---------------------------------------------------------------- selection


def called_for(called: list[dict], f: Finding) -> bool:
    """True when a function-level rule covering this finding's advisory has a call site (stretch goal 1)."""
    ids = {i.upper() for i in [f.vuln_id, *f.aliases] if i}
    return any(c.get("sites") and ("*" in c.get("vuln_ids", []) or ids & {v.upper() for v in c["vuln_ids"]})
               for c in called)


def cve_plannable(f: Finding) -> bool:
    return (f.category is FindingCategory.CVE and bool(f.fixed_versions)
            and (f.component_purl or "").startswith(("pkg:npm/", "pkg:pypi/")))  # package.json / requirements*.txt


def is_direct(f: Finding) -> bool:
    """A dependency the project declares itself (path project -> package), or a finding with no dependency path."""
    return not f.dependency_paths or any(len(p) == 2 for p in f.dependency_paths)


def _pick_key(f: Finding, score: float) -> tuple:
    legacy = (f.file_path or "").endswith(".bak")  # a live manifest beats a shipped backup
    # highest risk first; on a tie a direct dependency first (one manifest edit, no parent upgrade to guess);
    # then content, never the random finding id
    return -score, not is_direct(f), legacy, f.title, f.component_purl or "", f.file_path or ""


def select(findings: list[Finding], limit: int, scores: dict[str, float] | None = None) -> list[Finding]:
    """The findings the remediation loop works on, highest risk score first.

    Every fixable finding competes on its score, so a Critical vulnerability is never passed over for a Medium
    supply-chain issue. At most one finding per package version (its fix is chosen to clear every advisory on
    that package, see remediation.cve_candidates) and one per supply-chain category (one fix covers them all).
    """
    scores = scores or {}
    ok = [f for f in findings if f.status is not FindingStatus.ESCALATED]
    chosen: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for f in sorted(ok, key=lambda f: _pick_key(f, scores.get(f.finding_id, 0))):
        if len(chosen) >= limit:
            break
        if f.category in PLANNABLE:
            key = ("category", f.category.value)
        elif cve_plannable(f):
            key = ("package", f.component_purl or "")
        else:
            continue
        if key in seen:
            continue
        seen.add(key)
        chosen.append(f)
    return chosen


# ---------------------------------------------------------------- LLM summaries (optional)


def _llm_summaries(rc: RunContext, ranked: list[tuple[Finding, RiskAssessment]]) -> dict[str, tuple[str, list]]:
    audit = rc.audit
    if rc.llm is None or not ranked:
        return {}
    budget = rc.tool_ctx.budget
    if budget is not None and budget.tokens_left() <= 0:
        audit.emit("guardrail", "guardrail", "G3.6 LLM token budget exhausted -> template summaries",
                   data={"rule": "G3.6"})
        return {}
    aliases = Aliases()
    blocks, hits = [], []
    for f, a in ranked:
        fa = aliases.of(f.finding_id, "F")
        # structural order (factor order, then the finding's own evidence), never by id: ids are ULIDs whose
        # random part differs between runs, so sorting by id would change the prompt and miss the replay cache
        cited = dict.fromkeys([*(e for fv in (a.factors.S, a.factors.E, a.factors.R, a.factors.P, a.factors.X)
                                 for e in fv.evidence_ids), *f.evidence_ids[:2]])
        evs = [rc.store.get_evidence(e) for e in cited]
        view = {"finding": {**_finding_view(f), "finding_id": fa},
                "computed": {"score": a.score, "band": a.band.value, "confidence": a.confidence.value,
                             "override": a.override_applied,
                             "factors": {k: {"value": getattr(a.factors, k).value, "tier": getattr(a.factors, k).tier,
                                             "unknown": getattr(a.factors, k).unknown,
                                             "evidence": [aliases.of(e, "E") for e in getattr(a.factors, k).evidence_ids]}
                                         for k in "SERPX"}},
                "evidence": [{**_evidence_view(e), "evidence_id": aliases.of(e.evidence_id, "E")} for e in evs if e]}
        block, h = wrap(f"finding {fa}", view)
        blocks.append(block)
        hits += h
    if hits:
        audit.emit("guardrail", "guardrail", f"G2.3 injection-like text in untrusted data: {hits[:3]}",
                   data={"rule": "G2.3", "hits": hits[:10]})
    user = (f"Write the summary for these {len(ranked)} scored findings (ids: "
            f"{', '.join(aliases.of(f.finding_id, 'F') for f, _ in ranked)}).\n\n" + "\n\n".join(blocks))
    audit.emit(AGENT, "llm_call", f"Writing summaries for {len(ranked)} top-risk findings",
               data={"model": rc.llm.model, "mode": rc.llm.mode})
    try:
        resp = rc.llm.complete_json(AGENT, SYSTEM, user, batch_json_schema())
        if budget is not None and resp.usage:
            budget.charge_tokens(resp.usage.get("input_tokens", 0) + resp.usage.get("output_tokens", 0))
        batch = parse_batch(resp.text)
    except (LLMError, SchemaError) as exc:
        audit.emit(AGENT, "error", f"LLM unavailable for summaries ({type(exc).__name__}: {str(exc)[:160]}) "
                                   f"-> template summaries")
        return {}
    lookup = {e.evidence_id: e for e in rc.store.list_evidence()}
    by_id = {aliases.real(x.finding_id): x for x in batch.assessments}
    out = {}
    for f, a in ranked:
        raw = by_id.get(f.finding_id)
        if raw is None:
            continue
        for c in raw.claims:
            c.evidence_ids = [aliases.real(e) for e in c.evidence_ids]
        raw.initial_risk = a.band.value
        fev = [lookup[e] for e in f.evidence_ids if e in lookup]
        g = ground_assessment(raw, fev, lookup, finding_facts=_finding_view(f))
        for issue in g.issues:
            audit.emit("guardrail", "guardrail", f"{issue.rule}: {issue.detail}", finding_id=f.finding_id,
                       data={"rule": issue.rule})
        if g.explanation:
            out[f.finding_id] = (g.explanation, g.claims)
            labels = [c.label.value for c in g.claims]
            audit.emit(AGENT, "llm_result", f"{f.title[:80]} ({labels.count('verified')} verified, "
                                            f"{labels.count('inferred')} inferred, {len(g.rejected)} rejected)",
                       finding_id=f.finding_id)
    return out


# ---------------------------------------------------------------- node


def _collect(rc: RunContext, findings: list[Finding], pkgs: dict[str, tuple[str, str] | None]) -> Gathered:
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    g = Gathered()

    def run_tool(name: str, args: dict):
        out = call_tool(AGENT, name, None, ctx, store, audit, args=args)
        return out.evidence if out else []

    cves = sorted({c for f in findings for c in cve_ids(f)})
    if cves:
        for e in run_tool("threat_intel", {"cves": cves}):
            (g.epss if e.kind == "epss" else g.kev)[e.facts["cve"]] = e
    for eco in ("npm", "pypi", "maven"):  # other ecosystems: no import scanner, so R stays unknown
        names = sorted({p[0] for p in pkgs.values() if p and p[1] == eco
                        })
        if not names:
            continue
        for e in run_tool("reachability", {"packages": names, "ecosystem": eco}):
            g.reach[(e.facts["package"], eco)] = e
        for e in run_tool("exposure_signals", {"packages": names, "ecosystem": eco}):
            g.exposure[(e.facts["package"], eco)] = e
    purls = sorted({f.component_purl for f in findings if f.component_purl})
    if purls:
        for e in run_tool("package_scope", {"purls": purls}):
            g.scope[e.facts["purl"]] = e
    return g


def risk_analyst_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    audit, store, ctx = rc.audit, rc.store, rc.tool_ctx
    findings = [f for f in (store.get_finding(i) for i in state.get("finding_ids", [])) if f]
    audit.emit(AGENT, "agent_start", f"Scoring {len(findings)} findings (S, E, R, P, X + provenance modifier)")
    pkgs = {f.finding_id: (None if f.category in NOT_APPLICABLE else package_of(f, store)) for f in findings}
    g = _collect(rc, findings, pkgs)

    def assess(f: Finding) -> RiskAssessment:
        factors = build_factors(f, pkgs[f.finding_id], g)
        c = compute(factors)
        a = RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band, confidence=c.confidence,
                           override_applied=c.override_applied, factors=factors, summary="")
        a.summary = template_summary(f, a)
        return a

    assessments = {f.finding_id: assess(f) for f in findings}
    # provenance modifier: registry signals for the top-scored npm packages only (one batch call)
    top = sorted(findings, key=lambda f: -assessments[f.finding_id].score)
    purls = [f.component_purl for f in top if (f.component_purl or "").startswith("pkg:npm/")][:PROVENANCE_TOP]
    if purls:
        call_tool(AGENT, "npm_signatures", None, ctx, store, audit)  # Sigstore / registry signatures, if sandboxed
        out = call_tool(AGENT, "provenance_signals", None, ctx, store, audit, args={"purls": purls})
        for e in out.evidence if out else []:
            g.prov[e.facts["purl"]] = e
        if g.prov:
            assessments = {f.finding_id: assess(f) for f in findings}

    by_id = {f.finding_id: f for f in findings}

    def rank_key(a):  # ties broken by content, not by finding_id (a ULID: random between runs, see above)
        f = by_id[a.finding_id]
        return -a.score, f.title, f.component_purl or "", f.file_path or "", f.line or 0, a.finding_id

    ranked = sorted(assessments.values(), key=rank_key)
    summaries = _llm_summaries(rc, [(by_id[a.finding_id], a) for a in ranked[:LLM_TOP]])
    for fid, (text, claims) in summaries.items():
        assessments[fid].summary = text
        assessments[fid].claims = claims
    ranked = sorted(assessments.values(), key=rank_key)
    save_risks(ctx.run_dir, ranked)

    scores = {a.finding_id: a.score for a in ranked}
    limit = ctx.settings.max_plans
    batch = ctx.settings.batch_remediation
    # batch mode: EVERY finding gets a recommendation (a fix, or "no alternatives" with the reason), so nothing is
    # selected here; the recommend node groups them and writes recommendations.json
    chosen = [] if batch else select(findings, limit, scores)
    for f in chosen:
        f.status = FindingStatus.PLANNED
        store.update_finding(f)
    by_band: dict[str, int] = {}
    for a in ranked:
        by_band[a.band.value] = by_band.get(a.band.value, 0) + 1
    unknown = sum(1 for a in ranked for k in "SERP" if getattr(a.factors, k).unknown)
    audit.emit("supervisor", "decision",
               f"D1 risk scored: {by_band}; {unknown} unknown factors lower confidence. "
               + (f"Batch remediation: all {len(ranked)} findings get a recommendation (a fix or no alternative), "
                  f"decided together by a human" if batch else
                  f"{len(chosen)} findings -> remediation loop (every fixable finding by risk score, one per "
                  f"package or supply-chain category, limit GUARDIAN_MAX_PLANS={limit})"),
               evidence_ids=sorted({e for f in chosen for e in f.evidence_ids}),
               data={"bands": by_band, "chosen": [{"finding_id": f.finding_id, "category": f.category.value,
                                                   "score": scores.get(f.finding_id), "title": f.title}
                                                  for f in chosen]})
    audit.emit(AGENT, "agent_end",
               f"risk.json: {len(ranked)} assessments; top: "
               f"{[(by_id[a.finding_id].title[:40], a.score) for a in ranked[:3]]}",
               data={"count": len(ranked)})
    if chosen:
        audit.emit(AGENT, "handoff", f"{len(chosen)} findings -> remediation",
                   evidence_ids=sorted({e for f in chosen for e in f.evidence_ids}))
    queue = [a.finding_id for a in ranked] if batch else [f.finding_id for f in chosen]
    return {"status": "planning_loop", "plan_queue": queue, "current": None, "round": 0, "batch_id": None,
            "attempt": 0, "plan_id": None, "decision": None, "last_validation": None}
```

## 1b. Score formula, bands, simulate_after (Dev4 file, called by the analyst)

`guardian/core/scoring.py` lines 77-166

```python
WEIGHTS = {"S": 0.30, "E": 0.25, "R": 0.20, "P": 0.15, "X": 0.10}
PROVENANCE_BONUS = 5.0

# Factor S for non-CVE findings (plan section 7).
CATEGORY_SEVERITY = {
    FindingCategory.MALICIOUS_INDICATOR: 1.0,
    FindingCategory.TYPOSQUAT: 0.9,
    FindingCategory.DEPENDENCY_CONFUSION: 0.9,
    FindingCategory.INTEGRITY_CHANGE: 0.8,
    FindingCategory.INSTALL_SCRIPT: 0.6,
    FindingCategory.UNPINNED_CI: 0.6,
    FindingCategory.MAINTAINER_CHANGE: 0.6,
    FindingCategory.LOCKFILE: 0.5,
    FindingCategory.UNTRUSTED_IMAGE: 0.5,
    FindingCategory.UNEXPECTED_CHANGE: 0.5,
    FindingCategory.MAJOR_JUMP: 0.5,
    FindingCategory.PROVENANCE_GAP: 0.5,
    FindingCategory.POLICY_VIOLATION: 0.5,
    FindingCategory.OUTDATED: 0.4,
}
REACHABILITY = {"called": 1.0, "imported": 0.6, "unknown": 0.5, "not_imported": 0.1, "not_applicable": 0.0}
SCOPE = {"prod": 1.0, "dev": 0.3, "unknown": 0.7}
EXPOSURE = {"network": 1.0, "internal": 0.5, "unknown": 0.5}
_CONF = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


def band(score: float) -> Priority:
    if score >= 80:
        return Priority.CRITICAL
    if score >= 60:
        return Priority.HIGH
    if score >= 40:
        return Priority.MEDIUM
    return Priority.LOW


def factor(value: float, tier: str, evidence_ids: list[str] | None = None, *, unknown: bool = False,
           label: ClaimLabel | None = None) -> FactorValue:
    ids = list(dict.fromkeys(evidence_ids or []))
    return FactorValue(value=round(value, 4), tier=tier, unknown=unknown, evidence_ids=ids,
                       label=label or (ClaimLabel.INFERRED if unknown or not ids else ClaimLabel.VERIFIED))


def weights_for(f: RiskFactors) -> dict[str, float]:
    w = dict(WEIGHTS)
    if f.R.tier == "not_applicable":  # CI / lockfile / image findings: the R weight moves onto S
        w["S"] += w["R"]
        w["R"] = 0.0
    return w


@dataclass(frozen=True)
class Computed:
    score: float
    band: Priority
    confidence: Confidence
    override_applied: str | None
    weights: dict[str, float]
    contributions: dict[str, float]


def compute(f: RiskFactors) -> Computed:
    w = weights_for(f)
    vals = {k: getattr(f, k).value for k in WEIGHTS}
    contrib = {k: round(100 * w[k] * vals[k], 2) for k in WEIGHTS}
    score = round(min(100.0, 100 * sum(w[k] * vals[k] for k in WEIGHTS) + f.provenance_modifier), 2)
    b = band(score)
    override = None
    if f.E.tier == "kev" and f.R.tier in ("called", "imported") and f.P.tier == "prod" \
            and _ORDER.index(b) < _ORDER.index(Priority.HIGH):
        b, override = Priority.HIGH, "kev_reachable_prod"
    unknown = sum(1 for k in ("S", "E", "R", "P") if getattr(f, k).unknown)  # X never lowers confidence
    conf = _CONF[max(0, len(_CONF) - 1 - unknown)]
    return Computed(score, b, conf, override, w, contrib)


def simulate_after(assessment: RiskAssessment | None, action: str) -> tuple[float, Priority]:
    """Expected score once the plan is applied and validated (not written by the LLM).

    Actions that remove the risky component or setting resolve the finding (score 0). `mitigate` keeps the
    component but moves X to internal; `escalate` changes nothing."""
    if assessment is None:
        return 0.0, Priority.LOW
    if action == "escalate":
        return assessment.score, assessment.band
    if action == "mitigate":
        f = assessment.factors.model_copy(update={"X": factor(0.5, "internal", [], unknown=True)})
        c = compute(f)
        return c.score, c.band
    return 0.0, Priority.LOW
```

## 1c. Evidence tools the analyst and remediation call

`guardian/tools/risk_tools.py` lines 81-281

```python
def threat_intel(ctx: ToolContext, args: ThreatIntelArgs) -> ToolOutput:
    cves = sorted({c.upper() for c in args.cves if re.match(CVE, c.upper())})
    client = intel(ctx, "risk_analyst")
    epss = client.epss_lookup(cves)
    kev = client.kev_lookup(cves)  # {} when the catalog is unavailable -> unknown, not "not listed"
    out: list[Evidence] = []
    for c in cves:
        if c in epss:
            out.append(_ev(ctx, "epss", "first.org/epss", {"cve": c, **epss[c]}))
        if c in kev:
            e = kev[c]
            out.append(_ev(ctx, "kev", "cisa.gov/kev", {"cve": c, "listed": e is not None,
                                                        "date_added": (e or {}).get("dateAdded")}))
    return ToolOutput(evidence=out, summary=f"{len(epss)}/{len(cves)} EPSS, "
                                            f"{sum(1 for c in cves if kev.get(c))} on KEV "
                                            f"({'catalog available' if kev else 'KEV unavailable'})")


# ---------------------------------------------------------------- reachability + exposure


def reachability(ctx: ToolContext, args: PackagesArgs) -> ToolOutput:
    root = ctx.work_dir or ctx.repo
    out = []
    for name in sorted(set(args.packages)):
        r = reach.reachability_import(root, name, args.ecosystem)
        called = reach.reachability_called(root, name, args.ecosystem) if r.tier == "imported" else []
        hit = (called[0]["sites"][0] if called else None) or (r.hits[0] if r.hits else None)
        out.append(_ev(ctx, "reachability", "reachability_import",
                       {"package": name, "ecosystem": args.ecosystem, "tier": r.tier, "files_scanned": r.files_scanned,
                        "hits": r.hits, "called": called,
                        "method": "import search in production paths (tests excluded); vulnerable-function calls "
                                  "from data/reachability/vulnerable_functions.yaml"},
                       file_path=hit["file"] if hit else None, line=hit["line"] if hit else None,
                       excerpt=hit["excerpt"] if hit else None))
    n = sum(1 for e in out if e.facts["tier"] == "imported")
    return ToolOutput(evidence=out, summary=f"{n}/{len(out)} packages imported in production paths")


def _server_hit(hit: dict, ecosystem: str, has_port: bool) -> bool:
    parts = hit["file"].lower().split("/")
    if parts[0] in {"frontend", "client", "ui", "web"}:
        return False
    if ecosystem == "pypi":
        return has_port
    return bool(SERVER_DIRS & set(parts[:-1])) or parts[-1].split(".")[0] in {"server", "app", "index"}


def exposure_signals(ctx: ToolContext, args: PackagesArgs) -> ToolOutput:
    root = ctx.work_dir or ctx.repo
    _, ports = dockerfile.parse(root)
    prod, scanned = reach.import_index(root, args.ecosystem, False)
    alltests, _ = reach.import_index(root, args.ecosystem, True)
    out = []
    for name in sorted(set(args.packages)):
        key = reach.norm(name, args.ecosystem)
        hits = prod.get(key, [])
        server = [h["file"] for h in hits if _server_hit(h, args.ecosystem, bool(ports))]
        if ports and server:
            tier = "network"
        elif scanned and ((alltests.get(key) and not hits) or (hits and not server)):
            tier = "internal"
        else:
            tier = "unknown"
        out.append(_ev(ctx, "exposure", "exposure_signals",
                       {"package": name, "tier": tier, "expose": ports, "imported_in_server_paths": server[:5],
                        "imported_in_prod": bool(hits)},
                       file_path=server[0] if server else None))
    return ToolOutput(evidence=out, summary=f"{sum(1 for e in out if e.facts['tier'] == 'network')} network-facing "
                                            f"of {len(out)} (EXPOSE: {ports or 'none'})")


# ---------------------------------------------------------------- scope (P) from the dependency graph


def package_scope(ctx: ToolContext, args: PurlsArgs) -> ToolOutput:
    nodes: dict[str, dict] = {}
    if ctx.graph is not None and hasattr(ctx.graph, "g"):
        nodes = dict(ctx.graph.g.nodes(data=True))
    elif "graph_json" in ctx.artifacts:
        nodes = {n["id"]: n for n in ctx.artifacts["graph_json"].get("nodes", [])}
    out = []
    for p in sorted(set(args.purls)):
        d = nodes.get(p)
        if d and d.get("scope") in ("prod", "dev"):
            out.append(_ev(ctx, "graph", "graph_build", {"purl": p, "scope": d["scope"], "direct": d.get("direct"),
                                                         "project": d.get("project")}))
    return ToolOutput(evidence=out, summary=f"scope known for {len(out)}/{len(set(args.purls))} components")


# ---------------------------------------------------------------- provenance (npm registry signals)


def npm_signatures(ctx: ToolContext) -> ToolOutput:
    """Stretch goal 3: `npm audit signatures` over the installed dependency tree (registry signatures and
    Sigstore-backed provenance attestations, verified by npm), read from the sandbox's deps image."""
    from guardian.tools import sandbox

    res, why = sandbox.signature_audit(ctx.work_dir or ctx.repo)
    if res is None:
        return ToolOutput(summary=f"signature audit not run: {why}")
    ctx.artifacts["npm_signatures"] = res
    ev = _ev(ctx, "provenance", "npm audit signatures (Sigstore)", {k: v for k, v in res.items() if k != "image"})
    return ToolOutput(evidence=[ev], summary=(
        f"{res.get('verified_signatures')} verified registry signatures, {res.get('verified_attestations')} verified "
        f"attestations, {len(res['invalid'])} invalid, {len(res['missing'])} missing"))


def _audit_for(ctx: ToolContext, purl: str) -> dict | None:
    sig = ctx.artifacts.get("npm_signatures")
    if not sig:
        return None
    name, version, _ = parse_purl(purl)
    key = f"{name}@{version}"
    if key in sig["invalid"]:
        return {"signature_verified": False}
    if key in sig["missing"]:
        return {"signature_verified": None}
    return {"signature_verified": True}  # audited, not reported invalid or missing


def provenance_signals(ctx: ToolContext, args: PurlsArgs) -> ToolOutput:
    client = intel(ctx, "risk_analyst")
    out = []
    for p in sorted(set(args.purls))[:50]:
        meta = client.registry_metadata(p)
        if meta is None:
            continue
        out.append(_ev(ctx, "provenance", "registry_metadata", {"purl": p, **prov.provenance_for(meta, _audit_for(ctx, p))}))
    return ToolOutput(evidence=out, summary=f"provenance for {len(out)} packages, "
                                            f"{sum(1 for e in out if e.facts['score_modifier'])} failed")


# ---------------------------------------------------------------- safe version + compat hint (remediation)


def _stable(v: str) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+", v))


def safe_version_lookup(ctx: ToolContext, args: SafeVersionArgs) -> ToolOutput:
    name, cur, eco = parse_purl(args.purl)
    client = intel(ctx, "remediation")
    res = {"fixed_version": None, "all_fixed": [], "affected_range": None}
    if args.vuln_ids:
        res = client.safe_version_lookup(args.purl, args.vuln_ids)
    meta = client.registry_metadata(args.purl) if eco == "npm" else None
    latest = (meta or {}).get("latest")
    pool = {*res["all_fixed"], *args.scanner_fixed}
    floor = res["fixed_version"] or (min(args.scanner_fixed, key=version_key) if args.scanner_fixed else None)
    cands = {v for v in pool if floor is None or version_key(v) >= version_key(floor)}
    if latest and _stable(latest) and (floor is None or version_key(latest) >= version_key(floor)):
        cands.add(latest)
    child_ranges: dict[str, str] = {}
    pulls_fixed: list[str] = []
    if args.child and args.child_fixed and meta:
        # an older major of the parent may already pull a fixed child: prove it from the registry's
        # dependency range (its lowest admitted version >= the child's fixed version), never assume it
        for v, deps in (meta.get("major_heads") or {}).items():
            if args.child in deps:
                child_ranges[v] = deps[args.child]
                floor_v = range_floor(deps[args.child])
                if floor_v and version_key(floor_v) >= version_key(args.child_fixed):
                    pulls_fixed.append(v)
        cands |= set(pulls_fixed)
    cands = sorted((v for v in cands if cur is None or version_key(v) > version_key(cur)), key=version_key)
    pulls_fixed = [v for v in cands if v in pulls_fixed]
    source = "osv+scanner" if res["all_fixed"] else ("scanner" if args.scanner_fixed else "registry")
    ev = _ev(ctx, "osv", "safe_version_lookup",
             {"purl": args.purl, "package": name, "installed": cur, "vuln_ids": args.vuln_ids,
              "fixed_version": res["fixed_version"] or floor, "candidates": cands, "latest": latest,
              "scanner_fixed": args.scanner_fixed, "affected_range": res["affected_range"], "source": source,
              **({"child": args.child, "child_fixed": args.child_fixed, "child_ranges": child_ranges,
                  "pulls_fixed_child": pulls_fixed} if args.child else {})})
    return ToolOutput(evidence=[ev], summary=f"{name}: candidates {cands or 'none'} ({source})")


def _semver(v: str) -> tuple[int, int, int] | None:
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)) if m else None


def compat_hint(ctx: ToolContext, args: CompatArgs) -> ToolOutput:
    name, _, eco = parse_purl(args.purl)
    a, b = _semver(args.from_version), _semver(args.to_version)
    delta = "unknown" if not (a and b) else ("major" if a[0] != b[0] else "minor" if a[1] != b[1]
                                             else "patch" if a[2] != b[2] else "none")
    meta = intel(ctx, "remediation").version_metadata(name, args.to_version) if eco == "npm" else None
    peers = sorted((meta or {}).get("peer_dependencies", {}))
    deprecated = bool((meta or {}).get("deprecated")) if meta else None
    level = {"major": "high", "minor": "medium", "patch": "low", "none": "low"}.get(delta, "medium")
    if deprecated:
        level = "high"
    elif peers and level == "low":
        level = "medium"
    ev = _ev(ctx, "compat_hint", "compat_hint",
             {"purl": args.purl, "from_version": args.from_version, "to_version": args.to_version,
              "semver_delta": delta, "engines_ok": None, "engines": (meta or {}).get("engines") or {},
              "peer_dep_changes": peers, "deprecated_target": deprecated, "level": level,
              "registry_checked": meta is not None})
    return ToolOutput(evidence=[ev], summary=f"{name} {args.from_version}->{args.to_version}: {delta}, risk {level}")
```

## 2. Remediation: candidates, plan building, sequential node

`guardian/agents/remediation.py` lines 1-680

```python
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
    image: dict | None = None  # {file, image, tag, new_tag?}: digest resolved just before the plan is fixed
    compat: CompatHint | None = None


def ops_key(ops: list[PatchOp]) -> str:
    return json.dumps([o.model_dump(mode="json") for o in ops], sort_keys=True)


def _facts(rc: RunContext, f: Finding) -> tuple[dict, Evidence | None]:
    for eid in f.evidence_ids:
        ev = rc.store.get_evidence(eid)
        if ev is not None:
            return ev.facts, ev
    return {}, None


def _manifest_declares(rc: RunContext, rel: str, name: str) -> bool:
    try:
        text = (rc.tool_ctx.repo / rel).read_text(encoding="utf-8")
    except OSError:
        return False
    return re.search(rf'"{re.escape(name)}"\s*:\s*"', text) is not None


def _lookup(rc: RunContext, purl: str, vuln_ids: list[str], fixed: list[str], *, child: str | None = None,
            child_fixed: str | None = None) -> Evidence | None:
    ctx = rc.tool_ctx
    args = {"purl": purl, "vuln_ids": vuln_ids[:50], "scanner_fixed": fixed[:50]}
    if child and child_fixed:
        args |= {"child": child, "child_fixed": child_fixed}
    out = call_tool(AGENT, "safe_version_lookup", None, ctx, rc.store, rc.audit, args=args)
    return out.evidence[0] if out and out.evidence else None


def _compat(rc: RunContext, purl: str, cur: str, to: str) -> Evidence | None:
    out = call_tool(AGENT, "compat_hint", None, rc.tool_ctx, rc.store, rc.audit,
                    args={"purl": purl, "from_version": cur, "to_version": to})
    return out.evidence[0] if out and out.evidence else None


def _upgrade(rc: RunContext, f: Finding, purl: str, pkg_file: str, why: list, lookup: Evidence, target: str,
             *, via: str | None = None, op: str = "set_dependency_version", spec: str = "^") -> Candidate | None:
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
    version = f"{spec}{target}" if spec != "==" else target
    return Candidate("upgrade", [PatchOp(op=op, file_path=pkg_file, args={"name": name, "version": version})],
                     target, claims, "scanner re-scan", evidence_ids=ev_ids, compat=hint)


# ---------------------------------------------------------------- steering after a rejection

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
# how invasive each kind of change is; "too big" only moves down this scale (or to a lower version)
_SIZE = {"mitigate": 0, "pin": 1, "update_base_image": 2, "upgrade": 2, "replace": 3, "remove": 4, "block": 5}


def _major(v: str | None) -> str | None:
    m = re.match(r"v?(\d+)", v or "")
    return m.group(1) if m else None


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


def steer(cands: list[Candidate], rejected: RemediationPlan | None, reason_type: str | None,
          hits=None) -> tuple[list[Candidate], str | None]:
    """Reorder or filter the remaining candidates by why the human rejected the last fix.
    Returns the candidates and, when the reason rules every one out, a plain-language note why.
    `hits(cand)` lists the advisories a candidate still leaves (None: unknown, all treated as clean)."""
    if rejected is None or reason_type in (None, "", "other"):
        return cands, None
    rv = rejected.target_version
    if reason_type == "too_new":
        def older(c: Candidate) -> bool:
            return c.action == "upgrade" and bool(c.target and rv) and version_key(c.target) < version_key(rv)

        olds = sorted((c for c in cands if older(c)), key=lambda c: version_key(c.target), reverse=True)
        clean = [c for c in olds if not (hits(c) if hits else [])]
        dirty = [c for c in olds if c not in clean]
        rest = sorted((c for c in cands if not older(c) and not (c.action == "upgrade" and c.target and rv)),
                      key=lambda c: _SIZE.get(c.action, 2))
        out = clean + dirty + rest  # the closest older clean version first, then other kinds of fix
        return out, None if out else "no older version and no other kind of fix is available"
    if reason_type == "too_big":
        size = _SIZE.get(rejected.action, 2)

        def smaller(c: Candidate) -> bool:
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

_STEER_PROMPT = Path(__file__).resolve().parent.parent / "prompts" / "remediation_steer.md"
STEER_AGENT = "remediation_steer"
STEER_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["order", "reading"],
                "properties": {"order": {"type": "array", "items": {"type": "string"}},
                               "reading": {"type": "string"}}}


@dataclass
class Steered:
    cands: list[Candidate]
    note: str | None = None  # why nothing is left
    source: str | None = None  # "llm" | "rules" | None (no reason given)
    reading: str | None = None  # one sentence: how the reason was read
    order: list[str] = field(default_factory=list)


def _change(c: Candidate) -> str:
    name = next((str(o.args["name"]) for o in c.ops if "name" in o.args), None)
    return f"{c.action} {name or ''} {c.target or ''}".replace("  ", " ").strip()


def interpret_rejection(rc: RunContext, rejected: RemediationPlan, comment: str, reason_type: str | None,
                        cands: list[Candidate], hits=None) -> tuple[list[Candidate], str, list[str]] | None:
    """Ask the model how to read the human's free-text reason and which remaining candidate fits best. It may only
    reorder or drop the given candidates (C1..Cn); anything else, or any failure, returns None (rules take over)."""
    from guardian.guardrails.untrusted import SYSTEM_RULE, wrap
    from guardian.llm.provider import LLMError

    audit, budget = rc.audit, rc.tool_ctx.budget
    if budget is not None and budget.tokens_left() <= 0:
        audit.emit("guardrail", "guardrail", "G3.6 LLM token budget exhausted -> rules read the rejection",
                   data={"rule": "G3.6"})
        return None
    ids = {f"C{i + 1}": c for i, c in enumerate(cands)}
    leaves = {cid: (hits(c) if hits else []) for cid, c in ids.items()}
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
        reading = str(data.get("reading") or "").strip()[:300]
    except (ValueError, KeyError, TypeError):
        return None
    if not order or any(i not in ids for i in order):  # it may only reorder / drop the given ids
        audit.emit("guardrail", "guardrail", "G4.1 rejection reading named unknown or no candidates -> ignored",
                   data={"rule": "G4.1", "order": order[:10]})
        return None
    order = list(dict.fromkeys(order))
    fixed = sorted(order, key=lambda i: bool(leaves[i]))  # stable: nothing still affected ranks above a clean one
    if fixed != order:
        audit.emit("guardrail", "guardrail", "A candidate with a remaining advisory was ranked above a clean one: "
                                             "corrected", data={"rule": "G4.5", "order": order, "corrected": fixed})
    return [ids[i] for i in fixed], reading or "(no reading given)", fixed


def steer_rejection(rc: RunContext, f: Finding, rejected: RemediationPlan | None, comment: str | None,
                    reason_type: str | None, cands: list[Candidate], hits=None) -> Steered:
    """Order the remaining candidates after a rejection: the deterministic rules by reason type, then (when a model is
    available and the human wrote a comment) the model's reading of it, validated; any failure keeps the rules."""
    rules, note = steer(cands, rejected, reason_type, hits)
    known = reason_type not in (None, "", "other")
    out = Steered(rules, note, "rules" if known else None, RULE_READING.get(reason_type or "") if known else None)
    if rejected is None:
        return out
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
    for eid in c.evidence_ids:
        e = rc.store.get_evidence(eid)
        d = (e.facts.get("release_dates") or {}).get(c.target) if e is not None else None
        if d:
            return str(d)
    return None


# ---------------------------------------------------------------- other advisories on a candidate version

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
    """Advisories found in this scan that still affect `name` at `version` (any instance of the package)."""
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
    dropped, unless no version clears them all (then they stay, and the plan says what it leaves behind)."""
    clean = [(v, hit) for v, hit in scored if not hit]
    dirty = [(v, hit) for v, hit in scored if hit]
    if dirty:
        rc.audit.emit(AGENT, "decision",
                      "Skipping versions still affected by other advisories: "
                      + "; ".join(f"{v} ({', '.join(h[:3])}{'...' if len(h) > 3 else ''})" for v, h in dirty)
                      + ("" if clean else " - no version clears them all, so they stay as a last resort"),
                      finding_id=f.finding_id, data={"skipped": {v: h for v, h in dirty}, "kept_dirty": not clean})
    return clean or dirty


DEP_OPS = {"set_dependency_version", "set_requirement_version", "replace_dependency", "remove_dependency",
           "block_package"}  # ops that edit one dependency of a manifest


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
    Only children the scan found vulnerable, only versions whose dependency range is known."""
    if not parent_purl.startswith("pkg:npm/"):
        return {}
    eco = parse_purl(parent_purl)[2]
    children: dict[str, list[str]] = {}
    for g in rc.store.list_findings():
        if g.category is FindingCategory.CVE and g.component_purl:
            for path in g.dependency_paths:
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
    """Upgrade candidates, safest first. Direct dependency: each fixed version; transitive: the direct parent."""
    purl = f.component_purl
    if purl and purl.startswith("pkg:pypi/"):
        return pip_candidates(rc, f)
    if not purl or not purl.startswith("pkg:npm/"):
        return []
    name, cur, _ = parse_purl(purl)
    pkg_file = "package.json" if f.project in (None, "root") else f"{f.project}/package.json"
    ids = [i for i in [f.vuln_id, *f.aliases] if i]
    out: list[Candidate] = []
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
            scored = [(v, hit + floor.get(v, [])) for v, hit in scored]
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
    image, raw_tag = facts.get("image"), str(facts.get("tag") or "latest")
    if not image or not f.file_path:
        return []
    tag = "latest" if raw_tag.startswith("latest") else raw_tag
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


def ungrounded_target(rc: RunContext, f: Finding, ops: list[PatchOp], evidence_ids: list[str]) -> str | None:
    """G4.5 for image and block ops: why a digest, tag or package name is not backed by tool evidence, else None."""
    cited = [e for e in (rc.store.get_evidence(i) for i in dict.fromkeys([*f.evidence_ids, *evidence_ids])) if e]
    own = [e for e in (rc.store.get_evidence(i) for i in f.evidence_ids) if e]
    for o in ops:
        a = o.args
        if o.op in ("pin_image_digest", "update_base_image"):
            want_tag = a.get("new_tag") or a.get("tag")
```

## 3a. Recommendation data model

`guardian/core/recs.py` lines 1-69

```python
"""Batch remediation files (recommendations.json), shared by the graph, the API and the CLI. Owner: Dev1.

runs/<id>/recommendations.json  {"round", "status", "batch_id", "items": [Recommendation]} (all rounds' state)
runs/<id>/pending_batch.json    only while the run waits for the human's decisions (see core/plans.py)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

Outcome = Literal["awaiting_decision", "approved", "validating", "verified", "failed", "rejected", "accepted",
                  "no_alternative", "needs_person"]
FINAL = {"verified", "accepted", "no_alternative", "needs_person"}


class Alternative(BaseModel):
    action: str
    target_version: str | None = None
    summary: str


class Previous(BaseModel):
    plan_id: str
    outcome: Literal["failed", "rejected"]
    detail: str
    reason_type: str | None = None  # for a rejection: steers which alternative comes next


class Recommendation(BaseModel):
    rec_id: str
    round: int
    finding_ids: list[str]
    primary_finding_id: str
    kind: Literal["fix", "no_alternative"]
    plan_id: str | None = None
    plan_hash: str | None = None
    alternatives: list[Alternative] = []
    reason: str | None = None
    previous: Previous | None = None
    decision: Literal["approve", "reject", "accept_risk"] | None = None
    outcome: Outcome
    steer_note: str | None = None  # how the human's rejection reason was read (AI interpretation, INFERRED, if llm)
    steer_source: Literal["llm", "rules"] | None = None
    attempt: int = 0  # ADDITIVE: attempts spent on this group (G5.4 max 3)
    score: float = 0  # ADDITIVE: risk score of the primary finding (items are sorted by it)


def recs_path(run_dir: Path) -> Path:
    return run_dir / "recommendations.json"


def load_recs(run_dir: Path) -> dict:
    """{"round", "status", "batch_id", "items": [Recommendation]}; empty state when nothing was written yet."""
    path = recs_path(run_dir)
    if not path.exists():
        return {"round": 0, "step": 0, "status": "awaiting_decisions", "batch_id": None, "items": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("step", 0)
    data["items"] = [Recommendation.model_validate(i) for i in data.get("items", [])]
    return data


def save_recs(run_dir: Path, round_no: int, status: str, batch_id: str | None, items: list[Recommendation],
              step: int | None = None) -> None:
    """`round` = full rounds; `step` = decision sets submitted so far (full or one at a time), kept when not given."""
```

## 3b. Recommendation: batch nodes (recommend, gate, record, validate)

`guardian/agents/batch.py` lines 1-542

```python
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
    steer_note: str | None = None  # how the rejection reason was read
    steer_source: str | None = None  # "llm" | "rules"


def _vkey(c: Candidate):
    return version_key(c.target or "0")


def prepare(rc: RunContext, members: list[Finding], rec: Recommendation | None) -> Prep:
    """Candidates for a group, then steered by why the human rejected the last fix (if they did)."""
    prep = _prepare(rc, members, rec)
    prev = rec.previous if rec else None
    if prev is not None and prev.outcome == "rejected" and prep.cands:
        st = steer_rejection(rc, prep.primary, load_plan(rc.tool_ctx.run_dir, prev.plan_id), prev.detail,
                             prev.reason_type, prep.cands, hits=lambda c: candidate_hits(rc, c))
        prep.cands, prep.note, prep.steer_note, prep.steer_source = st.cands, st.note, st.reading, st.source
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
        held = [r for r in items if r.outcome == "approved"]
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
            r.outcome = "approved"  # held: validation starts only once no fix is left undecided
            _set_status(rc, r.finding_ids, FindingStatus.AWAITING_HUMAN)
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
    retry = [r for r in items if r.outcome in ("failed", "rejected")]
    waiting = [r for r in items if r.outcome == "awaiting_decision"]  # undecided (one at a time)
    held = [r for r in items if r.outcome == "approved"]
    # Validation starts only when EVERY fix has a decision: rejected ones first get (and need) a new decision,
    # undecided ones keep waiting; approvals are held until then and validated together.
    route = "recommend" if (retry or waiting) else "validate" if held else "report"
    approved = held if route == "validate" else []
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
    # approvals were held across steps: every approval on record counts, not only the last submission's
    by_plan_approval = _recorded_approvals(run_dir)
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
```

## 4a. Human approval: plan hash and decision checks

`guardian/guardrails/approval.py` lines 1-71

```python
"""G3.3 / G5.1 / G5.2: approvals are bound to the exact plan a human saw. Owner: Dev1.

`plan_hash` is a SHA-256 over the canonical JSON of the plan's content (ops, target, rationale ...), so an
approval for one plan can never be replayed onto a different or edited plan.
"""

from __future__ import annotations

import hashlib
import json

from guardian.core.models import Approval, RemediationPlan

DECISIONS = {"approve", "reject", "accept_risk"}
REASON_TYPES = {"too_big", "too_new", "breaks_app", "different_approach", "other"}  # mirrors remediation.REASON_TYPES


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
```

## 4b. Human approval: gate and decision recording (sequential)

`guardian/agents/human_gate.py` lines 1-58

```python
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
```

## 4c. Routing and graph wiring

`guardian/graph/workflow.py` lines 52-178

```python
# ---------------------------------------------------------------- supervisor routing


def route_after_discovery(state: GraphState) -> str:
    audit = get_ctx(state["run_id"]).audit
    if not state.get("sbom_evidence_id"):
        audit.emit("supervisor", "decision",
                   "No SBOM evidence from discovery -> still routing to detection (detectors work on files)")
    else:
        audit.emit("supervisor", "decision", "SBOM + graph ready -> detection", evidence_ids=[state["sbom_evidence_id"]])
    return "detection"


def route_after_detection(state: GraphState) -> str:
    audit = get_ctx(state["run_id"]).audit
    n = len(state.get("finding_ids", []))
    if n == 0:
        audit.emit("supervisor", "decision", "No findings -> reporter (nothing to analyse, report still written)")
        return "reporter"
    audit.emit("supervisor", "decision", f"{n} findings with evidence -> evidence_analyst for explanation + initial risk")
    return "evidence_analyst"


def route_next(state: GraphState) -> str:
    """Next finding in the remediation queue, or the reporter when the queue is done."""
    audit = get_ctx(state["run_id"]).audit
    queue = state.get("plan_queue") or []
    if queue:
        audit.emit("supervisor", "decision", f"{len(queue)} finding(s) left in the remediation queue -> remediation")
        return "remediation"
    audit.emit("supervisor", "decision", "Remediation queue empty -> reporter")
    return "reporter"


def route_after_remediation(state: GraphState) -> str:
    if state.get("route") == "gate":
        get_ctx(state["run_id"]).audit.emit("supervisor", "decision",
                                            f"Plan {state['plan_id']} ready -> human_gate (no change without approval)")
        return "human_gate"
    return route_next(state)


def route_after_decision(state: GraphState) -> str:
    audit = get_ctx(state["run_id"]).audit
    route = state.get("route")
    if route == "validate":
        audit.emit("supervisor", "decision", f"Plan {state['plan_id']} approved -> validator")
        return "validator"
    if route == "replan":
        audit.emit("supervisor", "decision", "Plan rejected -> remediation must propose a different plan")
        return "remediation"
    if route == "gate":
        return "human_gate"
    return route_next(state)


def route_after_validation(state: GraphState) -> str:
    if state.get("route") == "replan":
        get_ctx(state["run_id"]).audit.emit(
            "supervisor", "decision",
            f"Validation {state['last_validation']['verdict']} -> remediation re-plans (different plan)")
        return "remediation"
    return route_next(state)


def route_after_risk(state: GraphState) -> str:
    rc = get_ctx(state["run_id"])
    if rc.tool_ctx.settings.batch_remediation and state.get("plan_queue"):
        rc.audit.emit("supervisor", "decision", "Batch remediation -> recommend (a recommendation for every finding)")
        return "recommend"
    return "remediation" if state.get("plan_queue") else route_next(state)


def route_after_recommend(state: GraphState) -> str:
    audit = get_ctx(state["run_id"]).audit
    if state.get("route") == "gate":
        audit.emit("supervisor", "decision", f"Batch {state.get('batch_id')} ready -> batch_gate (no validation "
                                             f"until every fix has a decision)")
        return "batch_gate"
    if state.get("route") == "validate":
        return "validate_batch"
    audit.emit("supervisor", "decision", "No fix waits for a decision -> reporter")
    return "reporter"


def route_after_record_batch(state: GraphState) -> str:
    route = state.get("route")
    if route == "gate":
        return "batch_gate"
    if route == "validate":
        return "validate_batch"
    if route == "recommend":
        return "recommend"
    return "reporter"


def route_after_validate_batch(state: GraphState) -> str:
    return "recommend" if state.get("route") == "recommend" else "reporter"


def build_graph(checkpointer=None):
    g = StateGraph(GraphState)
    for name, fn in [("discovery", discovery_node), ("detection", detection_node),
                     ("evidence_analyst", evidence_analyst_node), ("investigator", investigator_node),
                     ("risk_analyst", risk_analyst_node),
                     ("remediation", remediation_node), ("human_gate", human_gate_node),
                     ("record_decision", record_decision_node), ("validator", validator_node),
                     ("recommend", recommend_node), ("batch_gate", batch_gate_node),
                     ("record_batch", record_batch_node), ("validate_batch", validate_batch_node),
                     ("reporter", reporter_node)]:
        g.add_node(name, fn)
    g.add_edge(START, "discovery")
    g.add_conditional_edges("discovery", route_after_discovery, ["detection"])
    g.add_conditional_edges("detection", route_after_detection, ["evidence_analyst", "reporter"])
    g.add_edge("evidence_analyst", "investigator")
    g.add_edge("investigator", "risk_analyst")
    g.add_conditional_edges("risk_analyst", route_after_risk, ["remediation", "recommend", "reporter"])
    g.add_conditional_edges("recommend", route_after_recommend, ["batch_gate", "validate_batch", "reporter"])
    g.add_edge("batch_gate", "record_batch")
    g.add_conditional_edges("record_batch", route_after_record_batch,
                            ["validate_batch", "batch_gate", "recommend", "reporter"])
    g.add_conditional_edges("validate_batch", route_after_validate_batch, ["recommend", "reporter"])
    g.add_conditional_edges("remediation", route_after_remediation, ["human_gate", "remediation", "reporter"])
    g.add_edge("human_gate", "record_decision")
    g.add_conditional_edges("record_decision", route_after_decision,
                            ["validator", "remediation", "human_gate", "reporter"])
    g.add_conditional_edges("validator", route_after_validation, ["remediation", "reporter"])
```

## 4d. resume, resume_batch, _resume

`guardian/graph/workflow.py` lines 420-485

```python


def resume(run_id: str, approval: Approval, settings: Settings | None = None, llm: LLMProvider | None = None,
           echo: bool = True) -> Path:
    """Continue a run paused at the human gate with a human decision. The decision is checked against the
    pending plan first (G5.1/G5.2); an invalid one raises DecisionRejected and nothing resumes."""
    settings = settings or load_settings()
    run_dir = settings.runs_dir / run_id
    pending = get_pending(run_dir)
    if pending is None:
        raise DecisionRejected(f"run {run_id} is not waiting for a decision")
    reason = check_decision(pending, approval)
    if reason:
        raise DecisionRejected(reason)
    return _resume(run_id, settings, llm, echo, Command(resume=approval.model_dump(mode="json")),
                   f"Resuming {run_id}: {approval.decision} on plan {approval.plan_id}")


def resume_batch(run_id: str, batch_id: str, approvals: list[Approval], settings: Settings | None = None,
                 llm: LLMProvider | None = None, echo: bool = True, partial: bool = False) -> Path:
    """Continue a batch-mode run paused at the gate with one decision for EVERY fix of the batch (or, with
    `partial=True`, for one or more of them: the rest stay pending). The set is checked first (every item decided
    unless partial, none extra, G5.1 hashes, G5.2 comments); an invalid one raises DecisionRejected and nothing
    resumes."""
    settings = settings or load_settings()
    run_dir = settings.runs_dir / run_id
    reason = check_batch(get_pending_batch(run_dir), batch_id, approvals, partial=partial)
    if reason:
        raise DecisionRejected(reason)
    value = {"batch_id": batch_id, "partial": partial, "decisions": [a.model_dump(mode="json") for a in approvals]}
    return _resume(run_id, settings, llm, echo, Command(resume=value),
                   f"Resuming {run_id}: batch {batch_id} with {len(approvals)} decisions")


def _resume(run_id: str, settings: Settings, llm: LLMProvider | None, echo: bool, graph_input, message: str) -> Path:
    run_dir = settings.runs_dir / run_id
    lock = run_dir / ".resume.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise DecisionRejected(f"run {run_id} is already resuming") from exc
    os.close(fd)
    try:
        summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
        started = datetime.fromisoformat(summary["started_at"])
        conn = sqlite3.connect(run_dir / "checkpoints.sqlite", check_same_thread=False)
        try:
            values = build_graph(SqliteSaver(conn)).get_state(_config(run_id)).values
        finally:
            conn.close()
        audit = AuditLog(run_dir, run_id, echo=echo)
        store = JsonStore(run_dir)
        tool_ctx = ToolContext(run_id=run_id, run_dir=run_dir, repo=Path(values["repo"]), settings=settings,
                               work_dir=Path(values["work_dir"]) if values.get("work_dir") else None,
                               sbom_path=Path(values["sbom_path"]) if values.get("sbom_path") else None,
                               budget=Budget(max_llm_tokens=settings.max_llm_tokens))
        if values.get("compare_ref"):
            tool_ctx.artifacts["compare_ref"] = values["compare_ref"]
        if summary.get("llm"):
            tool_ctx.artifacts["run_llm"] = summary["llm"]
        if (run_dir / "changes.json").exists():
            tool_ctx.artifacts["changes"] = json.loads((run_dir / "changes.json").read_text(encoding="utf-8"))
        _rebuild_graph(tool_ctx)
        rc = RunContext(tool_ctx=tool_ctx, store=store, audit=audit, llm=llm)
        _write_running(run_dir, run_id, started)
        audit.emit("supervisor", "agent_start", message)
```

## 4e. Decision endpoints (API)

`guardian/api/app.py` lines 296-344

```python
    # ---- human gate ----------------------------------------------------
    @app.post("/runs/{run_id}/plans/{plan_id}/decision", status_code=202)
    def decide(run_id: RunId, plan_id: Pid, body: DecisionBody, request: Request) -> dict:
        who = principal_for(request, store, "approver")
        d = run_dir(run_id)
        pending_file = d / "pending_plan.json"
        if not pending_file.is_file():
            raise HTTPException(409, "no plan is pending a decision")
        pending = _read_json(pending_file)
        if plan_id != pending.get("plan_id") or body.plan_hash != pending.get("plan_hash"):
            raise HTTPException(400, "plan_id/plan_hash do not match the pending plan (G5.1)")
        if body.decision in ("reject", "accept_risk") and not (body.comment and body.comment.strip()):
            raise HTTPException(400, f"{body.decision} requires a comment (G5.2)")
        decided_by = who.name if who.authenticated else (body.decided_by.strip() or "human")
        if body.reason_type and body.decision != "reject":
            raise HTTPException(400, "reason_type is only for a reject")
        approval = Approval(plan_id=plan_id, plan_hash=body.plan_hash, decision=body.decision,
                            comment=body.comment, reason_type=body.reason_type, decided_by=decided_by)
        from guardian.graph import workflow

        spawn(d.name, workflow.resume, d.name, approval, settings=load_settings(runs_dir=runs), echo=False)
        return {"run_id": d.name, "plan_id": plan_id, "decision": body.decision, "decided_by": decided_by}

    @app.post("/runs/{run_id}/batches/{batch_id}/decisions", status_code=202)
    def decide_batch(run_id: RunId, batch_id: Bid, body: BatchDecisionBody, request: Request) -> dict:
        """One decision for EVERY fix of the pending batch (anything less or more is refused as a whole), or with
        `partial` one or more decisions now while the rest stay pending."""
        who = principal_for(request, store, "approver")
        d = run_dir(run_id)
        pending_file = d / "pending_batch.json"
        if not pending_file.is_file():
            raise HTTPException(409, "no batch is pending a decision")
        decided_by = who.name if who.authenticated else (body.decided_by.strip() or "human")
        for i in body.decisions:  # a reject says why, so the next suggestion can follow it
            if i.decision == "reject" and not i.reason_type:
                raise HTTPException(400, f"reject of {i.plan_id} needs a reason_type: too_big, too_new, breaks_app, "
                                         f"different_approach or other")
            if i.reason_type and i.decision != "reject":
                raise HTTPException(400, f"reason_type on {i.plan_id} is only for a reject")
        approvals = [Approval(plan_id=i.plan_id, plan_hash=i.plan_hash, decision=i.decision, comment=i.comment,
                              reason_type=i.reason_type, decided_by=decided_by) for i in body.decisions]
        from guardian.guardrails.approval import check_batch

        reason = check_batch(_read_json(pending_file), batch_id, approvals, partial=body.partial)
        if reason:
            raise HTTPException(400, reason)
        from guardian.graph import workflow

        spawn(d.name, workflow.resume_batch, d.name, batch_id, approvals, settings=load_settings(runs_dir=runs),
```

## 4f. decide / decide-batch (CLI)

`guardian/cli.py` lines 215-276

```python
def _cmd_decide_batch(args: argparse.Namespace) -> int:
    from guardian.core.models import Approval
    from guardian.core.plans import get_pending_batch
    from guardian.graph.workflow import DecisionRejected, resume_batch

    run_dir = _run_dir(args)
    batch = get_pending_batch(run_dir)
    if batch is None:
        print(f"{run_dir.name} has no batch waiting for decisions", file=sys.stderr)
        return 2
    if bool(args.approve_all) == bool(args.file):
        print("give exactly one of --approve-all or --file decisions.json", file=sys.stderr)
        return 2
    only = list(args.only or [])
    partial = bool(only) or args.partial  # one at a time: the fixes not named stay pending
    pending_ids = {i["plan_id"] for i in batch["items"]}
    if unknown := [p for p in only if p not in pending_ids]:
        print(f"not in the pending batch: {', '.join(unknown)}", file=sys.stderr)
        return 2
    if args.approve_all:
        rows = [{"plan_id": i["plan_id"], "plan_hash": i["plan_hash"], "decision": "approve", "comment": args.comment}
                for i in batch["items"] if not only or i["plan_id"] in only]
    else:
        try:
            rows = json.loads(Path(args.file).read_text(encoding="utf-8"))
            if not isinstance(rows, list):
                raise ValueError("expected a JSON list")
        except (OSError, ValueError) as exc:
            print(f"cannot read {args.file}: {exc}", file=sys.stderr)
            return 2
        if only:
            rows = [r for r in rows if isinstance(r, dict) and r.get("plan_id") in only]
    try:
        approvals = [Approval(plan_id=r["plan_id"], plan_hash=r["plan_hash"], decision=r["decision"],
                              comment=r.get("comment") or args.comment, reason_type=r.get("reason_type"),
                              decided_by=args.by) for r in rows]
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        print(f"bad decision entry: {exc!r}", file=sys.stderr)
        return 2
    try:
        run_dir = resume_batch(run_dir.name, args.batch, approvals, partial=partial)
    except DecisionRejected as exc:
        print(f"decisions refused: {exc}", file=sys.stderr)
        return 2
    return _report(run_dir)


def _cmd_decide(args: argparse.Namespace) -> int:
    from guardian.core.models import Approval
    from guardian.core.plans import get_pending
    from guardian.graph.workflow import DecisionRejected, resume

    run_dir = _run_dir(args)
    pending = get_pending(run_dir)
    if pending is None:
        print(f"{run_dir.name} is not waiting for a decision", file=sys.stderr)
        return 2
    # The human types (a prefix of) the hash they were shown, so the approval binds to that exact plan (G5.1).
    if len(args.plan_hash) < 12 or not pending.plan_hash.startswith(args.plan_hash):
        print("--plan-hash must be at least the first 12 characters of the hash shown by `guardian plans`",
              file=sys.stderr)
        return 2
```

## 4g. call_tool guardrails (G3.3 write check)

`guardian/tools/registry.py` lines 199-231

```python
def call_tool(agent: str, name: str, target: str | None, ctx: ToolContext, store: JsonStore, audit: AuditLog,
              *, args: dict | BaseModel | None = None, plan: RemediationPlan | None = None,
              approval: Approval | None = None) -> ToolOutput | None:
    """Run one tool through the G3 guardrails. Blocked, unavailable or failing tools are logged and return
    None (the pipeline continues)."""
    if any(w in name.lower() for w in FORBIDDEN_WORDS):
        _block(audit, agent, name, "G3.4", "publish/push/merge/deploy tools do not exist")
        return None
    if name not in allowed_tools(agent):
        _block(audit, agent, name, "G3.1", "not in this agent's tool allowlist")
        return None
    target = target or target_of(name)
    spec = tool_specs().get(name)
    parsed = None
    if spec and spec.args_model is not None:
        try:
            parsed = args if isinstance(args, spec.args_model) else spec.args_model.model_validate(args or {})
        except ValidationError as exc:
            _block(audit, agent, name, "G3.2", f"invalid args: {exc.errors()[0].get('msg', exc)}")
            return None
    elif args is not None:
        _block(audit, agent, name, "G3.2", "tool takes no arguments")
        return None
    if spec and spec.writes:
        reason = check_write(plan, approval)
        if reason:
            _block(audit, agent, name, "G3.3", reason)
            return None
    if ctx.budget is not None:
        reason = ctx.budget.charge_tool(agent)
        if reason:
            _block(audit, agent, name, "G3.6", f"budget exhausted ({reason})")
            return None
```
