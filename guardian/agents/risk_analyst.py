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
    Priority,
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
_RANK = {Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2, Priority.LOW: 3, None: 4}
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
            return name, ("pypi" if eco.lower() == "pypi" else "npm")
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


def _key(f: Finding, score: float) -> tuple:
    legacy = (f.file_path or "").endswith(".bak")  # a live manifest beats a shipped backup
    cat = PLANNABLE.index(f.category) if f.category in PLANNABLE else len(PLANNABLE)
    return _RANK[f.initial_risk], legacy, cat, -score, f.title


def cve_plannable(f: Finding) -> bool:
    return (f.category is FindingCategory.CVE and bool(f.fixed_versions)
            and (f.component_purl or "").startswith(("pkg:npm/", "pkg:pypi/")))  # package.json / requirements*.txt


def select(findings: list[Finding], limit: int, scores: dict[str, float] | None = None) -> list[Finding]:
    scores = scores or {}
    ok = [f for f in findings if f.status is not FindingStatus.ESCALATED]
    heur, seen = [], set()
    for f in sorted((f for f in ok if f.category in PLANNABLE), key=lambda f: _key(f, scores.get(f.finding_id, 0))):
        if f.category not in seen:
            heur.append(f)
            seen.add(f.category)
    cves = sorted((f for f in ok if cve_plannable(f)), key=lambda f: (-scores.get(f.finding_id, 0), f.title))
    reserve = 1 if cves and limit >= 2 else 0
    chosen = heur[:max(0, limit - reserve)]
    chosen += cves[:max(0, limit - len(chosen))]
    chosen += [f for f in heur if f not in chosen][:max(0, limit - len(chosen))]
    return sorted(chosen[:limit], key=lambda f: _key(f, scores.get(f.finding_id, 0)))


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
    for eco in ("npm", "pypi"):
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
    chosen = select(findings, limit, scores)
    for f in chosen:
        f.status = FindingStatus.PLANNED
        store.update_finding(f)
    by_band: dict[str, int] = {}
    for a in ranked:
        by_band[a.band.value] = by_band.get(a.band.value, 0) + 1
    unknown = sum(1 for a in ranked for k in "SERP" if getattr(a.factors, k).unknown)
    audit.emit("supervisor", "decision",
               f"D1 risk scored: {by_band}; {unknown} unknown factors lower confidence. {len(chosen)} findings -> "
               f"remediation loop (fixable non-CVE categories + top CVEs with a fixed version by score, "
               f"limit GUARDIAN_MAX_PLANS={limit})",
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
    return {"status": "planning_loop", "plan_queue": [f.finding_id for f in chosen], "current": None,
            "attempt": 0, "plan_id": None, "decision": None, "last_validation": None}
