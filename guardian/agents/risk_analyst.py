"""Risk analyst (D1-06): evidence -> RiskFactors -> section-7 score, in code. Owner: Dev1.

Role: fifth node, after detection/analysis/investigation. It ranks every finding by how much it matters for THIS
project, and decides which findings enter remediation.

For every finding the analyst gathers EPSS/KEV (CVE only), reachability (import search in production paths),
exposure (Dockerfile EXPOSE + server-path import), scope (dependency graph) and provenance evidence through the
registry tools, builds `RiskFactors` in deterministic Python and calls `scoring.compute` (weights, bands, KEV
override, confidence). The five factors are S severity, E exploitability, R reachability, P production scope and
X exposure, each in 0..1, plus a provenance bonus; a factor whose evidence is missing uses a default and is
flagged `unknown`, which lowers the confidence of the score. The LLM only writes the `summary` and structured
claims, which are grounded by guardrails/grounding.py (claim labels VERIFIED/INFERRED set by code, unknown
evidence ids rejected, finding text passed only as untrusted <data>); with no LLM, a replay miss or an ungrounded
answer a template summary is used. The score never depends on the LLM. Output: `risk.json` (list[RiskAssessment],
highest score first).

Inputs:  state `run_id`, `finding_ids`; the Findings from the store.
Tools:   threat_intel (EPSS, KEV), reachability, exposure_signals, package_scope, npm_signatures,
         provenance_signals; each produces Evidence (kinds epss, kev, reachability, exposure, scope, provenance).
Audit:   `agent_start`, a supervisor `decision` with the band counts and the chosen findings, `llm_call` /
         `llm_result`, `guardrail` events (G2.3, G3.6, G4.x), `agent_end`, and a `handoff` to remediation.

It then picks what enters the remediation loop (GUARDIAN_MAX_PLANS): one finding per non-CVE category we can patch
and verify (typosquat, lockfile, unpinned CI) plus the top CVE findings by score that have a fixed version.
In batch mode (GUARDIAN_BATCH_REMEDIATION) nothing is selected here: every finding is queued and the batch
recommend node proposes a fix or "no alternative" for each, decided together by a human.
Returns state keys: `status` ("planning_loop"), `plan_queue` (finding ids for remediation), and the reset loop
fields (`current`, `round`, `batch_id`, `attempt`, `plan_id`, `decision`, `last_validation`).
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
# Non-CVE categories for which Guardian can write AND verify a patch; one finding per category is
# chosen because one fix (e.g. pinning all CI actions) covers every finding of that category.
PLANNABLE = [FindingCategory.TYPOSQUAT, FindingCategory.LOCKFILE, FindingCategory.UNPINNED_CI,
             FindingCategory.UNTRUSTED_IMAGE]
# Only the 8 highest-scored findings get an LLM-written summary (cost cap); the rest use the template.
LLM_TOP = 8  # findings whose summary the LLM writes; the rest get the template
# Provenance (registry signature / publisher) lookups are limited to the top-25 scored npm packages.
PROVENANCE_TOP = 25
# Categories where reachability does not make sense (a CI file or lockfile is not "imported"):
# R is scored not_applicable and P is treated as production, since these files ship with the project.
NOT_APPLICABLE = {FindingCategory.UNPINNED_CI, FindingCategory.LOCKFILE, FindingCategory.UNTRUSTED_IMAGE,
                  FindingCategory.POLICY_VIOLATION}
# Strict CVE id shape; aliases such as GHSA-... are not CVE ids and are not sent to threat intel.
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)

# System prompt: the model explains a score that code already computed. It must not change the band,
# must cite only evidence ids it was shown, and must not name CVEs/purls/versions absent from the evidence.
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
    """Sorted, upper-cased CVE ids of a finding (its vuln_id plus aliases that look like CVE-YYYY-NNNN)."""
    return sorted({i.upper() for i in [f.vuln_id, *f.aliases] if i and _CVE.match(i)})


def package_of(f: Finding, store) -> tuple[str, str] | None:
    """(name, ecosystem) of the package a finding is about, or None if it cannot be determined.

    Uses the purl when present (the ecosystem is the real one: npm, pypi, maven, ...); otherwise a `name` fact from
    the finding's evidence, assumed to be npm.
    """
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
    """Evidence collected for scoring, indexed for lookup by `build_factors`.

    epss / kev are keyed by CVE id; reach / exposure by (package name, ecosystem); scope / prov by purl.
    """
    def __init__(self) -> None:
        self.epss: dict[str, Evidence] = {}
        self.kev: dict[str, Evidence] = {}
        self.reach: dict[tuple[str, str], Evidence] = {}
        self.exposure: dict[tuple[str, str], Evidence] = {}
        self.scope: dict[str, Evidence] = {}
        self.prov: dict[str, Evidence] = {}


def build_factors(f: Finding, pkg: tuple[str, str] | None, g: Gathered) -> RiskFactors:
    """Compute the five risk factors (and the provenance modifier) of a finding, deterministically.

    Each factor is made with `factor(value, tier, evidence_ids, unknown=...)`: the tier names why that value was
    chosen, the evidence ids prove it, and `unknown=True` marks a default used because no evidence existed.
    Args: f - the finding; pkg - (name, ecosystem) or None; g - the gathered evidence.
    Returns: RiskFactors, ready for `scoring.compute`. No LLM, no side effects.
    """
    fev = list(f.evidence_ids)
    is_cve = f.category is FindingCategory.CVE
    # S severity
    # CVEs use CVSS/10 (0.5 and unknown when missing); other categories use a fixed
    # per-category severity from scoring.CATEGORY_SEVERITY.
    if is_cve:
        S = (factor(max(0.0, min(f.cvss, 10.0)) / 10, "cvss", fev) if f.cvss is not None
             else factor(0.5, "unknown", fev, unknown=True))
    else:
        S = factor(CATEGORY_SEVERITY.get(f.category, 0.5), f.category.value, fev)
    # E exploitability
    # CISA KEV listing = 1.0 (known exploited); else the EPSS percentile; unknown (0.5)
    # for a CVE with neither; a malicious-indicator is exploited by definition; other non-CVE: neutral 0.5.
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
    # How the project uses the package. Tier "imported" is upgraded to "called" when
    # a reviewed rule names the vulnerable function and production code calls it.
    if f.category in NOT_APPLICABLE:
        R = factor(REACHABILITY["not_applicable"], "not_applicable", fev)
    else:
        ev = g.reach.get(pkg) if pkg else None
        tier = ev.facts["tier"] if ev else "unknown"
        if ev is not None and tier == "imported" and called_for(ev.facts.get("called") or [], f):
            tier = "called"  # a reviewed rule names the vulnerable function and production code calls it
        R = factor(REACHABILITY.get(tier, 0.5), tier, [ev.evidence_id] if ev else [], unknown=tier == "unknown")
    # P production scope
    # Dependency-graph scope evidence first, then the finding's own scope field.
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
    # Only network/internal exposure tiers count; anything else is treated as unknown.
    xev = g.exposure.get(pkg) if pkg else None
    xt = xev.facts["tier"] if xev else "unknown"
    X = (factor(EXPOSURE[xt], xt, [xev.evidence_id]) if xt in ("network", "internal")
         else factor(EXPOSURE["unknown"], "unknown", [], unknown=True))
    # provenance modifier
    # A flat bonus (PROVENANCE_BONUS) only when the registry/provenance check
    # failed, i.e. the package may not come from its claimed publisher.
    pv = g.prov.get(f.component_purl or "")
    failed = pv is not None and bool(pv.facts.get("score_modifier"))
    return RiskFactors(S=S, E=E, R=R, P=P, X=X, provenance_modifier=PROVENANCE_BONUS if failed else 0.0,
                       provenance_evidence_ids=[pv.evidence_id] if failed else [])


def template_summary(f: Finding, a: RiskAssessment) -> str:
    """Plain, code-written summary of a score: band, confidence, each factor with its tier, unknown
    factors, KEV override and provenance bonus. Used for every finding the LLM does not (or cannot) summarise, so
    the explanation never depends on the LLM.
    """
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
    """True when a function-level rule covering this finding's advisory has a call site (stretch goal 1).

    Args: called - the `called` facts of reachability evidence, dicts with `vuln_ids` (or "*" for all) and `sites`.
    """
    ids = {i.upper() for i in [f.vuln_id, *f.aliases] if i}
    return any(c.get("sites") and ("*" in c.get("vuln_ids", []) or ids & {v.upper() for v in c["vuln_ids"]})
               for c in called)


def cve_plannable(f: Finding) -> bool:
    """A CVE Guardian can try to fix: a fixed version exists and the package is npm or PyPI."""
    return (f.category is FindingCategory.CVE and bool(f.fixed_versions)
            and (f.component_purl or "").startswith(("pkg:npm/", "pkg:pypi/")))  # package.json / requirements*.txt


def is_direct(f: Finding) -> bool:
    """A dependency the project declares itself (path project -> package), or a finding with no dependency path.
    A transitive one (path longer than 2) can only be fixed through its parent, which is harder to get right.
    """
    return not f.dependency_paths or any(len(p) == 2 for p in f.dependency_paths)


def _pick_key(f: Finding, score: float) -> tuple:
    """Sort key for `select`: smaller sorts first. Deterministic, so two runs pick the same findings.

    Order: higher score, then direct dependency, then live manifest over a .bak backup, then content fields.
    """
    legacy = (f.file_path or "").endswith(".bak")  # a live manifest beats a shipped backup
    # highest risk first; on a tie a direct dependency first (one manifest edit, no parent upgrade to guess);
    # then content, never the random finding id
    return -score, not is_direct(f), legacy, f.title, f.component_purl or "", f.file_path or ""


def select(findings: list[Finding], limit: int, scores: dict[str, float] | None = None) -> list[Finding]:
    """The findings the remediation loop works on, highest risk score first.

    Every fixable finding competes on its score, so a Critical vulnerability is never passed over for a Medium
    supply-chain issue. At most one finding per package version (its fix is chosen to clear every advisory on
    that package, see remediation.cve_candidates) and one per supply-chain category (one fix covers them all).
    Args: findings - all findings; limit - max to choose (GUARDIAN_MAX_PLANS); scores - finding_id -> score.
    Escalated findings (invalid LLM output) are skipped: a human must look at those first.
    """
    scores = scores or {}
    ok = [f for f in findings if f.status is not FindingStatus.ESCALATED]
    chosen: list[Finding] = []
    seen: set[tuple[str, str]] = set()  # ("category", name) or ("package", purl) already represented in `chosen`
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
    """Ask the LLM to explain the scores of the top findings; returns {finding_id: (summary, claims)}.

    Returns {} (so the template summary stays) when there is no LLM, the token budget is spent (G3.6), the provider
    fails, or the output is invalid. The model is shown the computed score/band/factors and the cited evidence
    (as untrusted <data>, aliased ids) and told not to change the band: the band is forced back to the computed
    one (`raw.initial_risk = a.band.value`) before grounding, which verifies claims against the evidence (G4.x).
    Args: rc - run context; ranked - (finding, assessment) pairs, best first. Side effects: audit events, token use.
    """
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
    """Run the evidence-gathering tools for all findings in as few calls as possible.

    One batch call each for threat intel (all CVEs), reachability + exposure (per ecosystem), and package scope (all
    purls); the registry stores the Evidence. Returns the `Gathered` index. A failed tool just leaves its factor unknown.
    """
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    g = Gathered()

    def run_tool(name: str, args: dict):
        """Call one registry tool for the whole run and return its Evidence list ([] when the call failed)."""
        out = call_tool(AGENT, name, None, ctx, store, audit, args=args)
        return out.evidence if out else []

    cves = sorted({c for f in findings for c in cve_ids(f)})
    if cves:
        for e in run_tool("threat_intel", {"cves": cves}):
            (g.epss if e.kind == "epss" else g.kev)[e.facts["cve"]] = e
    # Ecosystems with an import scanner; others (e.g. nuget) skip this, so R stays unknown.
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
    """LangGraph node: score every finding, write risk.json, and choose what to remediate.

    Steps: gather evidence -> build factors and score each finding -> (provenance lookups for the top npm packages,
    then rescore) -> rank -> LLM summaries for the top LLM_TOP -> save risk.json -> select findings for remediation.
    Ties in the ranking are broken by content (title, purl, path, line), never by id: finding ids are ULIDs that
    differ between runs, which would make ranking and the LLM prompt non-reproducible.
    Args: state - graph state with `run_id` and `finding_ids`.
    Returns: state update with `plan_queue` (batch mode: all findings by rank; else the selected ones) and the reset
    loop counters. Side effects: tool calls, risk.json, chosen findings set to status PLANNED, audit events.
    """
    rc = get_ctx(state["run_id"])
    audit, store, ctx = rc.audit, rc.store, rc.tool_ctx
    findings = [f for f in (store.get_finding(i) for i in state.get("finding_ids", [])) if f]
    audit.emit(AGENT, "agent_start", f"Scoring {len(findings)} findings (S, E, R, P, X + provenance modifier)")
    pkgs = {f.finding_id: (None if f.category in NOT_APPLICABLE else package_of(f, store)) for f in findings}
    g = _collect(rc, findings, pkgs)

    def assess(f: Finding) -> RiskAssessment:
        """Score one finding: build its factors, compute the section-7 score/band/confidence, add the template summary."""
        factors = build_factors(f, pkgs[f.finding_id], g)
        c = compute(factors)
        a = RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band, confidence=c.confidence,
                           override_applied=c.override_applied, factors=factors, summary="")
        a.summary = template_summary(f, a)
        return a

    # First pass: every finding scored without provenance.
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
    # Count of unknown S/E/R/P factors across findings (X is excluded: it is unknown for most). Reported so the
    # summary says how much of the ranking rests on defaults.
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
    # Batch mode queues every finding in rank order; sequential mode queues only the chosen ones.
    queue = [a.finding_id for a in ranked] if batch else [f.finding_id for f in chosen]
    return {"status": "planning_loop", "plan_queue": queue, "current": None, "round": 0, "batch_id": None,
            "attempt": 0, "plan_id": None, "decision": None, "last_validation": None}
