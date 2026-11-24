# Document the contract for the surrounding module or callable.
"""Deterministic initial-risk rules (D4-02) and full evidence-backed risk scoring (D4-04).

Two layers live here, both pure code (no LLM, no I/O), so any number in the UI or report can be recomputed:

1. Initial risk (`initial_risk`): a quick band for every finding right after detection, used as the fallback
   when the evidence analyst LLM is unavailable and as the starting point shown in the findings list.
   CVSS bands: >= 9 critical, >= 7 high, >= 4 medium, else low. No CVSS -> scanner severity text.
   Non-CVE category defaults follow the §7 S-factor ordering (typosquat/confusion/integrity high ...).
   Dev-only scope lowers a CVE by one band (dev tooling does not ship to production).

2. Full risk score (`compute`, plan §7), computed by the risk analyst from five factors, each in 0..1:
       S severity      CVSS/10 for a CVE; fixed per-category value for non-CVE findings (CATEGORY_SEVERITY)
       E exploitability 1.0 if listed in CISA KEV, else the EPSS percentile; 0.5 when unknown
       R reachability  called 1.0 > imported 0.6 > unknown 0.5 > not_imported 0.1; not_applicable 0.0
       P production    prod 1.0, unknown 0.7, dev 0.3
       X exposure      network 1.0; internal or unknown 0.5
   score = 100 * (0.40*S + 0.15*E + 0.20*R + 0.15*P + 0.10*X) + provenance_modifier, capped at 100.
   The provenance modifier is a flat +PROVENANCE_BONUS (5) points, applied only when the provenance check
   failed (the package may not come from its claimed publisher); it is 0 otherwise.
   Band thresholds: >= 80 critical, >= 60 high, >= 40 medium, else low.
   not_applicable weight move: CI, lockfile and image findings have no code to reach, so R is "not_applicable"
   and its 0.20 weight is added to S (S weighs 0.60, R 0): otherwise 20% of the score would be spent on a factor
   that cannot exist for them, and these findings would be under-ranked.
   KEV override: a KEV-listed finding that is reachable (called/imported) in production code is raised to at
   least HIGH even if the weighted score is lower ("kev_reachable_prod"), because known-exploited and
   reachable is urgent regardless of CVSS. The score itself is not changed, only the band.
   Confidence: starts at HIGH and drops one level per unknown factor among S, E, R, P (X is excluded because
   exposure is rarely knowable from a repository); floor LOW.
"""

# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Import dataclass from dataclasses.
from dataclasses import dataclass

# Import ClaimLabel, Confidence, FactorValue, Finding, FindingCategory, Priority, RiskAssessment, RiskFactors, Scope from guardian.core.models.
from guardian.core.models import (
    # Supply the next part of the expression started above.
    ClaimLabel,
    # Supply the next part of the expression started above.
    Confidence,
    # Supply the next part of the expression started above.
    FactorValue,
    # Supply the next part of the expression started above.
    Finding,
    # Supply the next part of the expression started above.
    FindingCategory,
    # Supply the next part of the expression started above.
    Priority,
    # Supply the next part of the expression started above.
    RiskAssessment,
    # Supply the next part of the expression started above.
    RiskFactors,
    # Supply the next part of the expression started above.
    Scope,
# Close the current expression or collection.
)

# Bands from lowest to highest; the index is used to lower a band (dev scope) or compare it (KEV override).
# Store an ordered collection in _ORDER.
_ORDER = [Priority.LOW, Priority.MEDIUM, Priority.HIGH, Priority.CRITICAL]

# Initial band for non-CVE categories (CVEs are banded by CVSS instead). Mirrors CATEGORY_SEVERITY below.
# Store a mapping keyed by the fields below in CATEGORY_DEFAULT.
CATEGORY_DEFAULT = {
    # Supply the next part of the expression started above.
    FindingCategory.MALICIOUS_INDICATOR: Priority.CRITICAL,
    # Supply the next part of the expression started above.
    FindingCategory.TYPOSQUAT: Priority.HIGH,
    # Supply the next part of the expression started above.
    FindingCategory.DEPENDENCY_CONFUSION: Priority.HIGH,
    # Supply the next part of the expression started above.
    FindingCategory.INTEGRITY_CHANGE: Priority.HIGH,
    # Supply the next part of the expression started above.
    FindingCategory.INSTALL_SCRIPT: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.UNPINNED_CI: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.MAINTAINER_CHANGE: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.LOCKFILE: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.UNTRUSTED_IMAGE: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.UNEXPECTED_CHANGE: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.MAJOR_JUMP: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.PROVENANCE_GAP: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.POLICY_VIOLATION: Priority.MEDIUM,
    # Supply the next part of the expression started above.
    FindingCategory.OUTDATED: Priority.LOW,
# Close the current expression or collection.
}

# Scanner severity words -> band, used when a CVE has no CVSS number (grype says "negligible", GitHub "moderate").
# Store a mapping keyed by the fields below in _SEVERITY.
_SEVERITY = {"critical": Priority.CRITICAL, "high": Priority.HIGH, "medium": Priority.MEDIUM,
             # Provide the mapping fields moderate, low, negligible on this line.
             "moderate": Priority.MEDIUM, "low": Priority.LOW, "negligible": Priority.LOW}


# Define cvss_band for risk scoring.
# Inputs include cvss.
def cvss_band(cvss: float) -> Priority:
    # Document the contract for the surrounding module or callable.
    """Standard CVSS v3 severity bands: 9.0+ critical, 7.0+ high, 4.0+ medium, below that low."""
    # Check whether cvss >= 9.
    if cvss >= 9:
        # Return Priority.CRITICAL to the caller.
        return Priority.CRITICAL
    # Check whether cvss >= 7.
    if cvss >= 7:
        # Return Priority.HIGH to the caller.
        return Priority.HIGH
    # Check whether cvss >= 4.
    if cvss >= 4:
        # Return Priority.MEDIUM to the caller.
        return Priority.MEDIUM
    # Return Priority.LOW to the caller.
    return Priority.LOW


# Define _lower for risk scoring.
# Inputs include p.
def _lower(p: Priority) -> Priority:
    # Document the contract for the surrounding module or callable.
    """One band down, stopping at LOW."""
    # Return _ORDER[max(0, _ORDER.index(p) - 1)] to the caller.
    return _ORDER[max(0, _ORDER.index(p) - 1)]


# Define initial_risk for risk scoring.
# Inputs include f.
def initial_risk(f: Finding) -> Priority:
    # Document the contract for the surrounding module or callable.
    """Rule-based first-pass band of a finding: CVSS (or scanner severity) for a CVE, lowered one band when
    the component is dev-only; the category default for everything else. Medium when nothing is known."""
    # Check whether f.category is FindingCategory.CVE.
    if f.category is FindingCategory.CVE:
        # Check whether f.cvss is not None.
        if f.cvss is not None:
            # Store the result of cvss_band in p.
            p = cvss_band(f.cvss)
        # Supply the alternative for the preceding condition.
        # This path covers the case where the earlier branch does not apply.
        else:
            # Store the result of _SEVERITY.get in p.
            p = _SEVERITY.get((f.severity or "").lower(), Priority.MEDIUM)
        # Return _lower(p) if f.scope is Scope.DEV else p to the caller.
        return _lower(p) if f.scope is Scope.DEV else p
    # Return the result of CATEGORY_DEFAULT.get to the caller.
    return CATEGORY_DEFAULT.get(f.category, Priority.MEDIUM)


# ---------------------------------------------------------------- full risk score (D4-04, plan section 7)
#
# Pure functions over the pydantic `RiskFactors` of core/models.py. The risk analyst builds the factors from
# tool evidence in code; `compute` is the only place a score, band, override and confidence are derived, so
# anyone can recompute them from risk.json (the report prints the same factor table).

# Store a mapping keyed by the fields below in WEIGHTS.
WEIGHTS = {"S": 0.40, "E": 0.15, "R": 0.20, "P": 0.15, "X": 0.10}  # sum = 1.0; severity and exploitability lead
# Give PROVENANCE_BONUS its starting value.
# The initial value is 5.0.
PROVENANCE_BONUS = 5.0  # points added to the 0-100 score when the provenance check failed

# Factor S for non-CVE findings (plan section 7).
# Store a mapping keyed by the fields below in CATEGORY_SEVERITY.
CATEGORY_SEVERITY = {
    # Supply the next part of the expression started above.
    FindingCategory.MALICIOUS_INDICATOR: 1.0,
    # Supply the next part of the expression started above.
    FindingCategory.TYPOSQUAT: 0.9,
    # Supply the next part of the expression started above.
    FindingCategory.DEPENDENCY_CONFUSION: 0.9,
    # Supply the next part of the expression started above.
    FindingCategory.INTEGRITY_CHANGE: 0.8,
    # Supply the next part of the expression started above.
    FindingCategory.INSTALL_SCRIPT: 0.6,
    # Supply the next part of the expression started above.
    FindingCategory.UNPINNED_CI: 0.6,
    # Supply the next part of the expression started above.
    FindingCategory.MAINTAINER_CHANGE: 0.6,
    # Supply the next part of the expression started above.
    FindingCategory.LOCKFILE: 0.5,
    # Supply the next part of the expression started above.
    FindingCategory.UNTRUSTED_IMAGE: 0.5,
    # Supply the next part of the expression started above.
    FindingCategory.UNEXPECTED_CHANGE: 0.5,
    # Supply the next part of the expression started above.
    FindingCategory.MAJOR_JUMP: 0.5,
    # Supply the next part of the expression started above.
    FindingCategory.PROVENANCE_GAP: 0.5,
    # Supply the next part of the expression started above.
    FindingCategory.POLICY_VIOLATION: 0.5,
    # Supply the next part of the expression started above.
    FindingCategory.OUTDATED: 0.4,
# Close the current expression or collection.
}
# Tier -> heuristic factor value. Missing evidence is not evidence of safety.
# These defaults are ranking choices, not probabilities; unknown scope uses 0.7,
# while unknown reachability/exposure use 0.5. build_factors marks the unknowns.
# Store a mapping keyed by the fields below in REACHABILITY.
REACHABILITY = {"called": 1.0, "imported": 0.6, "unknown": 0.5, "not_imported": 0.1, "not_applicable": 0.0}
# Store a mapping keyed by the fields below in SCOPE.
SCOPE = {"prod": 1.0, "dev": 0.3, "unknown": 0.7}
# Store a mapping keyed by the fields below in EXPOSURE.
EXPOSURE = {"network": 1.0, "internal": 0.5, "unknown": 0.5}
# Store an ordered collection in _CONF.
_CONF = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


# Define band for risk scoring.
# Inputs include score.
def band(score: float) -> Priority:
    # Document the contract for the surrounding module or callable.
    """Map a 0-100 score to a band: >= 80 critical, >= 60 high, >= 40 medium, else low."""
    # Check whether score >= 80.
    if score >= 80:
        # Return Priority.CRITICAL to the caller.
        return Priority.CRITICAL
    # Check whether score >= 60.
    if score >= 60:
        # Return Priority.HIGH to the caller.
        return Priority.HIGH
    # Check whether score >= 40.
    if score >= 40:
        # Return Priority.MEDIUM to the caller.
        return Priority.MEDIUM
    # Return Priority.LOW to the caller.
    return Priority.LOW


# Define factor for risk scoring.
# Inputs include value, tier, evidence_ids, unknown, label.
def factor(value: float, tier: str, evidence_ids: list[str] | None = None, *, unknown: bool = False,
           # Continue the function signature with its remaining arguments.
           label: ClaimLabel | None = None) -> FactorValue:
    # Document the contract for the surrounding module or callable.
    """Build a FactorValue. `tier` names why the value was chosen; `evidence_ids` (de-duplicated, order kept)
    support it. The label defaults to VERIFIED when evidence backs the value and it is not a guess, else INFERRED.
    INFERRED can therefore mean a deterministic missing-data default; it does not imply an LLM chose the value.
    """
    # Store the result of list in ids.
    ids = list(dict.fromkeys(evidence_ids or []))
    # Return the result of FactorValue to the caller.
    return FactorValue(value=round(value, 4), tier=tier, unknown=unknown, evidence_ids=ids,
                       # Supply label as named arguments to the surrounding call.
                       # These names connect the values to the receiving parameters.
                       label=label or (ClaimLabel.INFERRED if unknown or not ids else ClaimLabel.VERIFIED))


# Define weights_for for risk scoring.
# Inputs include f.
def weights_for(f: RiskFactors) -> dict[str, float]:
    # Document the contract for the surrounding module or callable.
    """The weights to use for these factors: WEIGHTS, except that a not_applicable R gives its weight to S."""
    # Store the result of dict in w.
    w = dict(WEIGHTS)
    # Check whether f.R.tier == 'not_applicable'.
    if f.R.tier == "not_applicable":  # CI / lockfile / image findings: the R weight moves onto S
        # Update the existing value of w['S'].
        # The update incorporates w['R'].
        w["S"] += w["R"]
        # Give w['R'] its starting value.
        # The initial value is 0.0.
        w["R"] = 0.0
    # Return w to the caller.
    return w


# Apply the dataclass decorator to the declaration below.
@dataclass(frozen=True)
# Define Computed for risk scoring.
# Group the related fields or methods under this type.
class Computed:
    # Document the contract for the surrounding module or callable.
    """Result of `compute`: score (0-100), band (after any override), confidence, the override's name if one
    applied, the weights actually used and each factor's contribution in points.
    Contributions are rounded separately and are computed before the final 100-point cap;
    adding them to the provenance modifier need not exactly equal the capped final score.
    """

    # Declare score with type float.
    # The caller or container supplies the value.
    score: float
    # Declare band with type Priority.
    # The caller or container supplies the value.
    band: Priority
    # Declare confidence with type Confidence.
    # The caller or container supplies the value.
    confidence: Confidence
    # Declare override_applied with type str | None.
    # The caller or container supplies the value.
    override_applied: str | None
    # Declare weights with type dict[str, float].
    # The caller or container supplies the value.
    weights: dict[str, float]
    # Declare contributions with type dict[str, float].
    # The caller or container supplies the value.
    contributions: dict[str, float]


# Combine weighted factor values and determine the score, priority, and confidence.
# Inputs include f.
def compute(f: RiskFactors) -> Computed:
    # Document the contract for the surrounding module or callable.
    """Derive score, band, KEV override and confidence from the supplied factors.

    Evidence lookup and normalization belong to agents/risk_analyst.py:build_factors.
    This function does no network/model calls. The score is a prioritization heuristic,
    not an exploitation probability, and confidence records missing inputs separately.
    """
    # Store the result of weights_for in w.
    w = weights_for(f)
    # Store a lookup built from the input records in vals.
    vals = {k: getattr(f, k).value for k in WEIGHTS}
    # Store a lookup built from the input records in contrib.
    contrib = {k: round(100 * w[k] * vals[k], 2) for k in WEIGHTS}
    # Store the result of round in score.
    score = round(min(100.0, 100 * sum(w[k] * vals[k] for k in WEIGHTS) + f.provenance_modifier), 2)
    # Store the result of band in b.
    b = band(score)
    # Give override its starting value.
    # The initial value is None to represent an absent value.
    override = None
    # KEV-listed + reachable + production: never below HIGH (only ever raises the band, never lowers it)
    # Check whether the expression on this line.
    # Apply this additional term to the condition.
    # The combined condition controls whether the branch runs.
    if f.E.tier == "kev" and f.R.tier in ("called", "imported") and f.P.tier == "prod" \
            and _ORDER.index(b) < _ORDER.index(Priority.HIGH):
        # Store (Priority.HIGH, 'kev_reachable_prod') in (b, override).
        b, override = Priority.HIGH, "kev_reachable_prod"
    # Store the result of sum in unknown.
    unknown = sum(1 for k in ("S", "E", "R", "P") if getattr(f, k).unknown)  # X never lowers confidence
    # Store _CONF[max(0, len(_CONF) - 1 - unknown)] in conf.
    conf = _CONF[max(0, len(_CONF) - 1 - unknown)]
    # Return the result of Computed to the caller.
    return Computed(score, b, conf, override, w, contrib)


# Define simulate_after for risk scoring.
# Inputs include assessment, action.
def simulate_after(assessment: RiskAssessment | None, action: str) -> tuple[float, Priority]:
    # Document the contract for the surrounding module or callable.
    """Expected score once the plan is applied and validated (not written by the LLM).

    Actions that remove the risky component or setting resolve the finding (score 0). `mitigate` keeps the
    component but moves X to internal; `escalate` changes nothing."""
    # Check whether assessment is None.
    if assessment is None:
        # Return (0.0, Priority.LOW) to the caller.
        return 0.0, Priority.LOW
    # Check whether action == 'escalate'.
    if action == "escalate":
        # Return (assessment.score, assessment.band) to the caller.
        return assessment.score, assessment.band
    # Check whether action == 'mitigate'.
    if action == "mitigate":
        # Store the result of assessment.factors.model_copy in f.
        f = assessment.factors.model_copy(update={"X": factor(0.5, "internal", [], unknown=True)})
        # Store the result of compute in c.
        c = compute(f)
        # Return (c.score, c.band) to the caller.
        return c.score, c.band
    # Return (0.0, Priority.LOW) to the caller.
    return 0.0, Priority.LOW
