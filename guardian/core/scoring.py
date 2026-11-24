"""Scoring (Dev4). CP1: initial-risk rule (D4-02). Full §7 score comes in D4-04.

CVSS bands: >= 9 critical, >= 7 high, >= 4 medium, else low. No CVSS -> scanner severity text.
Non-CVE category defaults follow the §7 S-factor ordering (typosquat/confusion/integrity high ...).
Dev-only scope lowers a CVE by one band (dev tooling does not ship to production).
"""

from __future__ import annotations

from dataclasses import dataclass

from guardian.core.models import (
    ClaimLabel,
    Confidence,
    FactorValue,
    Finding,
    FindingCategory,
    Priority,
    RiskAssessment,
    RiskFactors,
    Scope,
)

_ORDER = [Priority.LOW, Priority.MEDIUM, Priority.HIGH, Priority.CRITICAL]

CATEGORY_DEFAULT = {
    FindingCategory.MALICIOUS_INDICATOR: Priority.CRITICAL,
    FindingCategory.TYPOSQUAT: Priority.HIGH,
    FindingCategory.DEPENDENCY_CONFUSION: Priority.HIGH,
    FindingCategory.INTEGRITY_CHANGE: Priority.HIGH,
    FindingCategory.INSTALL_SCRIPT: Priority.MEDIUM,
    FindingCategory.UNPINNED_CI: Priority.MEDIUM,
    FindingCategory.MAINTAINER_CHANGE: Priority.MEDIUM,
    FindingCategory.LOCKFILE: Priority.MEDIUM,
    FindingCategory.UNTRUSTED_IMAGE: Priority.MEDIUM,
    FindingCategory.UNEXPECTED_CHANGE: Priority.MEDIUM,
    FindingCategory.MAJOR_JUMP: Priority.MEDIUM,
    FindingCategory.PROVENANCE_GAP: Priority.MEDIUM,
    FindingCategory.POLICY_VIOLATION: Priority.MEDIUM,
    FindingCategory.OUTDATED: Priority.LOW,
}

_SEVERITY = {"critical": Priority.CRITICAL, "high": Priority.HIGH, "medium": Priority.MEDIUM,
             "moderate": Priority.MEDIUM, "low": Priority.LOW, "negligible": Priority.LOW}


def cvss_band(cvss: float) -> Priority:
    if cvss >= 9:
        return Priority.CRITICAL
    if cvss >= 7:
        return Priority.HIGH
    if cvss >= 4:
        return Priority.MEDIUM
    return Priority.LOW


def _lower(p: Priority) -> Priority:
    return _ORDER[max(0, _ORDER.index(p) - 1)]


def initial_risk(f: Finding) -> Priority:
    if f.category is FindingCategory.CVE:
        if f.cvss is not None:
            p = cvss_band(f.cvss)
        else:
            p = _SEVERITY.get((f.severity or "").lower(), Priority.MEDIUM)
        return _lower(p) if f.scope is Scope.DEV else p
    return CATEGORY_DEFAULT.get(f.category, Priority.MEDIUM)


# ---------------------------------------------------------------- full risk score (D4-04, plan section 7)
#
# Pure functions over the pydantic `RiskFactors` of core/models.py. The risk analyst builds the factors from
# tool evidence in code; `compute` is the only place a score, band, override and confidence are derived, so
# anyone can recompute them from risk.json (the report prints the same factor table).

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
