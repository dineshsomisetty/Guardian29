"""Explainable risk scoring (D4-02 initial risk, D4-04 full score; plan section 7).

Pure functions. `Priority`/`Confidence` mirror the models in core/models.py; values are
plain strings so they compare equal to the Pydantic enums once Dev1's models land.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

WEIGHTS = {"S": 0.30, "E": 0.25, "R": 0.20, "P": 0.15, "X": 0.10}
PROVENANCE_BONUS = 5


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_ORDER = [Priority.LOW, Priority.MEDIUM, Priority.HIGH, Priority.CRITICAL]
_CONF_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]

# Factor S for non-CVE findings (plan section 7).
CATEGORY_SEVERITY = {
    "malicious_indicator": 1.0,
    "typosquat": 0.9,
    "dependency_confusion": 0.9,
    "integrity_change": 0.8,
    "install_script": 0.6,
    "unpinned_ci": 0.6,
    "maintainer_change": 0.6,
    "lockfile": 0.5,
    "untrusted_image": 0.5,
    "unexpected_change": 0.5,
    "major_jump": 0.5,
    "provenance_gap": 0.5,
    "policy_violation": 0.5,
    "outdated": 0.4,
}

# Day-1 initial risk defaults for non-CVE categories (D4-02).
CATEGORY_INITIAL_RISK = {
    "malicious_indicator": Priority.CRITICAL,
    "typosquat": Priority.HIGH,
    "dependency_confusion": Priority.HIGH,
    "integrity_change": Priority.HIGH,
    "install_script": Priority.MEDIUM,
    "unpinned_ci": Priority.MEDIUM,
    "maintainer_change": Priority.MEDIUM,
    "lockfile": Priority.MEDIUM,
    "untrusted_image": Priority.MEDIUM,
    "unexpected_change": Priority.MEDIUM,
    "major_jump": Priority.MEDIUM,
    "provenance_gap": Priority.MEDIUM,
    "policy_violation": Priority.MEDIUM,
    "outdated": Priority.LOW,
}

REACHABILITY = {
    "called": 1.0,
    "imported": 0.6,
    "unknown": 0.5,
    "not_imported": 0.1,
}
SCOPE = {"prod": 1.0, "dev": 0.3, "unknown": 0.7}
EXPOSURE = {"network": 1.0, "internal": 0.5, "unknown": 0.5}


def cvss_to_priority(cvss: float) -> Priority:
    if cvss >= 9.0:
        return Priority.CRITICAL
    if cvss >= 7.0:
        return Priority.HIGH
    if cvss >= 4.0:
        return Priority.MEDIUM
    return Priority.LOW


def initial_risk(category: str, cvss: float | None = None, severity: str | None = None) -> Priority:
    """Day-1 rule: CVSS bands for CVEs, category defaults otherwise."""
    if category == "cve":
        if cvss is not None:
            return cvss_to_priority(cvss)
        if severity:
            try:
                return Priority(severity.strip().lower())
            except ValueError:
                pass  # e.g. "negligible"/"unknown" fall through to the default
            if severity.strip().lower() == "moderate":
                return Priority.MEDIUM
        return Priority.MEDIUM  # no data: do not under-call
    return CATEGORY_INITIAL_RISK.get(category, Priority.MEDIUM)


def band(score: float) -> Priority:
    if score >= 80:
        return Priority.CRITICAL
    if score >= 60:
        return Priority.HIGH
    if score >= 40:
        return Priority.MEDIUM
    return Priority.LOW


@dataclass
class RiskFactors:
    category: str = "cve"
    cvss: float | None = None  # CVE only
    on_kev: bool = False
    epss_percentile: float | None = None  # 0..1
    malicious_evidence: bool = False  # non-CVE exploitability
    reachability: str = "unknown"  # called|imported|not_imported|unknown|not_applicable
    scope: str = "unknown"  # prod|dev|unknown
    exposure: str = "unknown"  # network|internal|unknown (may be LLM-inferred)
    provenance_failed: bool = False  # signature failed, or no repo + maintainer changed
    sources: dict[str, list[str]] = field(default_factory=dict)  # factor -> evidence ids


@dataclass
class FactorRow:
    name: str
    raw: str
    value: float
    weight: float
    contribution: float
    sources: list[str]


@dataclass
class RiskScore:
    score: float
    priority: Priority
    confidence: Confidence
    rows: list[FactorRow]
    provenance_bonus: int
    override_applied: bool
    unknown_factors: list[str]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "priority": self.priority.value,
            "confidence": self.confidence.value,
            "provenance_bonus": self.provenance_bonus,
            "override_applied": self.override_applied,
            "unknown_factors": self.unknown_factors,
            "factors": [
                {"name": r.name, "raw": r.raw, "value": r.value, "weight": r.weight,
                 "contribution": r.contribution, "sources": r.sources}
                for r in self.rows
            ],
        }


def compute(f: RiskFactors) -> RiskScore:
    is_cve = f.category == "cve"
    unknown: list[str] = []

    # S: severity
    if is_cve:
        if f.cvss is None:
            s, s_raw = 0.5, "no CVSS"
            unknown.append("S")
        else:
            s, s_raw = max(0.0, min(f.cvss, 10.0)) / 10, f"CVSS {f.cvss}"
    else:
        s, s_raw = CATEGORY_SEVERITY.get(f.category, 0.5), f"category {f.category}"

    # E: exploitability
    if f.on_kev:
        e, e_raw = 1.0, "on CISA KEV"
    elif is_cve:
        if f.epss_percentile is None:
            e, e_raw = 0.5, "no EPSS"
            unknown.append("E")
        else:
            e, e_raw = max(0.0, min(f.epss_percentile, 1.0)), f"EPSS percentile {f.epss_percentile:.2f}"
    else:
        e = 1.0 if f.malicious_evidence else 0.5
        e_raw = "malicious evidence" if f.malicious_evidence else "no exploit evidence"

    # R: reachability; not_applicable moves its weight onto S
    w = dict(WEIGHTS)
    if f.reachability == "not_applicable":
        w["S"] += w["R"]
        w["R"] = 0.0
        r, r_raw = 0.0, "not applicable (weight moved to S)"
    else:
        r = REACHABILITY.get(f.reachability, 0.5)
        r_raw = f.reachability
        if f.reachability not in REACHABILITY or f.reachability == "unknown":
            unknown.append("R")

    p = SCOPE.get(f.scope, 0.7)
    if f.scope not in ("prod", "dev"):
        unknown.append("P")

    x = EXPOSURE.get(f.exposure, 0.5)  # unknown X does not lower confidence

    vals = {"S": (s, s_raw), "E": (e, e_raw), "R": (r, r_raw), "P": (p, f.scope), "X": (x, f.exposure)}
    rows = [
        FactorRow(k, raw, v, w[k], round(100 * w[k] * v, 2), f.sources.get(k, []))
        for k, (v, raw) in vals.items()
    ]
    score = sum(100 * w[k] * v for k, (v, _) in vals.items())

    bonus = PROVENANCE_BONUS if f.provenance_failed else 0
    score = min(100.0, score + bonus)
    score = round(score, 2)
    priority = band(score)

    override = False
    reachable = f.reachability in ("called", "imported")
    if f.on_kev and reachable and f.scope == "prod" and _ORDER.index(priority) < _ORDER.index(Priority.HIGH):
        priority, override = Priority.HIGH, True

    conf_idx = len(_CONF_ORDER) - 1 - len(unknown)
    confidence = _CONF_ORDER[max(0, conf_idx)]

    return RiskScore(score, priority, confidence, rows, bonus, override, unknown)
