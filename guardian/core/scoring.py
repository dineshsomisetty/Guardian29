"""Scoring (Dev4). CP1: initial-risk rule (D4-02). Full §7 score comes in D4-04.

CVSS bands: >= 9 critical, >= 7 high, >= 4 medium, else low. No CVSS -> scanner severity text.
Non-CVE category defaults follow the §7 S-factor ordering (typosquat/confusion/integrity high ...).
Dev-only scope lowers a CVE by one band (dev tooling does not ship to production).
"""

from __future__ import annotations

from guardian.core.models import Finding, FindingCategory, Priority, Scope

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
