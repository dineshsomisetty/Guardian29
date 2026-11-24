"""Provenance signals per package (D4-09).

Called by: tools/risk_tools.py (`provenance_signals`, risk analyst) and tools/package_risk.py (provenance gaps).
Combines registry metadata (IntelClient.registry_metadata, a trimmed packument) with Dev2's `npm audit signatures`
result (passed in as a dict; this module never runs npm and does no I/O or network).
Output: a Provenance-shaped dict, also used as Evidence `provenance` facts:
  status               verified | failed | unknown   (from the registry-signature audit)
  origin, integrity    passed through from the audit when present
  signature_verified   True / False / None (not audited)       attestation_present  True / None
  repository_url       the package's declared source repository, None if it has none
  maintainer_changed   latest release's maintainers differ from the previous release's
  score_modifier       True = failed -> becomes RiskFactors.provenance_failed in core/scoring.py
  provenance_gap       True = worth an Investigator look -> a provenance_gap finding
No registry data and no audit means status "unknown" and no gap: absence of data is not treated as evidence of risk.
"""
from __future__ import annotations


def _names(ms: list[dict] | None) -> set[str]:
    """Maintainer names from npm maintainer dicts, ignoring entries without a name."""
    return {m.get("name", "") for m in ms or [] if m.get("name")}


def maintainer_changed(meta: dict) -> bool:
    """True when the latest release's maintainer names differ from the previous release's. Needs both sets to be
    known; a first release or missing data is "no change" rather than a false alarm."""
    cur, prev = _names(meta.get("latest_maintainers")), _names(meta.get("previous_maintainers"))
    return bool(cur and prev and cur != prev)


def provenance_for(meta: dict | None, audit: dict | None = None) -> dict:
    """Provenance facts for one package (keys: see module docstring).

    meta: trimmed packument or None.
    audit: optional {"signature_verified": bool|None, "attestation_present": bool|None,
    "origin": str, "integrity": str} parsed from `npm audit signatures` evidence by Dev2."""
    audit = audit or {}
    repo = None
    if meta:
        r = meta.get("repository")
        repo = r.get("url") if isinstance(r, dict) else r
    sig = audit.get("signature_verified")
    att = audit.get("attestation_present")
    if att is None and meta is not None and meta.get("latest_attestations"):
        att = True
    changed = maintainer_changed(meta) if meta else False

    # status reflects the signature audit only; repository/maintainer signals feed `failed` and `gap` below
    status = "failed" if sig is False else "verified" if sig is True else "unknown"

    # Plan section 7: failed verification, or no repository + maintainer changed in latest release.
    # `failed` = hard signal (counts in scoring); `gap` = softer signal worth investigating (unknown status
    # and no declared repository, or any failure)
    failed = sig is False or (meta is not None and not repo and changed)
    gap = failed or (status == "unknown" and not repo and meta is not None)
    return {
        "status": status,
        "origin": audit.get("origin"),
        "integrity": audit.get("integrity"),
        "signature_verified": sig,
        "attestation_present": att,
        "repository_url": repo,
        "maintainer_changed": changed,
        "score_modifier": bool(failed),  # -> RiskFactors.provenance_failed
        "provenance_gap": bool(gap),     # -> emit a provenance_gap finding for the Investigator
    }
