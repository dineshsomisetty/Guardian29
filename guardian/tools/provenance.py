"""Provenance signals per package (D4-09).

Combines registry metadata (IntelClient.registry_metadata) with Dev2's `npm audit signatures`
result (passed in as a dict; this module never runs npm). Output is a Provenance-shaped dict
plus the inputs core/scoring.py needs for the provenance modifier.

status: verified | failed | unknown
"""
from __future__ import annotations


def _names(ms: list[dict] | None) -> set[str]:
    return {m.get("name", "") for m in ms or [] if m.get("name")}


def maintainer_changed(meta: dict) -> bool:
    cur, prev = _names(meta.get("latest_maintainers")), _names(meta.get("previous_maintainers"))
    return bool(cur and prev and cur != prev)


def provenance_for(meta: dict | None, audit: dict | None = None) -> dict:
    """audit: optional {"signature_verified": bool|None, "attestation_present": bool|None,
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

    status = "failed" if sig is False else "verified" if sig is True else "unknown"

    # Plan section 7: failed verification, or no repository + maintainer changed in latest release.
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
