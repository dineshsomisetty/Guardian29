# Document the contract for the surrounding module or callable.
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
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations


# Define _names for package provenance assessment.
# Inputs include ms.
def _names(ms: list[dict] | None) -> set[str]:
    # Document the contract for the surrounding module or callable.
    """Maintainer names from npm maintainer dicts, ignoring entries without a name."""
    # Return values selected or transformed from the input to the caller.
    return {m.get("name", "") for m in ms or [] if m.get("name")}


# Define maintainer_changed for package provenance assessment.
# Inputs include meta.
def maintainer_changed(meta: dict) -> bool:
    # Document the contract for the surrounding module or callable.
    """True when the latest release's maintainer names differ from the previous release's. Needs both sets to be
    known; a first release or missing data is "no change" rather than a false alarm."""
    # Store the expression on this line in (cur, prev).
    cur, prev = _names(meta.get("latest_maintainers")), _names(meta.get("previous_maintainers"))
    # Return the result of bool to the caller.
    return bool(cur and prev and cur != prev)


# Combine signature audit results and registry facts into provenance signals.
# Inputs include meta, audit.
def provenance_for(meta: dict | None, audit: dict | None = None) -> dict:
    # Document the contract for the surrounding module or callable.
    """Provenance facts for one package (keys: see module docstring).

    meta: trimmed packument or None.
    audit: optional {"signature_verified": bool|None, "attestation_present": bool|None,
    "origin": str, "integrity": str} parsed from `npm audit signatures` evidence by Dev2."""
    # Store audit or {} in audit.
    audit = audit or {}
    # Give repo its starting value.
    # The initial value is None to represent an absent value.
    repo = None
    # Check whether meta.
    if meta:
        # Store the result of meta.get in r.
        r = meta.get("repository")
        # Store r.get('url') if isinstance(r, dict) else r in repo.
        repo = r.get("url") if isinstance(r, dict) else r
    # Store the result of audit.get in sig.
    sig = audit.get("signature_verified")
    # Store the result of audit.get in att.
    att = audit.get("attestation_present")
    # Check whether the expression on this line.
    if att is None and meta is not None and meta.get("latest_attestations"):
        # Give att its starting value.
        # The initial value is True.
        att = True
    # Store maintainer_changed(meta) if meta else False in changed.
    changed = maintainer_changed(meta) if meta else False

    # status reflects the signature audit only; repository/maintainer signals feed `failed` and `gap` below
    # Store the expression on this line in status.
    status = "failed" if sig is False else "verified" if sig is True else "unknown"

    # Plan section 7: failed verification, or no repository + maintainer changed in latest release.
    # `failed` = hard signal (counts in scoring); `gap` = softer signal worth investigating (unknown status
    # and no declared repository, or any failure)
    # Store sig is False or (meta is not None and (not repo) and changed) in failed.
    failed = sig is False or (meta is not None and not repo and changed)
    # Store the expression on this line in gap.
    gap = failed or (status == "unknown" and not repo and meta is not None)
    # Return a mapping keyed by the fields below to the caller.
    return {
        # Provide the mapping fields status on this line.
        "status": status,
        # Provide the mapping fields origin on this line.
        "origin": audit.get("origin"),
        # Provide the mapping fields integrity on this line.
        "integrity": audit.get("integrity"),
        # Provide the mapping fields signature_verified on this line.
        "signature_verified": sig,
        # Provide the mapping fields attestation_present on this line.
        "attestation_present": att,
        # Provide the mapping fields repository_url on this line.
        "repository_url": repo,
        # Provide the mapping fields maintainer_changed on this line.
        "maintainer_changed": changed,
        # Provide the mapping fields score_modifier on this line.
        "score_modifier": bool(failed),  # -> RiskFactors.provenance_failed
        # Provide the mapping fields provenance_gap on this line.
        "provenance_gap": bool(gap),     # -> emit a provenance_gap finding for the Investigator
    # Close the current expression or collection.
    }
