# Document the contract for the surrounding module or callable.
"""Advanced package risk from registry metadata (D4-10, stretch; ported from dev04 and extended).

Called by: tools/detectors/package_risk.py (the detection agent's `package_risk` tool), which fetches the
trimmed packuments and passes them in. Everything here is a pure function over a trimmed packument (the dict
produced by threat_intel.trim_packument), so unit tests need no network and the module never does I/O.
Rules (each returns facts that become Evidence `registry_metadata` facts in the detector):
  * maintainer change     the latest release has a completely different maintainer set than the one before
  * unusual release activity  burst of releases, very recent release, very young package
  * dependency confusion  names under an internal scope/name from guardian.yaml that also exist publicly
  * provenance gaps       registry/audit signals from tools/provenance.py; "peers" = the other packages checked
Missing metadata (offline cache miss, unpublished package) simply produces no facts: no finding, no guess.
Thresholds come from guardian.yaml `thresholds` merged over DEFAULTS.
"""
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Import UTC, datetime, timedelta from datetime.
from datetime import UTC, datetime, timedelta

# Import maintainer_changed, provenance_for from guardian.tools.provenance.
from guardian.tools.provenance import maintainer_changed, provenance_for

# Defaults for guardian.yaml thresholds:
#   release_burst_versions / release_burst_days  this many stable releases inside this many days = a burst
#   release_burst_recent_days  only bursts within the last N days matter (old history is not a current signal)
#   new_version_days           a release this recent is "very recent"
#   min_package_age_days       a package younger than this is "very young" (typosquats/attacks are new packages)
# Store a mapping keyed by the fields below in DEFAULTS.
DEFAULTS = {"release_burst_versions": 5, "release_burst_days": 7, "new_version_days": 3, "min_package_age_days": 7,
            # Provide the mapping fields release_burst_recent_days on this line.
            "release_burst_recent_days": 90}
# Give PEER_MIN its starting value.
# The initial value is 3.
PEER_MIN = 3  # peers that must have a signal before its absence counts as a gap
# Give PEER_SHARE its starting value.
# The initial value is 0.5.
PEER_SHARE = 0.5  # ...and at least this fraction of the other checked packages must carry it


# Define _ts for registry-based package risk checks.
# Inputs include s.
def _ts(s: str) -> datetime | None:
    # Document the contract for the surrounding module or callable.
    """Parse an npm registry ISO timestamp (trailing Z allowed); None if missing or malformed."""
    # Run the following operation with exception handling.
    # The handlers below determine how the listed failures are handled.
    try:
        # Return the result of datetime.fromisoformat to the caller.
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    # Handle (ValueError, AttributeError) from the preceding block.
    except (ValueError, AttributeError):
        # Return None to represent an absent value to the caller.
        return None


# Summarize clustered releases and recent publishing activity.
# Inputs include meta, thresholds, now.
def release_activity(meta: dict, thresholds: dict | None = None, now: datetime | None = None) -> list[dict]:
    # Document the contract for the surrounding module or callable.
    """Unusual-release-activity signals for one package: [{rule: release_burst | very_recent_release |
    very_young_package, ...details}], empty when normal.

    `thresholds` overrides DEFAULTS (None values ignored); `now` is injectable for tests. A lone
    very_recent_release is dropped because a fresh release is routine for an active project; it is only kept
    as context next to a real signal."""
    # Store a mapping keyed by the fields below in c.
    c = {**DEFAULTS, **{k: v for k, v in (thresholds or {}).items() if v is not None}}
    # Store now or datetime.now(UTC) in now.
    now = now or datetime.now(UTC)
    # Store meta.get('time') or {} in t.
    t = meta.get("time") or {}
    # all publish times except registry bookkeeping keys (created/modified/unpublished are not versions)
    # Store the result of sorted in times.
    times = sorted(dt for k, v in t.items() if k not in ("created", "modified", "unpublished") and (dt := _ts(v)))
    # stable releases only: big projects publish -next/-rc builds daily, which is their normal cadence
    # Store the result of sorted in stable.
    stable = sorted(dt for k, v in t.items()
                    # Use this clause to iterate or filter the surrounding expression.
                    # The collection includes the results of the completed expression.
                    if k not in ("created", "modified", "unpublished") and "-" not in k and (dt := _ts(v)))
    # Store an ordered collection in out.
    out = []
    # Store the expression on this line in (n, d).
    n, d = int(c["release_burst_versions"]), timedelta(days=c["release_burst_days"])
    # Store the result of timedelta in window.
    window = timedelta(days=c["release_burst_recent_days"])
    # only a *recent* burst, and only for a package that normally releases less than weekly, is a signal
    # Store values selected or transformed from the input in recent.
    recent = [x for x in stable if now - x <= window]
    # the 365 days before the recent window: used to tell a normally busy package from a sudden burst
    # Store values selected or transformed from the input in year_before.
    year_before = [x for x in stable if window < now - x <= window + timedelta(days=365)]
    # Check whether len(year_before) >= 52.
    if len(year_before) >= 52:
        # Store an ordered collection in recent.
        recent = []  # a package that already releases weekly or faster: a busy week is normal for it
    # Iterate over range(len(recent) - n + 1).
    # Bind each item to i before processing it.
    for i in range(len(recent) - n + 1):  # sliding window: n consecutive releases within d days
        # Check whether recent[i + n - 1] - recent[i] <= d.
        if recent[i + n - 1] - recent[i] <= d:
            # Call out.append at this point.
            out.append({"rule": "release_burst", "versions": n, "window_days": c["release_burst_days"],
                        # Provide the mapping fields start on this line.
                        "start": recent[i].date().isoformat()})
            # Stop the current loop here.
            break
    # Check whether the expression on this line.
    if times and now - times[-1] <= timedelta(days=c["new_version_days"]):
        # Call out.append at this point.
        out.append({"rule": "very_recent_release", "published": times[-1].date().isoformat(),
                    # Provide the mapping fields days_ago on this line.
                    "days_ago": (now - times[-1]).days})
    # Store the result of _ts in created.
    created = _ts(t.get("created", ""))
    # Check whether the expression on this line.
    if created and now - created < timedelta(days=c["min_package_age_days"]):
        # Call out.append at this point.
        out.append({"rule": "very_young_package", "created": created.date().isoformat(),
                    # Provide the mapping fields age_days on this line.
                    "age_days": (now - created).days})
    # a fresh release alone is routine for active projects: keep it only as context for a real signal
    # Check whether [a['rule'] for a in out] == ['very_recent_release'].
    if [a["rule"] for a in out] == ["very_recent_release"]:
        # Return an ordered collection to the caller.
        return []
    # Return out to the caller.
    return out


# Define _maintainer_names for registry-based package risk checks.
# Inputs include people.
def _maintainer_names(people) -> set[str]:
    # Document the contract for the surrounding module or callable.
    """Lowercased maintainer identifiers (name, else email) from npm maintainer dicts or plain strings."""
    # Return the expression on this line to the caller.
    return {(p.get("name") or p.get("email") or "").lower() if isinstance(p, dict) else str(p).lower()
            # Use this clause to iterate or filter the surrounding expression.
            # The collection includes the results of the completed expression.
            for p in people or []} - {""}


# Define maintainer_facts for registry-based package risk checks.
# Inputs include meta.
def maintainer_facts(meta: dict) -> dict | None:
    # Document the contract for the surrounding module or callable.
    """Only a full takeover is a finding: the latest release's maintainers share nobody with the previous
    release's. Ordinary rotation (someone added or removed) is normal and would only add noise."""
    # Check whether not maintainer_changed(meta).
    if not maintainer_changed(meta):
        # Return None to represent an absent value to the caller.
        return None
    # Store the expression on this line in (cur, prev).
    cur, prev = _maintainer_names(meta.get("latest_maintainers")), _maintainer_names(meta.get("previous_maintainers"))
    # Check whether not cur or not prev or cur & prev.
    if not cur or not prev or cur & prev:
        # Return None to represent an absent value to the caller.
        return None
    # Return a mapping keyed by the fields below to the caller.
    return {"previous": meta.get("previous_maintainers"), "latest": meta.get("latest_maintainers"),
            # Provide the mapping fields latest_version on this line.
            "latest_version": meta.get("latest")}


# Define _has for registry-based package risk checks.
# Inputs include meta, key.
def _has(meta: dict, key: str) -> bool:
    # Document the contract for the surrounding module or callable.
    """True when the packument has a non-empty value for `key` (e.g. latest_signatures)."""
    # Return the result of bool to the caller.
    return bool(meta.get(key))


# Define provenance_gaps for registry-based package risk checks.
# Inputs include metas.
def provenance_gaps(metas: dict[str, dict]) -> dict[str, dict]:
    # Document the contract for the surrounding module or callable.
    """purl -> {reasons: [...], provenance: <provenance_for output>, peers: {...}} for packages with a gap.

    Reasons: `no_repository_and_maintainer_changed` (plan section 7) and `signature_missing_peers_have` /
    `attestation_missing_peers_have` (>= PEER_MIN of the other checked packages, >= PEER_SHARE of them, carry it)."""
    # Store the result of len in n.
    n = len(metas)  # packages checked in this run (the peer group)
    # Store the result of sum in sig_peers.
    sig_peers = sum(1 for m in metas.values() if _has(m, "latest_signatures"))
    # Store the result of sum in att_peers.
    att_peers = sum(1 for m in metas.values() if _has(m, "latest_attestations"))
    # Declare out with type dict[str, dict].
    # Use a mapping keyed by the fields below as its initial value.
    out: dict[str, dict] = {}
    # Iterate over metas.items().
    # Bind each item to (purl, meta) before processing it.
    for purl, meta in metas.items():
        # Store the result of provenance_for in prov.
        prov = provenance_for(meta)
        # Store an ordered collection in reasons.
        reasons = []
        # Check whether not prov['repository_url'] and prov['maintainer_changed'].
        if not prov["repository_url"] and prov["maintainer_changed"]:
            # Call reasons.append at this point.
            reasons.append("no_repository_and_maintainer_changed")
        # Store the result of max in others.
        others = max(n - 1, 0)  # peers excluding this package
        # peers with the signal = group total minus this package itself
        # Store sig_peers - (1 if _has(meta, 'latest_signatures') else 0) in sig_others.
        sig_others = sig_peers - (1 if _has(meta, "latest_signatures") else 0)
        # Store att_peers - (1 if _has(meta, 'latest_attestations') else 0) in att_others.
        att_others = att_peers - (1 if _has(meta, "latest_attestations") else 0)
        # absence only matters when the ecosystem norm in this repo is to have it (a lone unsigned package among
        # unsigned peers is not suspicious)
        # Check whether the expression on this line.
        if not _has(meta, "latest_signatures") and sig_others >= PEER_MIN and sig_others >= PEER_SHARE * others:
            # Call reasons.append at this point.
            reasons.append("signature_missing_peers_have")
        # Check whether the expression on this line.
        if not _has(meta, "latest_attestations") and att_others >= PEER_MIN and att_others >= PEER_SHARE * others:
            # Call reasons.append at this point.
            reasons.append("attestation_missing_peers_have")
        # Check whether reasons.
        if reasons:
            # Store a mapping keyed by the fields below in out[purl].
            out[purl] = {"reasons": reasons, "provenance": prov,
                         # Provide the mapping fields peers, with_signatures, with_attestations on this line.
                         "peers": {"checked": n, "with_signatures": sig_others, "with_attestations": att_others}}
    # Return out to the caller.
    return out


# Define matches_internal for registry-based package risk checks.
# Inputs include name, internal.
def matches_internal(name: str, internal: list[str]) -> bool:
    # Document the contract for the surrounding module or callable.
    """True if `name` is under one of the organisation's internal names. `internal` entries are scopes
    ("@acme", "@acme/") or exact package names (guardian.yaml internal_scopes)."""
    # Iterate over internal.
    # Bind each item to s before processing it.
    for s in internal:
        # Store the result of str(s).rstrip in s.
        s = str(s).rstrip("/")
        # Check whether name == s or (s.startswith('@') and name.startswith(s + '/')).
        if name == s or (s.startswith("@") and name.startswith(s + "/")):
            # Return True to the caller.
            return True
    # Return False to the caller.
    return False


# Define confusion_facts for registry-based package risk checks.
# Inputs include meta.
def confusion_facts(meta: dict | None) -> dict | None:
    # Document the contract for the surrounding module or callable.
    """Facts when an internal-looking name resolves on the public registry; None if it does not exist there.

    That is the dependency-confusion risk: a public package with the same name as a private one can be installed
    instead of it. The facts (public latest version, maintainers, creation date, version count) let a reviewer
    judge whether the public package is the real internal one or an impostor."""
    # Check whether not meta.
    if not meta:
        # Return None to represent an absent value to the caller.
        return None
    # Store meta.get('time') or {} in t.
    t = meta.get("time") or {}
    # Return a mapping keyed by the fields below to the caller.
    return {"public_latest": meta.get("latest"),
            # Provide the mapping fields public_maintainers on this line.
            "public_maintainers": [m.get("name") for m in meta.get("maintainers") or []],
            # Provide the mapping fields public_created, public_versions on this line.
            "public_created": t.get("created"), "public_versions": len(meta.get("version_list") or [])}
