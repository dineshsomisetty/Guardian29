"""Advanced package risk from registry metadata (D4-10, stretch; ported from dev04 and extended).

Pure functions over trimmed packuments (threat_intel.trim_packument), so fixtures are easy and offline:
  * maintainer change in the latest release
  * unusual release activity (burst of releases, very recent release, very young package)
  * dependency confusion (names under an internal scope/name from guardian.yaml that also exist publicly)
  * provenance gaps (registry/audit signals from tools/provenance.py; peers = the other checked packages)
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from guardian.tools.provenance import maintainer_changed, provenance_for

DEFAULTS = {"release_burst_versions": 5, "release_burst_days": 7, "new_version_days": 3, "min_package_age_days": 7,
            "release_burst_recent_days": 90}
PEER_MIN = 3  # peers that must have a signal before its absence counts as a gap
PEER_SHARE = 0.5


def _ts(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def release_activity(meta: dict, thresholds: dict | None = None, now: datetime | None = None) -> list[dict]:
    c = {**DEFAULTS, **{k: v for k, v in (thresholds or {}).items() if v is not None}}
    now = now or datetime.now(UTC)
    t = meta.get("time") or {}
    times = sorted(dt for k, v in t.items() if k not in ("created", "modified", "unpublished") and (dt := _ts(v)))
    out = []
    n, d = int(c["release_burst_versions"]), timedelta(days=c["release_burst_days"])
    # only a *recent* burst is a signal: almost every mature package had a busy week at some point
    recent = [x for x in times if now - x <= timedelta(days=c["release_burst_recent_days"])]
    for i in range(len(recent) - n + 1):
        if recent[i + n - 1] - recent[i] <= d:
            out.append({"rule": "release_burst", "versions": n, "window_days": c["release_burst_days"],
                        "start": recent[i].date().isoformat()})
            break
    if times and now - times[-1] <= timedelta(days=c["new_version_days"]):
        out.append({"rule": "very_recent_release", "published": times[-1].date().isoformat(),
                    "days_ago": (now - times[-1]).days})
    created = _ts(t.get("created", ""))
    if created and now - created < timedelta(days=c["min_package_age_days"]):
        out.append({"rule": "very_young_package", "created": created.date().isoformat(),
                    "age_days": (now - created).days})
    return out


def _maintainer_names(people) -> set[str]:
    return {(p.get("name") or p.get("email") or "").lower() if isinstance(p, dict) else str(p).lower()
            for p in people or []} - {""}


def maintainer_facts(meta: dict) -> dict | None:
    """Only a full takeover is a finding: the latest release's maintainers share nobody with the previous
    release's. Ordinary rotation (someone added or removed) is normal and would only add noise."""
    if not maintainer_changed(meta):
        return None
    cur, prev = _maintainer_names(meta.get("latest_maintainers")), _maintainer_names(meta.get("previous_maintainers"))
    if not cur or not prev or cur & prev:
        return None
    return {"previous": meta.get("previous_maintainers"), "latest": meta.get("latest_maintainers"),
            "latest_version": meta.get("latest")}


def _has(meta: dict, key: str) -> bool:
    return bool(meta.get(key))


def provenance_gaps(metas: dict[str, dict]) -> dict[str, dict]:
    """purl -> {reasons: [...], provenance: <provenance_for output>, peers: {...}} for packages with a gap.

    Reasons: `no_repository_and_maintainer_changed` (plan section 7) and `signature_missing_peers_have` /
    `attestation_missing_peers_have` (>= PEER_MIN of the other checked packages, >= PEER_SHARE of them, carry it)."""
    n = len(metas)
    sig_peers = sum(1 for m in metas.values() if _has(m, "latest_signatures"))
    att_peers = sum(1 for m in metas.values() if _has(m, "latest_attestations"))
    out: dict[str, dict] = {}
    for purl, meta in metas.items():
        prov = provenance_for(meta)
        reasons = []
        if not prov["repository_url"] and prov["maintainer_changed"]:
            reasons.append("no_repository_and_maintainer_changed")
        others = max(n - 1, 0)
        sig_others = sig_peers - (1 if _has(meta, "latest_signatures") else 0)
        att_others = att_peers - (1 if _has(meta, "latest_attestations") else 0)
        if not _has(meta, "latest_signatures") and sig_others >= PEER_MIN and sig_others >= PEER_SHARE * others:
            reasons.append("signature_missing_peers_have")
        if not _has(meta, "latest_attestations") and att_others >= PEER_MIN and att_others >= PEER_SHARE * others:
            reasons.append("attestation_missing_peers_have")
        if reasons:
            out[purl] = {"reasons": reasons, "provenance": prov,
                         "peers": {"checked": n, "with_signatures": sig_others, "with_attestations": att_others}}
    return out


def matches_internal(name: str, internal: list[str]) -> bool:
    """`internal` entries are scopes ("@acme", "@acme/") or exact package names."""
    for s in internal:
        s = str(s).rstrip("/")
        if name == s or (s.startswith("@") and name.startswith(s + "/")):
            return True
    return False


def confusion_facts(meta: dict | None) -> dict | None:
    """Facts when an internal-looking name resolves on the public registry; None if it does not exist there."""
    if not meta:
        return None
    t = meta.get("time") or {}
    return {"public_latest": meta.get("latest"),
            "public_maintainers": [m.get("name") for m in meta.get("maintainers") or []],
            "public_created": t.get("created"), "public_versions": len(meta.get("version_list") or [])}
