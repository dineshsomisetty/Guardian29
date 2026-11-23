"""Advanced package risk from registry metadata (D4-10, stretch).

Rules: maintainer change, unusual release activity, dependency confusion.
Pure over trimmed packument dicts (see threat_intel.trim_packument), so fixtures are easy.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from guardian.tools.provenance import maintainer_changed
from guardian.tools.threat_intel import IntelClient

DEFAULTS = {"burst_versions": 5, "burst_days": 7, "new_version_days": 3}


def _ts(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def release_activity(meta: dict, cfg: dict | None = None, now: datetime | None = None) -> list[dict]:
    c = {**DEFAULTS, **(cfg or {})}
    now = now or datetime.now(UTC)
    times = sorted(t for k, v in (meta.get("time") or {}).items()
                   if k not in ("created", "modified") and (t := _ts(v)))
    out = []
    n, d = c["burst_versions"], timedelta(days=c["burst_days"])
    for i in range(len(times) - n + 1):
        if times[i + n - 1] - times[i] <= d:
            out.append({"rule": "release_burst", "versions": n, "window_days": c["burst_days"],
                        "start": times[i].date().isoformat()})
            break
    if times and now - times[-1] <= timedelta(days=c["new_version_days"]):
        out.append({"rule": "very_recent_release", "published": times[-1].date().isoformat(),
                    "days_ago": (now - times[-1]).days})
    return out


def package_risks(purl: str, meta: dict | None, cfg: dict | None = None,
                  now: datetime | None = None) -> list[dict]:
    """Findings for maintainer change and release activity. Empty if no metadata."""
    if not meta:
        return []
    out = []
    if maintainer_changed(meta):
        out.append({"category": "maintainer_change", "component_purl": purl, "detector": "package_risk",
                    "title": f"{meta.get('name')}: maintainer set changed in latest release",
                    "facts": {"previous": meta.get("previous_maintainers"),
                              "latest": meta.get("latest_maintainers")}})
    acts = release_activity(meta, cfg, now)
    if acts:
        out.append({"category": "maintainer_change", "component_purl": purl, "detector": "package_risk",
                    "title": f"{meta.get('name')}: unusual release activity", "facts": {"signals": acts}})
    return out


def dependency_confusion(names: list[str], internal_scopes: list[str], intel: IntelClient) -> list[dict]:
    """Names under an internal scope that ALSO exist on the public registry."""
    findings = []
    scopes = tuple(s if s.endswith("/") else s + "/" for s in internal_scopes)
    for n in names:
        if not n.startswith(scopes):
            continue
        purl = "pkg:npm/" + n.replace("@", "%40", 1)
        meta = intel.registry_metadata(purl + "@0")
        if meta:
            findings.append({"category": "dependency_confusion", "component_purl": purl,
                             "detector": "package_risk",
                             "title": f"{n} is an internal-scope name that also exists on the public registry",
                             "facts": {"public_latest": meta.get("latest"),
                                       "public_maintainers": meta.get("maintainers")}})
    return findings
