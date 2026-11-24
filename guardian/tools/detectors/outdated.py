"""Outdated / deprecated dependency detector (D4-08).

Input: components [{purl, scope?, project?}], an IntelClient. Output: finding dicts
(category "outdated") with the registry facts that justify them; Dev2/Dev1 wrap them
into Finding + Evidence. Offline-miss components are skipped (no facts, no finding).
"""
from __future__ import annotations

from datetime import UTC, datetime

from guardian.tools.threat_intel import IntelClient, parse_purl

DEFAULTS = {"max_age_years": 2.0, "major_behind": 2}


def _major(v: str | None) -> int | None:
    try:
        return int((v or "").lstrip("v^~").split(".")[0])
    except ValueError:
        return None


def _parse(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def detect_outdated(components: list[dict], intel: IntelClient, config: dict | None = None,
                    now: datetime | None = None) -> list[dict]:
    cfg = {**DEFAULTS, **(config or {})}
    now = now or datetime.now(UTC)
    findings = []
    for comp in components:
        purl = comp["purl"]
        name, version, eco = parse_purl(purl)
        if eco != "npm":
            continue
        meta = intel.registry_metadata(purl)
        if not meta:
            continue
        reasons: list[dict] = []
        dep_msg = (meta.get("deprecated_versions") or {}).get(version or "")
        if dep_msg:
            reasons.append({"rule": "deprecated", "detail": dep_msg, "installed_version": version})
        latest = meta.get("latest")
        t_latest = _parse((meta.get("time") or {}).get(latest or "", ""))
        if t_latest and (now - t_latest).days / 365.25 >= cfg["max_age_years"]:
            reasons.append({"rule": "unmaintained", "latest": latest,
                            "latest_published": t_latest.date().isoformat(),
                            "years_since_release": round((now - t_latest).days / 365.25, 1)})
        im, lm = _major(version), _major(latest)
        if im is not None and lm is not None and lm - im >= cfg["major_behind"]:
            reasons.append({"rule": "major_behind", "installed": version, "latest": latest,
                            "majors_behind": lm - im})
        if not reasons:
            continue
        findings.append({
            "category": "outdated", "detector": "outdated", "component_purl": purl,
            "scope": comp.get("scope", "unknown"), "project": comp.get("project"),
            "title": f"{name} {version} is outdated/deprecated ({', '.join(r['rule'] for r in reasons)})",
            "facts": {"reasons": reasons, "latest": latest},
        })
    return findings
