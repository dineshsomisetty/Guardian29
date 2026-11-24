"""Outdated / deprecated dependency detector (D4-08).

Called by: the detection step that wraps its dicts into Finding + Evidence (Dev2/Dev1); not a registered tool itself.
Why: deprecated or abandoned packages no longer receive security fixes, and a version several majors behind is
costly to patch when a CVE finally lands.
Input: components [{purl, scope?, project?}] and an IntelClient (cached, throttled, G3.5-checked npm registry).
Only npm packages are examined. Offline-miss components are skipped (no facts, no finding), so the result depends
only on what the cache or registry could answer.
Output: finding dicts {category "outdated", detector, component_purl, scope, project, title, facts} where
facts = {reasons: [...], latest}. Reason rules:
  deprecated    the installed version carries an npm deprecation message          {rule, detail, installed_version}
  unmaintained  the latest release is older than max_age_years (default 2)       {rule, latest, latest_published,
                                                                                  years_since_release}
  major_behind  installed major is >= major_behind (default 2) below latest       {rule, installed, latest,
                                                                                  majors_behind}
Config keys max_age_years / major_behind override DEFAULTS.
"""
from __future__ import annotations

from datetime import UTC, datetime

from guardian.tools.threat_intel import IntelClient, parse_purl

# Thresholds: a latest release older than 2 years = unmaintained; 2+ majors behind = hard to upgrade later.
DEFAULTS = {"max_age_years": 2.0, "major_behind": 2}


def _major(v: str | None) -> int | None:
    """Major version number of a version or range string (leading v ^ ~ stripped); None if not numeric."""
    try:
        return int((v or "").lstrip("v^~").split(".")[0])
    except ValueError:
        return None


def _parse(ts: str) -> datetime | None:
    """Parse a registry ISO timestamp (trailing Z allowed); None if missing or malformed."""
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def detect_outdated(components: list[dict], intel: IntelClient, config: dict | None = None,
                    now: datetime | None = None) -> list[dict]:
    """Return one finding dict per npm component with at least one of the reasons in the module docstring.
    `config` overrides DEFAULTS; `now` is injectable for tests. Components the registry cannot describe are skipped."""
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
        # when the newest release was published; an old latest release means nobody is shipping fixes
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
