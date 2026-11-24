# Document the contract for the surrounding module or callable.
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
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Import UTC, datetime from datetime.
from datetime import UTC, datetime

# Import IntelClient, parse_purl from guardian.tools.threat_intel.
from guardian.tools.threat_intel import IntelClient, parse_purl

# Thresholds: a latest release older than 2 years = unmaintained; 2+ majors behind = hard to upgrade later.
# Store a mapping keyed by the fields below in DEFAULTS.
DEFAULTS = {"max_age_years": 2.0, "major_behind": 2}


# Define _major for dependency age and deprecation checks.
# Inputs include v.
def _major(v: str | None) -> int | None:
    # Document the contract for the surrounding module or callable.
    """Major version number of a version or range string (leading v ^ ~ stripped); None if not numeric."""
    # Run the following operation with exception handling.
    # The handlers below determine how the listed failures are handled.
    try:
        # Return the result of int to the caller.
        return int((v or "").lstrip("v^~").split(".")[0])
    # Handle ValueError from the preceding block.
    except ValueError:
        # Return None to represent an absent value to the caller.
        return None


# Define _parse for dependency age and deprecation checks.
# Inputs include ts.
def _parse(ts: str) -> datetime | None:
    # Document the contract for the surrounding module or callable.
    """Parse a registry ISO timestamp (trailing Z allowed); None if missing or malformed."""
    # Run the following operation with exception handling.
    # The handlers below determine how the listed failures are handled.
    try:
        # Return the result of datetime.fromisoformat to the caller.
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    # Handle (ValueError, AttributeError) from the preceding block.
    except (ValueError, AttributeError):
        # Return None to represent an absent value to the caller.
        return None


# Collect all applicable registry-backed reasons for each npm component.
# Inputs include components, intel, config, now.
def detect_outdated(components: list[dict], intel: IntelClient, config: dict | None = None,
                    # Continue the function signature with its remaining arguments.
                    now: datetime | None = None) -> list[dict]:
    # Document the contract for the surrounding module or callable.
    """Return one finding dict per npm component with at least one of the reasons in the module docstring.
    `config` overrides DEFAULTS; `now` is injectable for tests. Components the registry cannot describe are skipped."""
    # Store a mapping keyed by the fields below in cfg.
    cfg = {**DEFAULTS, **(config or {})}
    # Store now or datetime.now(UTC) in now.
    now = now or datetime.now(UTC)
    # Store an ordered collection in findings.
    findings = []
    # Iterate over components.
    # Bind each item to comp before processing it.
    for comp in components:
        # Store comp['purl'] in purl.
        purl = comp["purl"]
        # Store the result of parse_purl in (name, version, eco).
        name, version, eco = parse_purl(purl)
        # Check whether eco != 'npm'.
        if eco != "npm":
            # Skip the remaining work for this item.
            continue
        # Store the result of intel.registry_metadata in meta.
        meta = intel.registry_metadata(purl)
        # Check whether not meta.
        if not meta:
            # Skip the remaining work for this item.
            continue
        # Declare reasons with type list[dict].
        # Use an ordered collection as its initial value.
        reasons: list[dict] = []
        # Store the result of (meta.get('deprecated_versions') or {}).get in dep_msg.
        dep_msg = (meta.get("deprecated_versions") or {}).get(version or "")
        # Check whether dep_msg.
        if dep_msg:
            # Call reasons.append at this point.
            reasons.append({"rule": "deprecated", "detail": dep_msg, "installed_version": version})
        # Store the result of meta.get in latest.
        latest = meta.get("latest")
        # when the newest release was published; an old latest release means nobody is shipping fixes
        # Store the result of _parse in t_latest.
        t_latest = _parse((meta.get("time") or {}).get(latest or "", ""))
        # Check whether the expression on this line.
        if t_latest and (now - t_latest).days / 365.25 >= cfg["max_age_years"]:
            # Call reasons.append at this point.
            reasons.append({"rule": "unmaintained", "latest": latest,
                            # Provide the mapping fields latest_published on this line.
                            "latest_published": t_latest.date().isoformat(),
                            # Provide the mapping fields years_since_release on this line.
                            "years_since_release": round((now - t_latest).days / 365.25, 1)})
        # Store (_major(version), _major(latest)) in (im, lm).
        im, lm = _major(version), _major(latest)
        # Check whether the expression on this line.
        if im is not None and lm is not None and lm - im >= cfg["major_behind"]:
            # Call reasons.append at this point.
            reasons.append({"rule": "major_behind", "installed": version, "latest": latest,
                            # Provide the mapping fields majors_behind on this line.
                            "majors_behind": lm - im})
        # Check whether not reasons.
        if not reasons:
            # Skip the remaining work for this item.
            continue
        # Call findings.append at this point.
        findings.append({
            # Provide the mapping fields category, detector, component_purl on this line.
            "category": "outdated", "detector": "outdated", "component_purl": purl,
            # Provide the mapping fields scope, project on this line.
            "scope": comp.get("scope", "unknown"), "project": comp.get("project"),
            # Provide the mapping fields title on this line.
            "title": f"{name} {version} is outdated/deprecated ({', '.join(r['rule'] for r in reasons)})",
            # Provide the mapping fields facts, latest on this line.
            "facts": {"reasons": reasons, "latest": latest},
        # Close the current expression or collection.
        })
    # Return findings to the caller.
    return findings
