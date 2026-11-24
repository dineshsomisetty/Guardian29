# Document the contract for the surrounding module or callable.
"""Threat intelligence lookups (EPSS, CISA KEV, OSV, npm registry) with a disk cache and an offline mode.

Called by: guardian/tools/risk_tools.py (risk_analyst and remediation agents), several detectors (typosquat,
package_risk, outdated, policy_check) and the investigator. These functions return plain facts; risk_tools.py
wraps them into Evidence (kinds epss, kev, osv, provenance, compat_hint).

Inputs: CVE ids (EPSS, KEV), purls (OSV, npm registry), npm package names and versions.
Outputs (dicts, never Evidence): EPSS {epss, percentile, date}; KEV entry or None; OSV vulnerability list;
trimmed npm packument (latest, time, maintainers, deprecated_versions, version_list, major_heads ...).

Network: read-only public APIs only (plan section 14). Every outbound request goes through
guardrails/network.py:check_url (G3.5); a blocked host is treated like a cache miss. Calls are throttled
process-wide (MIN_INTERVAL_S) to be kind to the public services.
Cache: one JSON file per request key, named sha256(key)[:24], under data/cache/intel/threat (override with
GUARDIAN_INTEL_CACHE), stamped with the fetch time. Entries older than their max_age are refetched; if that
fails the stale entry is served instead of an error. GUARDIAN_INTEL_MAX_AGE caps every max_age (watch mode).
Offline (GUARDIAN_OFFLINE=1 or settings.offline): only the cache is read (age ignored). A miss returns
None / {} / [] and never raises, so callers can mark the factor "unknown" rather than guess.
"""
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Load hashlib for public advisory and registry lookups.
import hashlib
# Load json for public advisory and registry lookups.
import json
# Load os for public advisory and registry lookups.
import os
# Load re for public advisory and registry lookups.
import re
# Load threading for public advisory and registry lookups.
import threading
# Load time for public advisory and registry lookups.
import time
# Import Path from pathlib.
from pathlib import Path
# Import quote from urllib.parse.
from urllib.parse import quote

# Load httpx for public advisory and registry lookups.
import httpx

# Import REPO_ROOT from guardian.core.config.
from guardian.core.config import REPO_ROOT
# Import NetworkBlocked, check_url from guardian.guardrails.network.
from guardian.guardrails.network import NetworkBlocked, check_url

# Give EPSS_URL its starting value.
# The initial value is 'https://api.first.org/data/v1/epss'.
EPSS_URL = "https://api.first.org/data/v1/epss"
# Give KEV_URL its starting value.
# The initial value is the supplied text.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Give OSV_QUERY_URL its starting value.
# The initial value is 'https://api.osv.dev/v1/query'.
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
# Give NPM_REGISTRY its starting value.
# The initial value is 'https://registry.npmjs.org'.
NPM_REGISTRY = "https://registry.npmjs.org"
# Store REPO_ROOT / 'data' / 'cache' / 'intel' / 'threat' in DEFAULT_CACHE.
DEFAULT_CACHE = REPO_ROOT / "data" / "cache" / "intel" / "threat"
# Give EPSS_BATCH its starting value.
# The initial value is 100.
EPSS_BATCH = 100  # CVEs per EPSS request (comma-separated list; keeps the URL short)
# Give MIN_INTERVAL_S its starting value.
# The initial value is 0.25.
MIN_INTERVAL_S = 0.25  # throttle: be kind to public services / shared Wi-Fi

# Only well-formed CVE ids are sent to EPSS/KEV (rejects junk and keeps URLs safe).
# Store the result of re.compile in _CVE_RE.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# Process-wide throttle state shared by every IntelClient: time of the last real HTTP call.
# Store the result of threading.Lock in _lock.
_lock = threading.Lock()
# Give _last_call its starting value.
# The initial value is 0.0.
_last_call = 0.0


# Define is_offline for public advisory and registry lookups.
# This helper has no explicit input parameters.
def is_offline() -> bool:
    # Document the contract for the surrounding module or callable.
    """True when the GUARDIAN_OFFLINE environment variable is set to anything but empty/0/false."""
    # Return the expression on this line to the caller.
    return os.environ.get("GUARDIAN_OFFLINE", "") not in ("", "0", "false", "False")


# Define IntelClient for public advisory and registry lookups.
# Group the related fields or methods under this type.
class IntelClient:
    # Document the contract for the surrounding module or callable.
    """Cached, throttled, guardrail-checked client for EPSS, KEV, OSV and the npm registry.

    One instance per tool call is fine: all state lives in the on-disk cache and the module-level throttle.
    """

    # Define __init__ for public advisory and registry lookups.
    # Inputs include cache_dir, transport, offline, min_interval, ctx, agent, max_age.
    def __init__(self, cache_dir: Path | str | None = None, transport: httpx.BaseTransport | None = None,
                 # Continue the function signature with its remaining arguments.
                 offline: bool | None = None, min_interval: float = MIN_INTERVAL_S, ctx=None, agent: str = "guardrail",
                 # Continue the function signature with its remaining arguments.
                 max_age: float | None = None):
        # Document the contract for the surrounding module or callable.
        """cache_dir: where cache files go (default env GUARDIAN_INTEL_CACHE, else data/cache/intel/threat).
        transport: httpx transport, injected by tests so no real network is used.
        offline: True/False forces the mode; None follows ctx.settings.offline, then the GUARDIAN_OFFLINE env var.
        min_interval: minimum seconds between two real HTTP calls (throttle).
        ctx / agent: ToolContext and agent name, used only so G3.5 guardrail events land in this run's trace.
        max_age: ceiling in seconds on every cache entry's age (None = use each call's own max_age)."""
        # Store the result of Path in self.cache_dir.
        self.cache_dir = Path(cache_dir or os.environ.get("GUARDIAN_INTEL_CACHE") or DEFAULT_CACHE)
        # Store ctx in self._ctx.
        self._ctx = ctx  # ToolContext: G3.5 guardrail events go to this run's trace
        # Store agent in self._agent.
        self._agent = agent
        # Check whether the expression on this line.
        if offline is None and ctx is not None and getattr(ctx.settings, "offline", False):
            # Give offline its starting value.
            # The initial value is True.
            offline = True
        # Give self._made_dir its starting value.
        # The initial value is False.
        self._made_dir = False
        # Store the result of httpx.Client in self._http.
        self._http = httpx.Client(transport=transport, timeout=20.0,
                                  # Supply headers as named arguments to the surrounding call.
                                  # These names connect the values to the receiving parameters.
                                  headers={"User-Agent": "guardian-hackathon/0.1 (read-only)"})
        # Store offline in self._offline.
        self._offline = offline
        # watch mode: cap every cache max-age (seconds) so advisories are refreshed; env GUARDIAN_INTEL_MAX_AGE
        # Store the result of os.environ.get in env_age.
        env_age = os.environ.get("GUARDIAN_INTEL_MAX_AGE")
        # Store the expression on this line in self.max_age.
        self.max_age = max_age if max_age is not None else (float(env_age) if env_age else None)
        # Store min_interval in self.min_interval.
        self.min_interval = min_interval

    # Apply the property decorator to the declaration below.
    @property
    # Define offline for public advisory and registry lookups.
    # This helper has no explicit input parameters.
    def offline(self) -> bool:
        # Document the contract for the surrounding module or callable.
        """Effective offline flag: explicit constructor value if given, otherwise the environment variable."""
        # Return is_offline() if self._offline is None else self._offline to the caller.
        return is_offline() if self._offline is None else self._offline

    # ---- cache + http -------------------------------------------------
    # Define _path for public advisory and registry lookups.
    # Inputs include key.
    def _path(self, key: str) -> Path:
        # Document the contract for the surrounding module or callable.
        """Cache file for a request key: a short hash keeps file names safe and fixed-length on Windows."""
        # Store hashlib.sha256(key.encode()).hexdigest()[:24] in h.
        h = hashlib.sha256(key.encode()).hexdigest()[:24]
        # Return self.cache_dir / f'{h}.json' to the caller.
        return self.cache_dir / f"{h}.json"

    # Define _cached for public advisory and registry lookups.
    # Inputs include key, max_age.
    def _cached(self, key: str, max_age: float | None):
        # Document the contract for the surrounding module or callable.
        """Return the cache record {_key, _ts, payload} for `key`, or None when missing, unreadable or too old.
        Offline mode ignores age: an old answer beats no answer when nothing can be refreshed."""
        # Store the result of self._path in p.
        p = self._path(key)
        # Check whether not p.exists().
        if not p.exists():
            # Return None to represent an absent value to the caller.
            return None
        # Run the following operation with exception handling.
        # The handlers below determine how the listed failures are handled.
        try:
            # Store the result of json.loads in data.
            data = json.loads(p.read_text(encoding="utf-8"))
        # Handle (OSError, ValueError) from the preceding block.
        except (OSError, ValueError):
            # Return None to represent an absent value to the caller.
            return None
        # Check whether self.max_age is not None and max_age is not None.
        if self.max_age is not None and max_age is not None:
            # Store the result of min in max_age.
            max_age = min(max_age, self.max_age)
        # Check whether the expression on this line.
        if max_age is not None and not self.offline and time.time() - data["_ts"] > max_age:
            # Return None to represent an absent value to the caller.
            return None
        # Return data to the caller.
        return data

    # Define _store for public advisory and registry lookups.
    # Inputs include key, payload.
    def _store(self, key: str, payload) -> None:
        # Document the contract for the surrounding module or callable.
        """Write `payload` to the cache with the current time (creates the cache directory once)."""
        # Check whether not self._made_dir.
        if not self._made_dir:
            # Call self.cache_dir.mkdir at this point.
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            # Give self._made_dir its starting value.
            # The initial value is True.
            self._made_dir = True
        # Call self._path(key).write_text at this point.
        self._path(key).write_text(json.dumps({"_key": key, "_ts": time.time(), "payload": payload}),
                                   # Supply encoding as named arguments to the surrounding call.
                                   # These names connect the values to the receiving parameters.
                                   encoding="utf-8")

    # Use the cached response when possible and fall back to a public lookup when online.
    # Inputs include key, method, url, max_age, params, body.
    def _fetch(self, key: str, method: str, url: str, *, max_age: float | None = 86400,
               # Continue the function signature with its remaining arguments.
               params: dict | None = None, body: dict | None = None):
        # Document the contract for the surrounding module or callable.
        """Return the JSON payload for `key`, or None on an offline miss, a blocked host or a network error.

        Order: fresh cache hit -> (offline: give up) -> G3.5 URL check -> throttle -> HTTP request. A 404 is
        cached as {"_not_found": True} so a missing package is not re-queried every run. If the request fails,
        a stale cache entry is returned instead of None. Writes the cache on success."""
        # Store the result of self._cached in hit.
        hit = self._cached(key, max_age)
        # Check whether hit is not None.
        if hit is not None:
            # Return hit['payload'] to the caller.
            return hit["payload"]
        # Check whether self.offline.
        if self.offline:
            # Return None to represent an absent value to the caller.
            return None
        # Run the following operation with exception handling.
        # The handlers below determine how the listed failures are handled.
        try:
            # Call check_url at this point.
            check_url(url, ctx=self._ctx, agent=self._agent)  # G3.5
        # Handle NetworkBlocked from the preceding block.
        except NetworkBlocked:
            # Return None to represent an absent value to the caller.
            return None  # blocked host behaves like "no data"
        # Use the module-level binding for _last_call.
        # Assignments to the name update the shared module state.
        global _last_call
        # Enter the context managed by _lock.
        with _lock:  # serialise threads so the minimum gap between calls holds across the whole process
            # Store self.min_interval - (time.monotonic() - _last_call) in wait.
            wait = self.min_interval - (time.monotonic() - _last_call)
            # Check whether wait > 0.
            if wait > 0:
                # Call time.sleep at this point.
                time.sleep(wait)
            # Store the result of time.monotonic in _last_call.
            _last_call = time.monotonic()
        # Run the following operation with exception handling.
        # The handlers below determine how the listed failures are handled.
        try:
            # Store the result of self._http.request in r.
            r = self._http.request(method, url, params=params, json=body)
            # Check whether r.status_code == 404.
            if r.status_code == 404:
                # Store a mapping keyed by the fields below in payload.
                payload = {"_not_found": True}
            # Supply the alternative for the preceding condition.
            # This path covers the case where the earlier branch does not apply.
            else:
                # Call r.raise_for_status at this point.
                r.raise_for_status()
                # Store the result of r.json in payload.
                payload = r.json()
        # Handle (httpx.HTTPError, ValueError) from the preceding block.
        except (httpx.HTTPError, ValueError):
            # Store the result of self._cached in stale.
            stale = self._cached(key, None)  # fall back to stale cache rather than fail
            # Return stale['payload'] if stale else None to the caller.
            return stale["payload"] if stale else None
        # Call self._store at this point.
        self._store(key, payload)
        # Return payload to the caller.
        return payload

    # ---- EPSS ---------------------------------------------------------
    # Define epss_lookup for public advisory and registry lookups.
    # Inputs include cves.
    def epss_lookup(self, cves: list[str]) -> dict[str, dict]:
        # Document the contract for the surrounding module or callable.
        """CVE -> {epss, percentile, date}. Missing CVEs are absent from the result.

        epss is the probability (0-1) of exploitation in the next 30 days; percentile ranks it against all CVEs
        (scoring uses the percentile because the raw probability is heavily skewed towards 0).
        Results are cached per batch of up to EPSS_BATCH ids for a day."""
        # Store the result of sorted in ids.
        ids = sorted({c.upper() for c in cves if _CVE_RE.match(c)})
        # Declare out with type dict[str, dict].
        # Use a mapping keyed by the fields below as its initial value.
        out: dict[str, dict] = {}
        # Iterate over range(0, len(ids), EPSS_BATCH).
        # Bind each item to i before processing it.
        for i in range(0, len(ids), EPSS_BATCH):
            # Store ids[i:i + EPSS_BATCH] in chunk.
            chunk = ids[i:i + EPSS_BATCH]
            # Store the result of self._fetch in payload.
            payload = self._fetch("epss:" + ",".join(chunk), "GET", EPSS_URL,
                                  # Supply params, max_age as named arguments to the surrounding call.
                                  # These names connect the values to the receiving parameters.
                                  params={"cve": ",".join(chunk)}, max_age=86400)
            # Iterate over (payload or {}).get('data', []).
            # Bind each item to row before processing it.
            for row in (payload or {}).get("data", []):
                # Store a mapping keyed by the fields below in out[row['cve'].upper()].
                out[row["cve"].upper()] = {
                    # Provide the mapping fields epss, percentile, date on this line.
                    "epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date"),
                # Close the current expression or collection.
                }
        # Return out to the caller.
        return out

    # ---- KEV ----------------------------------------------------------
    # Define kev_catalog for public advisory and registry lookups.
    # This helper has no explicit input parameters.
    def kev_catalog(self) -> dict[str, dict]:
        # Document the contract for the surrounding module or callable.
        """The whole CISA Known Exploited Vulnerabilities catalog as {CVE id: entry}; {} if unavailable.
        One file covers all CVEs, so it is cached for only 6 hours (new entries appear during the day)."""
        # Store the result of self._fetch in payload.
        payload = self._fetch("kev:catalog", "GET", KEV_URL, max_age=6 * 3600)
        # Return a lookup built from the input records to the caller.
        return {v["cveID"].upper(): v for v in (payload or {}).get("vulnerabilities", [])}

    # Define kev_lookup for public advisory and registry lookups.
    # Inputs include cves.
    def kev_lookup(self, cves: list[str]) -> dict[str, dict | None]:
        # Document the contract for the surrounding module or callable.
        """CVE -> KEV entry (dateAdded, ransomware use...) or None if not listed.
        Returns {} when the catalog is unavailable (offline miss) so callers can tell 'unknown'."""
        # Store the result of self.kev_catalog in cat.
        cat = self.kev_catalog()
        # Check whether not cat.
        if not cat:
            # Return a mapping keyed by the fields below to the caller.
            return {}
        # Return a lookup built from the input records to the caller.
        return {c.upper(): cat.get(c.upper()) for c in cves}

    # ---- OSV ----------------------------------------------------------
    # Define osv_query for public advisory and registry lookups.
    # Inputs include purl.
    def osv_query(self, purl: str) -> list[dict]:
        # Document the contract for the surrounding module or callable.
        """OSV advisories for a package (at its version when the purl has one); [] if none or unavailable."""
        # Store the result of parse_purl in (name, version, eco).
        name, version, eco = parse_purl(purl)
        # Store a mapping keyed by the fields below in body.
        body = {"package": {"name": name, "ecosystem": eco}}
        # Check whether version.
        if version:
            # Store version in body['version'].
            body["version"] = version
        # Store the result of self._fetch in payload.
        payload = self._fetch(f"osv:{purl}", "POST", OSV_QUERY_URL, body=body, max_age=86400)
        # Return the result of (payload or {}).get to the caller.
        return (payload or {}).get("vulns", [])

    # ---- registry -----------------------------------------------------
    # Define registry_metadata for public advisory and registry lookups.
    # Inputs include purl.
    def registry_metadata(self, purl: str) -> dict | None:
        # Document the contract for the surrounding module or callable.
        """npm packument (trimmed to what rules need). None if offline-miss / not found."""
        # Store the result of parse_purl in (name, _, eco).
        name, _, eco = parse_purl(purl)
        # Check whether eco != 'npm'.
        if eco != "npm":
            # Return None to represent an absent value to the caller.
            return None  # only the npm registry is queried; PyPI/Maven have no registry lookup here
        # Store the result of self._fetch in payload.
        payload = self._fetch(f"npm:{name}", "GET", f"{NPM_REGISTRY}/{quote(name, safe='@')}", max_age=86400)
        # Check whether not payload or payload.get('_not_found').
        if not payload or payload.get("_not_found"):
            # Return None to represent an absent value to the caller.
            return None
        # Return the result of trim_packument to the caller.
        return trim_packument(payload)

    # Define version_metadata for public advisory and registry lookups.
    # Inputs include name, version.
    def version_metadata(self, name: str, version: str) -> dict | None:
        # Document the contract for the surrounding module or callable.
        """npm version document trimmed to what compat hints need (engines, peerDependencies, deprecated)."""
        # a published version document never changes, hence the longer 7-day cache
        # Store the result of self._fetch in payload.
        payload = self._fetch(f"npmv:{name}@{version}", "GET",
                              # Supply the next part of the expression started above.
                              f"{NPM_REGISTRY}/{quote(name, safe='@')}/{quote(version)}", max_age=7 * 86400)
        # Check whether not payload or payload.get('_not_found').
        if not payload or payload.get("_not_found"):
            # Return None to represent an absent value to the caller.
            return None
        # Return a mapping keyed by the fields below to the caller.
        return {"name": payload.get("name"), "version": payload.get("version"),
                # Provide the mapping fields engines, peer_dependencies on this line.
                "engines": payload.get("engines") or {}, "peer_dependencies": payload.get("peerDependencies") or {},
                # Provide the mapping fields deprecated on this line.
                "deprecated": payload.get("deprecated")}

    # ---- safe version -------------------------------------------------
    # Collect known fix versions across the matching advisory records.
    # Inputs include purl, vuln_ids.
    def safe_version_lookup(self, purl: str, vuln_ids: list[str] | None = None) -> dict:
        # Document the contract for the surrounding module or callable.
        """Lowest version (same ecosystem) that fixes ALL given vulns, from OSV data.

        Returns {"fixed_version": str|None, "affected_range": str|None, "per_vuln": {id: [fixed...]},
                 "source": "osv"}. fixed_version None means no single fix found."""
        # Store the result of parse_purl in (name, _, eco).
        name, _, eco = parse_purl(purl)
        # Store the result of self.osv_query in vulns.
        vulns = self.osv_query(purl)
        # Store {v.upper() for v in vuln_ids} if vuln_ids else None in wanted.
        wanted = {v.upper() for v in vuln_ids} if vuln_ids else None
        # Declare per_vuln with type dict[str, list[str]].
        # Use a mapping keyed by the fields below as its initial value.
        per_vuln: dict[str, list[str]] = {}  # advisory id -> its fixed versions, oldest first
        # Declare ranges with type list[str].
        # Use an ordered collection as its initial value.
        ranges: list[str] = []  # readable affected ranges, e.g. ">=1.0.0,<1.4.2" or "<1.4.2"
        # Iterate over vulns.
        # Bind each item to v before processing it.
        for v in vulns:
            # Store a collection of distinct values in ids.
            ids = {v["id"].upper(), *(a.upper() for a in v.get("aliases", []))}  # GHSA id plus CVE aliases
            # Check whether wanted is not None and (not ids & wanted).
            if wanted is not None and not (ids & wanted):
                # Skip the remaining work for this item.
                continue
            # Store ([], []) in (fixed, spans).
            fixed, spans = [], []
            # Iterate over v.get('affected', []).
            # Bind each item to aff before processing it.
            for aff in v.get("affected", []):
                # Store the result of aff.get in pkg.
                pkg = aff.get("package", {})
                # Check whether the expression on this line.
                if pkg.get("name", "").lower() != name.lower() or pkg.get("ecosystem", "").lower() != eco.lower():
                    # Skip the remaining work for this item.
                    continue
                # Iterate over aff.get('ranges', []).
                # Bind each item to rg before processing it.
                for rg in aff.get("ranges", []):
                    # OSV events: {"introduced": v} opens an affected span, {"fixed": v} closes it ("0" = from start)
                    # Store ('0', None) in (intro, fix).
                    intro, fix = "0", None
                    # Iterate over rg.get('events', []).
                    # Bind each item to ev before processing it.
                    for ev in rg.get("events", []):
                        # Store the result of ev.get in intro.
                        intro = ev.get("introduced", intro)
                        # Check whether 'fixed' in ev.
                        if "fixed" in ev:
                            # Store ev['fixed'] in fix.
                            fix = ev["fixed"]
                            # Call fixed.append at this point.
                            fixed.append(fix)
                            # Call spans.append at this point.
                            spans.append(f">={intro},<{fix}" if intro != "0" else f"<{fix}")
            # Store the result of sorted in per_vuln[v['id']].
            per_vuln[v["id"]] = sorted(set(fixed), key=version_key)
            # Call ranges.extend at this point.
            ranges.extend(spans)
        # intersection of the fix lists; informational only, the answer below is chosen with the floor rule
        # Give candidates its starting value.
        # The initial value is None to represent an absent value.
        candidates = None
        # Iterate over per_vuln.values().
        # Bind each item to fixes before processing it.
        for fixes in per_vuln.values():
            # Store set(fixes) if candidates is None else candidates & set(fixes) in candidates.
            candidates = set(fixes) if candidates is None else candidates & set(fixes)
        # Give fixed_version its starting value.
        # The initial value is None to represent an absent value.
        fixed_version = None
        # Check whether per_vuln and all(per_vuln.values()).
        if per_vuln and all(per_vuln.values()):
            # lowest version >= max over vulns of that vuln's lowest fix: one upgrade that clears every advisory
            # Store the result of max in floor.
            floor = max(version_key(min(f, key=version_key)) for f in per_vuln.values())
            # Store the result of sorted in ok.
            ok = sorted({f for fx in per_vuln.values() for f in fx if version_key(f) >= floor}, key=version_key)
            # Store ok[0] if ok else None in fixed_version.
            fixed_version = ok[0] if ok else None
        # Store the result of sorted in all_fixed.
        all_fixed = sorted({f for fx in per_vuln.values() for f in fx}, key=version_key)
        # Return a mapping keyed by the fields below to the caller.
        return {"fixed_version": fixed_version, "all_fixed": all_fixed, "affected_range": "; ".join(dict.fromkeys(ranges)) or None,
                # Provide the mapping fields per_vuln, source on this line.
                "per_vuln": per_vuln, "source": "osv"}


# Define parse_purl for public advisory and registry lookups.
# Inputs include purl.
def parse_purl(purl: str) -> tuple[str, str | None, str]:
    # Document the contract for the surrounding module or callable.
    """pkg:npm/%40scope/name@1.2.3 -> ('@scope/name', '1.2.3', 'npm').

    Returns (name, version or None, OSV ecosystem name). Raises ValueError on a string that is not a purl.
    Qualifiers/subpaths (?... / #...) are ignored; unknown types are passed through unchanged."""
    # pkg:<type>/<name, may hold a scope path>[@version][?qualifiers][#subpath]
    # Store the result of re.match in m.
    m = re.match(r"^pkg:([^/]+)/(.+?)(?:@([^@?#]+))?(?:[?#].*)?$", purl)
    # Check whether not m.
    if not m:
        # Raise ValueError(f'bad purl: {purl}').
        # The error leaves this branch and can be handled by the caller.
        raise ValueError(f"bad purl: {purl}")
    # Store the result of m.groups in (typ, name, ver).
    typ, name, ver = m.groups()
    # Store the result of name.replace in name.
    name = name.replace("%40", "@")
    # Store the result of {'npm': 'npm', 'pypi': 'PyPI', 'maven': 'Maven'}.get in eco.
    eco = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}.get(typ, typ)  # OSV spells ecosystems this way
    # Return (name, ver, eco) to the caller.
    return name, ver, eco


# Define version_key for public advisory and registry lookups.
# Inputs include v.
def version_key(v: str) -> tuple:
    # Document the contract for the surrounding module or callable.
    """Sort key for dotted versions: numeric parts compare as numbers, anything else (rc, beta) sorts lower.
    A rough comparator, enough to order fix versions; it is not a full semver implementation."""
    # Store the result of re.split in parts.
    parts = re.split(r"[.\-+]", v)
    # Store an ordered collection in key.
    key = []
    # Iterate over parts.
    # Bind each item to p before processing it.
    for p in parts:
        # Call key.append at this point.
        key.append((0, int(p)) if p.isdigit() else (-1, 0))  # (-1, 0): a text part sorts before any number
    # Return the result of tuple to the caller.
    return tuple(key)


# Project npm registry metadata into the fields the detectors consume.
# Inputs include p.
def trim_packument(p: dict) -> dict:
    # Document the contract for the surrounding module or callable.
    """Keep only fields our rules use, so cached files and evidence stay small."""
    # Store the result of (p.get('dist-tags') or {}).get in latest.
    latest = (p.get("dist-tags") or {}).get("latest")
    # Store p.get('versions') or {} in versions.
    versions = p.get("versions") or {}
    # Store versions.get(latest, {}) if latest else {} in lv.
    lv = versions.get(latest, {}) if latest else {}
    # Store the result of p.get in times.
    times = p.get("time", {})
    # versions by publish time, so "previous" is the release published just before `latest` (takeover check)
    # Store the result of sorted in ordered.
    ordered = sorted((v for v in versions if v in times), key=lambda v: times[v])
    # Store the expression on this line in prev.
    prev = versions.get(ordered[ordered.index(latest) - 1], {}) if latest in ordered and ordered.index(latest) > 0 else {}
    # Return a mapping keyed by the fields below to the caller.
    return {
        # Provide the mapping fields name on this line.
        "name": p.get("name"),
        # Provide the mapping fields latest on this line.
        "latest": latest,
        # Provide the mapping fields dist_tags on this line.
        "dist_tags": p.get("dist-tags", {}),
        # Provide the mapping fields time on this line.
        "time": p.get("time", {}),
        # Provide the mapping fields deprecated on this line.
        "deprecated": lv.get("deprecated"),  # message on the latest version, if any
        # Provide the mapping fields deprecated_versions on this line.
        "deprecated_versions": {k: v["deprecated"] for k, v in versions.items() if v.get("deprecated")},
        # Provide the mapping fields repository on this line.
        "repository": (lv.get("repository") or p.get("repository")),
        # Provide the mapping fields maintainers on this line.
        "maintainers": p.get("maintainers", []),
        # Provide the mapping fields latest_maintainers on this line.
        "latest_maintainers": lv.get("maintainers", []),
        # Provide the mapping fields previous_maintainers on this line.
        "previous_maintainers": prev.get("maintainers", []),
        # Provide the mapping fields latest_has_install_script on this line.
        "latest_has_install_script": any(s in (lv.get("scripts") or {}) for s in ("preinstall", "install", "postinstall")),
        # Provide the mapping fields latest_attestations on this line.
        "latest_attestations": (lv.get("dist") or {}).get("attestations"),
        # Provide the mapping fields latest_signatures on this line.
        "latest_signatures": (lv.get("dist") or {}).get("signatures"),
        # Provide the mapping fields version_list on this line.
        "version_list": list(versions.keys()),
        # Provide the mapping fields major_heads on this line.
        "major_heads": major_heads(versions, latest),
    # Close the current expression or collection.
    }


# Define major_heads for public advisory and registry lookups.
# Inputs include versions, latest, limit.
def major_heads(versions: dict, latest: str | None, limit: int = 12) -> dict[str, dict[str, str]]:
    # Document the contract for the surrounding module or callable.
    """{version: dependencies} for the newest stable release of each major (newest majors first, capped).
    Lets remediation prove that an older major of a direct parent already pulls a fixed transitive child
    without a registry call per version."""
    # Declare best with type dict[int, str].
    # Use a mapping keyed by the fields below as its initial value.
    best: dict[int, str] = {}
    # Store version_key(latest) if latest else None in lv.
    lv = version_key(latest) if latest else None
    # Iterate over versions.
    # Bind each item to v before processing it.
    for v in versions:
        # Check whether the expression on this line.
        if not re.fullmatch(r"\d+\.\d+\.\d+", v) or (lv is not None and version_key(v) > lv):
            # Skip the remaining work for this item.
            continue  # stable releases only, never above the `latest` tag
        # Store the result of int in major.
        major = int(v.split(".")[0])
        # Check whether major not in best or version_key(v) > version_key(best[major]).
        if major not in best or version_key(v) > version_key(best[major]):
            # Store v in best[major].
            best[major] = v
    # Store sorted(best.values(), key=version_key, reverse=True)[:limit] in heads.
    heads = sorted(best.values(), key=version_key, reverse=True)[:limit]
    # Return a lookup built from the input records to the caller.
    return {v: dict((versions[v] or {}).get("dependencies") or {}) for v in heads}
