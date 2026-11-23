"""Threat intelligence lookups with disk cache + offline mode (D4-03; ported from dev04, adapted by Dev1).

Read-only public APIs only (plan section 14): FIRST EPSS, CISA KEV, OSV, npm registry.
Every response is cached on disk and calls are throttled. With GUARDIAN_OFFLINE=1 (or settings.offline) only
the cache is used; a miss returns None (never raises), so callers can mark the factor unknown.
Every outbound request goes through guardrails/network.py:check_url (G3.5); a blocked host is a cache miss.
These functions return facts; guardian/tools/risk_tools.py wraps them into Evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path
from urllib.parse import quote

import httpx

from guardian.core.config import REPO_ROOT
from guardian.guardrails.network import NetworkBlocked, check_url

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
NPM_REGISTRY = "https://registry.npmjs.org"
DEFAULT_CACHE = REPO_ROOT / "data" / "cache" / "intel" / "threat"
EPSS_BATCH = 100
MIN_INTERVAL_S = 0.25  # throttle: be kind to public services / shared Wi-Fi

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_lock = threading.Lock()
_last_call = 0.0


def is_offline() -> bool:
    return os.environ.get("GUARDIAN_OFFLINE", "") not in ("", "0", "false", "False")


class IntelClient:
    def __init__(self, cache_dir: Path | str | None = None, transport: httpx.BaseTransport | None = None,
                 offline: bool | None = None, min_interval: float = MIN_INTERVAL_S, ctx=None, agent: str = "guardrail"):
        self.cache_dir = Path(cache_dir or os.environ.get("GUARDIAN_INTEL_CACHE") or DEFAULT_CACHE)
        self._ctx = ctx  # ToolContext: G3.5 guardrail events go to this run's trace
        self._agent = agent
        if offline is None and ctx is not None and ctx.settings.offline:
            offline = True
        self._made_dir = False
        self._http = httpx.Client(transport=transport, timeout=20.0,
                                  headers={"User-Agent": "guardian-hackathon/0.1 (read-only)"})
        self._offline = offline
        self.min_interval = min_interval

    @property
    def offline(self) -> bool:
        return is_offline() if self._offline is None else self._offline

    # ---- cache + http -------------------------------------------------
    def _path(self, key: str) -> Path:
        h = hashlib.sha256(key.encode()).hexdigest()[:24]
        return self.cache_dir / f"{h}.json"

    def _cached(self, key: str, max_age: float | None):
        p = self._path(key)
        if not p.exists():
            return None
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if max_age is not None and not self.offline and time.time() - data["_ts"] > max_age:
            return None
        return data

    def _store(self, key: str, payload) -> None:
        if not self._made_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._made_dir = True
        self._path(key).write_text(json.dumps({"_key": key, "_ts": time.time(), "payload": payload}),
                                   encoding="utf-8")

    def _fetch(self, key: str, method: str, url: str, *, max_age: float | None = 86400,
               params: dict | None = None, body: dict | None = None):
        """Return payload (JSON) or None when offline-miss / network error."""
        hit = self._cached(key, max_age)
        if hit is not None:
            return hit["payload"]
        if self.offline:
            return None
        try:
            check_url(url, ctx=self._ctx, agent=self._agent)  # G3.5
        except NetworkBlocked:
            return None
        global _last_call
        with _lock:
            wait = self.min_interval - (time.monotonic() - _last_call)
            if wait > 0:
                time.sleep(wait)
            _last_call = time.monotonic()
        try:
            r = self._http.request(method, url, params=params, json=body)
            if r.status_code == 404:
                payload = {"_not_found": True}
            else:
                r.raise_for_status()
                payload = r.json()
        except (httpx.HTTPError, ValueError):
            stale = self._cached(key, None)  # fall back to stale cache rather than fail
            return stale["payload"] if stale else None
        self._store(key, payload)
        return payload

    # ---- EPSS ---------------------------------------------------------
    def epss_lookup(self, cves: list[str]) -> dict[str, dict]:
        """CVE -> {epss, percentile, date}. Missing CVEs are absent from the result."""
        ids = sorted({c.upper() for c in cves if _CVE_RE.match(c)})
        out: dict[str, dict] = {}
        for i in range(0, len(ids), EPSS_BATCH):
            chunk = ids[i:i + EPSS_BATCH]
            payload = self._fetch("epss:" + ",".join(chunk), "GET", EPSS_URL,
                                  params={"cve": ",".join(chunk)}, max_age=86400)
            for row in (payload or {}).get("data", []):
                out[row["cve"].upper()] = {
                    "epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date"),
                }
        return out

    # ---- KEV ----------------------------------------------------------
    def kev_catalog(self) -> dict[str, dict]:
        payload = self._fetch("kev:catalog", "GET", KEV_URL, max_age=6 * 3600)
        return {v["cveID"].upper(): v for v in (payload or {}).get("vulnerabilities", [])}

    def kev_lookup(self, cves: list[str]) -> dict[str, dict | None]:
        """CVE -> KEV entry (dateAdded, ransomware use...) or None if not listed.
        Returns {} when the catalog is unavailable (offline miss) so callers can tell 'unknown'."""
        cat = self.kev_catalog()
        if not cat:
            return {}
        return {c.upper(): cat.get(c.upper()) for c in cves}

    # ---- OSV ----------------------------------------------------------
    def osv_query(self, purl: str) -> list[dict]:
        name, version, eco = parse_purl(purl)
        body = {"package": {"name": name, "ecosystem": eco}}
        if version:
            body["version"] = version
        payload = self._fetch(f"osv:{purl}", "POST", OSV_QUERY_URL, body=body, max_age=86400)
        return (payload or {}).get("vulns", [])

    # ---- registry -----------------------------------------------------
    def registry_metadata(self, purl: str) -> dict | None:
        """npm packument (trimmed to what rules need). None if offline-miss / not found."""
        name, _, eco = parse_purl(purl)
        if eco != "npm":
            return None
        payload = self._fetch(f"npm:{name}", "GET", f"{NPM_REGISTRY}/{quote(name, safe='@')}", max_age=86400)
        if not payload or payload.get("_not_found"):
            return None
        return trim_packument(payload)

    def version_metadata(self, name: str, version: str) -> dict | None:
        """npm version document trimmed to what compat hints need (engines, peerDependencies, deprecated)."""
        payload = self._fetch(f"npmv:{name}@{version}", "GET",
                              f"{NPM_REGISTRY}/{quote(name, safe='@')}/{quote(version)}", max_age=7 * 86400)
        if not payload or payload.get("_not_found"):
            return None
        return {"name": payload.get("name"), "version": payload.get("version"),
                "engines": payload.get("engines") or {}, "peer_dependencies": payload.get("peerDependencies") or {},
                "deprecated": payload.get("deprecated")}

    # ---- safe version -------------------------------------------------
    def safe_version_lookup(self, purl: str, vuln_ids: list[str] | None = None) -> dict:
        """Lowest version (same ecosystem) that fixes ALL given vulns, from OSV data.

        Returns {"fixed_version": str|None, "affected_range": str|None, "per_vuln": {id: [fixed...]},
                 "source": "osv"}. fixed_version None means no single fix found."""
        name, _, eco = parse_purl(purl)
        vulns = self.osv_query(purl)
        wanted = {v.upper() for v in vuln_ids} if vuln_ids else None
        per_vuln: dict[str, list[str]] = {}
        ranges: list[str] = []
        for v in vulns:
            ids = {v["id"].upper(), *(a.upper() for a in v.get("aliases", []))}
            if wanted is not None and not (ids & wanted):
                continue
            fixed, spans = [], []
            for aff in v.get("affected", []):
                pkg = aff.get("package", {})
                if pkg.get("name", "").lower() != name.lower() or pkg.get("ecosystem", "").lower() != eco.lower():
                    continue
                for rg in aff.get("ranges", []):
                    intro, fix = "0", None
                    for ev in rg.get("events", []):
                        intro = ev.get("introduced", intro)
                        if "fixed" in ev:
                            fix = ev["fixed"]
                            fixed.append(fix)
                            spans.append(f">={intro},<{fix}" if intro != "0" else f"<{fix}")
            per_vuln[v["id"]] = sorted(set(fixed), key=version_key)
            ranges.extend(spans)
        candidates = None
        for fixes in per_vuln.values():
            candidates = set(fixes) if candidates is None else candidates & set(fixes)
        fixed_version = None
        if per_vuln and all(per_vuln.values()):
            # lowest version >= max over vulns of that vuln's lowest fix
            floor = max(version_key(min(f, key=version_key)) for f in per_vuln.values())
            ok = sorted({f for fx in per_vuln.values() for f in fx if version_key(f) >= floor}, key=version_key)
            fixed_version = ok[0] if ok else None
        all_fixed = sorted({f for fx in per_vuln.values() for f in fx}, key=version_key)
        return {"fixed_version": fixed_version, "all_fixed": all_fixed, "affected_range": "; ".join(dict.fromkeys(ranges)) or None,
                "per_vuln": per_vuln, "source": "osv"}


def parse_purl(purl: str) -> tuple[str, str | None, str]:
    """pkg:npm/%40scope/name@1.2.3 -> ('@scope/name', '1.2.3', 'npm')."""
    m = re.match(r"^pkg:([^/]+)/(.+?)(?:@([^@?#]+))?(?:[?#].*)?$", purl)
    if not m:
        raise ValueError(f"bad purl: {purl}")
    typ, name, ver = m.groups()
    name = name.replace("%40", "@")
    eco = {"npm": "npm", "pypi": "PyPI", "maven": "Maven"}.get(typ, typ)
    return name, ver, eco


def version_key(v: str) -> tuple:
    parts = re.split(r"[.\-+]", v)
    key = []
    for p in parts:
        key.append((0, int(p)) if p.isdigit() else (-1, 0))
    return tuple(key)


def trim_packument(p: dict) -> dict:
    """Keep only fields our rules use, so cached files and evidence stay small."""
    latest = (p.get("dist-tags") or {}).get("latest")
    versions = p.get("versions") or {}
    lv = versions.get(latest, {}) if latest else {}
    times = p.get("time", {})
    ordered = sorted((v for v in versions if v in times), key=lambda v: times[v])
    prev = versions.get(ordered[ordered.index(latest) - 1], {}) if latest in ordered and ordered.index(latest) > 0 else {}
    return {
        "name": p.get("name"),
        "latest": latest,
        "dist_tags": p.get("dist-tags", {}),
        "time": p.get("time", {}),
        "deprecated": lv.get("deprecated"),  # message on the latest version, if any
        "deprecated_versions": {k: v["deprecated"] for k, v in versions.items() if v.get("deprecated")},
        "repository": (lv.get("repository") or p.get("repository")),
        "maintainers": p.get("maintainers", []),
        "latest_maintainers": lv.get("maintainers", []),
        "previous_maintainers": prev.get("maintainers", []),
        "latest_has_install_script": any(s in (lv.get("scripts") or {}) for s in ("preinstall", "install", "postinstall")),
        "latest_attestations": (lv.get("dist") or {}).get("attestations"),
        "latest_signatures": (lv.get("dist") or {}).get("signatures"),
        "version_list": list(versions.keys()),
    }
