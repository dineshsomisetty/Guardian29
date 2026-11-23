"""Evidence tools for the risk analyst and remediation agents (D1-06/D1-07, D4-03/05/09/13/14). Owner: Dev1.

All tools take typed args (G3.2), only read, and return Evidence (kinds epss, kev, reachability, exposure,
graph, provenance, osv, compat_hint). Network access (EPSS, KEV, OSV, registry) goes through IntelClient, which
checks every URL against the G3.5 allowlist, caches on disk and serves only the cache with GUARDIAN_OFFLINE=1.
Tools are batch-shaped (one call per run, one Evidence per item) so the per-agent tool budget stays small.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from guardian.adapters import dockerfile
from guardian.core.models import Evidence
from guardian.tools import provenance as prov
from guardian.tools import reachability as reach
from guardian.tools.registry import ToolContext, ToolOutput
from guardian.tools.threat_intel import IntelClient, parse_purl, version_key

CVE = r"^CVE-\d{4}-\d{4,}$"
PURL = r"^pkg:[a-z]+/[^\s]+$"
SERVER_DIRS = {"routes", "server", "api", "controllers", "middleware", "lib", "app", "models", "views", "pygoat",
               "introduction", "handlers"}


class ThreatIntelArgs(BaseModel):
    cves: list[str] = Field(max_length=300)


class PackagesArgs(BaseModel):
    packages: list[str] = Field(max_length=500)
    ecosystem: Literal["npm", "pypi"] = "npm"


class PurlsArgs(BaseModel):
    purls: list[str] = Field(max_length=600)


class SafeVersionArgs(BaseModel):
    purl: str = Field(pattern=PURL)
    vuln_ids: list[str] = Field(default=[], max_length=50)
    scanner_fixed: list[str] = Field(default=[], max_length=50)
    # transitive fix: the vulnerable child of this (direct parent) package and the child's lowest fixed version
    child: str | None = Field(default=None, max_length=214, pattern=r"^[@a-zA-Z0-9][\w.@/-]*$")
    child_fixed: str | None = Field(default=None, max_length=64, pattern=r"^\d+(\.\d+){0,2}")


def range_floor(spec: str | None) -> str | None:
    """Lowest version an npm range admits, for the common forms (^x, ~x, >=x, x, x - y); None if unbounded or
    not understood ("*", "latest", "||" unions, git/url specs) so it is never treated as a proof."""
    s = (spec or "").strip()
    if not s or "||" in s or s in ("*", "x", "latest") or ":" in s or "/" in s:
        return None
    m = re.match(r"^(?:\^|~|>=|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(?:\s|$|-)", s)
    if not m:
        return None
    parts = [m.group(1), m.group(2) or "0", m.group(3) or "0"]
    return ".".join("0" if p in ("x", "*") else p for p in parts)


class CompatArgs(BaseModel):
    purl: str = Field(pattern=PURL)
    from_version: str = Field(max_length=64)
    to_version: str = Field(max_length=64)


def intel(ctx: ToolContext, agent: str) -> IntelClient:
    return IntelClient(ctx=ctx, agent=agent)


def _ev(ctx: ToolContext, kind: str, tool: str, facts: dict, **kw) -> Evidence:
    return Evidence(run_id=ctx.run_id, kind=kind, source_tool=tool, facts=facts, **kw)


# ---------------------------------------------------------------- EPSS + KEV


def threat_intel(ctx: ToolContext, args: ThreatIntelArgs) -> ToolOutput:
    cves = sorted({c.upper() for c in args.cves if re.match(CVE, c.upper())})
    client = intel(ctx, "risk_analyst")
    epss = client.epss_lookup(cves)
    kev = client.kev_lookup(cves)  # {} when the catalog is unavailable -> unknown, not "not listed"
    out: list[Evidence] = []
    for c in cves:
        if c in epss:
            out.append(_ev(ctx, "epss", "first.org/epss", {"cve": c, **epss[c]}))
        if c in kev:
            e = kev[c]
            out.append(_ev(ctx, "kev", "cisa.gov/kev", {"cve": c, "listed": e is not None,
                                                        "date_added": (e or {}).get("dateAdded")}))
    return ToolOutput(evidence=out, summary=f"{len(epss)}/{len(cves)} EPSS, "
                                            f"{sum(1 for c in cves if kev.get(c))} on KEV "
                                            f"({'catalog available' if kev else 'KEV unavailable'})")


# ---------------------------------------------------------------- reachability + exposure


def reachability(ctx: ToolContext, args: PackagesArgs) -> ToolOutput:
    root = ctx.work_dir or ctx.repo
    out = []
    for name in sorted(set(args.packages)):
        r = reach.reachability_import(root, name, args.ecosystem)
        hit = r.hits[0] if r.hits else None
        out.append(_ev(ctx, "reachability", "reachability_import",
                       {"package": name, "ecosystem": args.ecosystem, "tier": r.tier, "files_scanned": r.files_scanned,
                        "hits": r.hits, "method": "import search in production paths (tests excluded)"},
                       file_path=hit["file"] if hit else None, line=hit["line"] if hit else None,
                       excerpt=hit["excerpt"] if hit else None))
    n = sum(1 for e in out if e.facts["tier"] == "imported")
    return ToolOutput(evidence=out, summary=f"{n}/{len(out)} packages imported in production paths")


def _server_hit(hit: dict, ecosystem: str, has_port: bool) -> bool:
    parts = hit["file"].lower().split("/")
    if parts[0] in {"frontend", "client", "ui", "web"}:
        return False
    if ecosystem == "pypi":
        return has_port
    return bool(SERVER_DIRS & set(parts[:-1])) or parts[-1].split(".")[0] in {"server", "app", "index"}


def exposure_signals(ctx: ToolContext, args: PackagesArgs) -> ToolOutput:
    root = ctx.work_dir or ctx.repo
    _, ports = dockerfile.parse(root)
    prod, scanned = reach.import_index(root, args.ecosystem, False)
    alltests, _ = reach.import_index(root, args.ecosystem, True)
    out = []
    for name in sorted(set(args.packages)):
        key = reach.norm(name, args.ecosystem)
        hits = prod.get(key, [])
        server = [h["file"] for h in hits if _server_hit(h, args.ecosystem, bool(ports))]
        if ports and server:
            tier = "network"
        elif scanned and ((alltests.get(key) and not hits) or (hits and not server)):
            tier = "internal"
        else:
            tier = "unknown"
        out.append(_ev(ctx, "exposure", "exposure_signals",
                       {"package": name, "tier": tier, "expose": ports, "imported_in_server_paths": server[:5],
                        "imported_in_prod": bool(hits)},
                       file_path=server[0] if server else None))
    return ToolOutput(evidence=out, summary=f"{sum(1 for e in out if e.facts['tier'] == 'network')} network-facing "
                                            f"of {len(out)} (EXPOSE: {ports or 'none'})")


# ---------------------------------------------------------------- scope (P) from the dependency graph


def package_scope(ctx: ToolContext, args: PurlsArgs) -> ToolOutput:
    nodes: dict[str, dict] = {}
    if ctx.graph is not None and hasattr(ctx.graph, "g"):
        nodes = dict(ctx.graph.g.nodes(data=True))
    elif "graph_json" in ctx.artifacts:
        nodes = {n["id"]: n for n in ctx.artifacts["graph_json"].get("nodes", [])}
    out = []
    for p in sorted(set(args.purls)):
        d = nodes.get(p)
        if d and d.get("scope") in ("prod", "dev"):
            out.append(_ev(ctx, "graph", "graph_build", {"purl": p, "scope": d["scope"], "direct": d.get("direct"),
                                                         "project": d.get("project")}))
    return ToolOutput(evidence=out, summary=f"scope known for {len(out)}/{len(set(args.purls))} components")


# ---------------------------------------------------------------- provenance (npm registry signals)


def provenance_signals(ctx: ToolContext, args: PurlsArgs) -> ToolOutput:
    client = intel(ctx, "risk_analyst")
    out = []
    for p in sorted(set(args.purls))[:50]:
        meta = client.registry_metadata(p)
        if meta is None:
            continue
        out.append(_ev(ctx, "provenance", "registry_metadata", {"purl": p, **prov.provenance_for(meta)}))
    return ToolOutput(evidence=out, summary=f"provenance for {len(out)} packages, "
                                            f"{sum(1 for e in out if e.facts['score_modifier'])} failed")


# ---------------------------------------------------------------- safe version + compat hint (remediation)


def _stable(v: str) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+", v))


def safe_version_lookup(ctx: ToolContext, args: SafeVersionArgs) -> ToolOutput:
    name, cur, eco = parse_purl(args.purl)
    client = intel(ctx, "remediation")
    res = {"fixed_version": None, "all_fixed": [], "affected_range": None}
    if args.vuln_ids:
        res = client.safe_version_lookup(args.purl, args.vuln_ids)
    meta = client.registry_metadata(args.purl) if eco == "npm" else None
    latest = (meta or {}).get("latest")
    pool = {*res["all_fixed"], *args.scanner_fixed}
    floor = res["fixed_version"] or (min(args.scanner_fixed, key=version_key) if args.scanner_fixed else None)
    cands = {v for v in pool if floor is None or version_key(v) >= version_key(floor)}
    if latest and _stable(latest) and (floor is None or version_key(latest) >= version_key(floor)):
        cands.add(latest)
    child_ranges: dict[str, str] = {}
    pulls_fixed: list[str] = []
    if args.child and args.child_fixed and meta:
        # an older major of the parent may already pull a fixed child: prove it from the registry's
        # dependency range (its lowest admitted version >= the child's fixed version), never assume it
        for v, deps in (meta.get("major_heads") or {}).items():
            if args.child in deps:
                child_ranges[v] = deps[args.child]
                floor_v = range_floor(deps[args.child])
                if floor_v and version_key(floor_v) >= version_key(args.child_fixed):
                    pulls_fixed.append(v)
        cands |= set(pulls_fixed)
    cands = sorted((v for v in cands if cur is None or version_key(v) > version_key(cur)), key=version_key)
    pulls_fixed = [v for v in cands if v in pulls_fixed]
    source = "osv+scanner" if res["all_fixed"] else ("scanner" if args.scanner_fixed else "registry")
    ev = _ev(ctx, "osv", "safe_version_lookup",
             {"purl": args.purl, "package": name, "installed": cur, "vuln_ids": args.vuln_ids,
              "fixed_version": res["fixed_version"] or floor, "candidates": cands, "latest": latest,
              "scanner_fixed": args.scanner_fixed, "affected_range": res["affected_range"], "source": source,
              **({"child": args.child, "child_fixed": args.child_fixed, "child_ranges": child_ranges,
                  "pulls_fixed_child": pulls_fixed} if args.child else {})})
    return ToolOutput(evidence=[ev], summary=f"{name}: candidates {cands or 'none'} ({source})")


def _semver(v: str) -> tuple[int, int, int] | None:
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)) if m else None


def compat_hint(ctx: ToolContext, args: CompatArgs) -> ToolOutput:
    name, _, eco = parse_purl(args.purl)
    a, b = _semver(args.from_version), _semver(args.to_version)
    delta = "unknown" if not (a and b) else ("major" if a[0] != b[0] else "minor" if a[1] != b[1]
                                             else "patch" if a[2] != b[2] else "none")
    meta = intel(ctx, "remediation").version_metadata(name, args.to_version) if eco == "npm" else None
    peers = sorted((meta or {}).get("peer_dependencies", {}))
    deprecated = bool((meta or {}).get("deprecated")) if meta else None
    level = {"major": "high", "minor": "medium", "patch": "low", "none": "low"}.get(delta, "medium")
    if deprecated:
        level = "high"
    elif peers and level == "low":
        level = "medium"
    ev = _ev(ctx, "compat_hint", "compat_hint",
             {"purl": args.purl, "from_version": args.from_version, "to_version": args.to_version,
              "semver_delta": delta, "engines_ok": None, "engines": (meta or {}).get("engines") or {},
              "peer_dep_changes": peers, "deprecated_target": deprecated, "level": level,
              "registry_checked": meta is not None})
    return ToolOutput(evidence=[ev], summary=f"{name} {args.from_version}->{args.to_version}: {delta}, risk {level}")
