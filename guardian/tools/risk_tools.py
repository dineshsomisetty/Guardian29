"""Evidence tools for the risk analyst and remediation agents (D1-06/D1-07, D4-03/05/09/13/14). Owner: Dev1.

Called by: the risk_analyst agent (threat_intel, reachability, exposure_signals, package_scope,
provenance_signals, npm_signatures) and the remediation agent (safe_version_lookup, compat_hint) through the
tool registry. Every tool takes a typed pydantic args model (G3.2), only reads, and returns a ToolOutput.
Tools are batch-shaped (one call per run, one Evidence per item) so the per-agent tool budget stays small.

Inputs: CVE ids, package names / purls, the work copy of the target repo, the dependency graph in the ToolContext
(or the graph_json artifact), and the data/reachability/vulnerable_functions.yaml rules.
Outputs, as Evidence kinds with these `facts` keys:
  epss          {cve, epss, percentile, date}              kev  {cve, listed, date_added}
  reachability  {package, ecosystem, tier, files_scanned, hits, called, method}; tier = imported | not_imported |
                unknown (see tools/reachability.py); `called` lists vulnerable-function call sites
  exposure      {package, tier network|internal|unknown, expose, imported_in_server_paths, imported_in_prod}
  graph         {purl, scope prod|dev, direct, project}   provenance {purl, ...tools/provenance.py output}
  osv           {purl, installed, fixed_version, candidates, latest, scanner_fixed, source, ...child fields}
  compat_hint   {purl, from_version, to_version, semver_delta, level low|medium|high, peer_dep_changes, ...}
Network: EPSS, KEV, OSV and the npm registry go through IntelClient (tools/threat_intel.py), which checks every
URL against the G3.5 allowlist, caches on disk and serves only the cache with GUARDIAN_OFFLINE=1. When data is
unavailable the tool emits fewer Evidence items (absence means "unknown", never "safe"); it does not raise.
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

# Argument validation patterns: a CVE id, and a package URL such as pkg:npm/name@1.0.0 (no whitespace).
CVE = r"^CVE-\d{4}-\d{4,}$"
PURL = r"^pkg:[a-z]+/[^\s]+$"
# Directory names that usually hold server-side code; an import found under one of them (or in a file named
# server/app/index) counts as network-facing for exposure_signals.
SERVER_DIRS = {"routes", "server", "api", "controllers", "middleware", "lib", "app", "models", "views", "pygoat",
               "introduction", "handlers"}


class ThreatIntelArgs(BaseModel):
    """Arguments of the threat_intel tool: the CVE ids to look up (invalid ids are dropped)."""

    cves: list[str] = Field(max_length=300)


class PackagesArgs(BaseModel):
    """Package names (not purls) plus their ecosystem; used by the reachability and exposure tools."""

    packages: list[str] = Field(max_length=500)
    ecosystem: Literal["npm", "pypi", "maven"] = "npm"


class PurlsArgs(BaseModel):
    """Package URLs (pkg:npm/...) for tools that need exact versions (scope, provenance)."""

    purls: list[str] = Field(max_length=600)


class SafeVersionArgs(BaseModel):
    """Arguments of safe_version_lookup: the vulnerable package, its advisory ids, versions the scanner already
    reported as fixed, and optionally a vulnerable transitive child to prove an older parent major fixes it."""

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
    # optional ^ ~ >= = prefix, then major[.minor[.patch]] (x or * allowed), then end / space / "-" (hyphen range)
    m = re.match(r"^(?:\^|~|>=|=)?\s*v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(?:\s|$|-)", s)
    if not m:
        return None
    parts = [m.group(1), m.group(2) or "0", m.group(3) or "0"]
    return ".".join("0" if p in ("x", "*") else p for p in parts)


class CompatArgs(BaseModel):
    """Arguments of compat_hint: the package and the installed (from) and proposed (to) versions."""

    purl: str = Field(pattern=PURL)
    from_version: str = Field(max_length=64)
    to_version: str = Field(max_length=64)


def intel(ctx: ToolContext, agent: str) -> IntelClient:
    """An IntelClient bound to this run, so its G3.5 network guardrail events are traced under `agent`."""
    return IntelClient(ctx=ctx, agent=agent)


def _ev(ctx: ToolContext, kind: str, tool: str, facts: dict, **kw) -> Evidence:
    """Build an Evidence row for this run; extra keywords (file_path, line, excerpt) pass straight through."""
    return Evidence(run_id=ctx.run_id, kind=kind, source_tool=tool, facts=facts, **kw)


# ---------------------------------------------------------------- EPSS + KEV


def threat_intel(ctx: ToolContext, args: ThreatIntelArgs) -> ToolOutput:
    """EPSS score and CISA KEV listing for each CVE: one `epss` and one `kev` Evidence per CVE that has data.

    A CVE with no EPSS row gets no epss Evidence. If the KEV catalog itself is unavailable (offline cache miss)
    no kev Evidence is emitted at all, so "not on KEV" (listed: false) is never confused with "unknown".
    Keep both EPSS fields in evidence: build_factors uses percentile for E; the raw
    epss probability is different. This tool records facts, not the numeric risk score.
    """
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
    """One `reachability` Evidence per package: is it imported by production code, and are known-vulnerable
    functions actually called? Scans the work copy; test paths are excluded (see tools/reachability.py).

    Tiers: imported (an import exists in prod code), not_imported (code was scanned, no import) or unknown
    (nothing could be scanned for this ecosystem). The function-level `called` search only runs for imported
    packages. file_path/line/excerpt point at the first call site, else the first import."""
    root = ctx.work_dir or ctx.repo
    out = []
    for name in sorted(set(args.packages)):
        r = reach.reachability_import(root, name, args.ecosystem)
        called = reach.reachability_called(root, name, args.ecosystem) if r.tier == "imported" else []
        hit = (called[0]["sites"][0] if called else None) or (r.hits[0] if r.hits else None)
        out.append(_ev(ctx, "reachability", "reachability_import",
                       {"package": name, "ecosystem": args.ecosystem, "tier": r.tier, "files_scanned": r.files_scanned,
                        "hits": r.hits, "called": called,
                        "method": "import search in production paths (tests excluded); vulnerable-function calls "
                                  "from data/reachability/vulnerable_functions.yaml"},
                       file_path=hit["file"] if hit else None, line=hit["line"] if hit else None,
                       excerpt=hit["excerpt"] if hit else None))
    n = sum(1 for e in out if e.facts["tier"] == "imported")
    return ToolOutput(evidence=out, summary=f"{n}/{len(out)} packages imported in production paths")


def _server_hit(hit: dict, ecosystem: str, has_port: bool) -> bool:
    """Does an import hit look like server-side (network-facing) code?

    Front-end directories never count. For Python, any prod import counts when the Dockerfile EXPOSEs a port
    (no routes/ convention to rely on). For JS, the file must sit in a server-ish directory or be named
    server/app/index."""
    parts = hit["file"].lower().split("/")
    if parts[0] in {"frontend", "client", "ui", "web"}:
        return False
    if ecosystem == "pypi":
        return has_port
    return bool(SERVER_DIRS & set(parts[:-1])) or parts[-1].split(".")[0] in {"server", "app", "index"}


def exposure_signals(ctx: ToolContext, args: PackagesArgs) -> ToolOutput:
    """One `exposure` Evidence per package: is the vulnerable code on a network-facing path?

    network  = the Dockerfile EXPOSEs a port AND the package is imported from server-side code;
    internal = sources were scanned and the package is imported only by tests, or in prod only outside server paths;
    unknown  = anything else (no sources scanned, never imported, or no EXPOSE signal).
    This is a repository heuristic: EXPOSE plus a server import does not prove a
    deployed port is public or that an attacker can reach the vulnerable function.
    """
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
    """`graph` Evidence {purl, scope, direct, project} per purl whose prod/dev scope is known in the dependency
    graph (the live graph, or the graph_json artifact when resumed). Unknown scope emits nothing."""
    nodes: dict[str, dict] = {}  # purl -> graph node attributes
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


def npm_signatures(ctx: ToolContext) -> ToolOutput:
    """Stretch goal 3: `npm audit signatures` over the installed dependency tree (registry signatures and
    Sigstore-backed provenance attestations, verified by npm), read from the sandbox's deps image."""
    from guardian.tools import sandbox

    res, why = sandbox.signature_audit(ctx.work_dir or ctx.repo)
    if res is None:
        return ToolOutput(summary=f"signature audit not run: {why}")
    ctx.artifacts["npm_signatures"] = res
    ev = _ev(ctx, "provenance", "npm audit signatures (Sigstore)", {k: v for k, v in res.items() if k != "image"})
    return ToolOutput(evidence=[ev], summary=(
        f"{res.get('verified_signatures')} verified registry signatures, {res.get('verified_attestations')} verified "
        f"attestations, {len(res['invalid'])} invalid, {len(res['missing'])} missing"))


def _audit_for(ctx: ToolContext, purl: str) -> dict | None:
    """Map the stored `npm audit signatures` result onto one purl as {"signature_verified": True|False|None}.
    None overall means the audit did not run, so provenance falls back to registry metadata alone."""
    sig = ctx.artifacts.get("npm_signatures")
    if not sig:
        return None
    name, version, _ = parse_purl(purl)
    key = f"{name}@{version}"
    if key in sig["invalid"]:
        return {"signature_verified": False}
    if key in sig["missing"]:
        return {"signature_verified": None}
    return {"signature_verified": True}  # audited, not reported invalid or missing


def provenance_signals(ctx: ToolContext, args: PurlsArgs) -> ToolOutput:
    """`provenance` Evidence per package (first 50, to bound registry calls): registry metadata combined with
    the signature audit via tools/provenance.py. Packages with no registry data (offline miss, non-npm) are skipped.
    facts.score_modifier is true for a failed check; the summary counts those."""
    client = intel(ctx, "risk_analyst")
    out = []
    for p in sorted(set(args.purls))[:50]:
        meta = client.registry_metadata(p)
        if meta is None:
            continue
        out.append(_ev(ctx, "provenance", "registry_metadata", {"purl": p, **prov.provenance_for(meta, _audit_for(ctx, p))}))
    return ToolOutput(evidence=out, summary=f"provenance for {len(out)} packages, "
                                            f"{sum(1 for e in out if e.facts['score_modifier'])} failed")


# ---------------------------------------------------------------- safe version + compat hint (remediation)


def _stable(v: str) -> bool:
    """True for a plain x.y.z release (no pre-release suffix): only these are offered as upgrade targets."""
    return bool(re.fullmatch(r"\d+\.\d+\.\d+", v))


def safe_version_lookup(ctx: ToolContext, args: SafeVersionArgs) -> ToolOutput:
    """One `osv` Evidence listing upgrade candidates for a vulnerable package, oldest first.

    Candidates combine OSV fixed versions, the versions the scanner reported and the registry's `latest` (when
    stable and at/above the fix floor), keeping only versions newer than the installed one. `fixed_version` is the
    lowest single version that clears every given advisory. For a vulnerable transitive child, candidates also
    include older majors of the parent whose registry dependency range provably admits only fixed child
    versions (`pulls_fixed_child`). `source` records where the fix data came from: osv+scanner, scanner or registry."""
    name, cur, eco = parse_purl(args.purl)
    client = intel(ctx, "remediation")
    res = {"fixed_version": None, "all_fixed": [], "affected_range": None}  # empty default: no advisory ids given
    if args.vuln_ids:
        res = client.safe_version_lookup(args.purl, args.vuln_ids)
    meta = client.registry_metadata(args.purl) if eco == "npm" else None
    latest = (meta or {}).get("latest")
    pool = {*res["all_fixed"], *args.scanner_fixed}  # every version anyone says is fixed
    # floor: nothing below this version fixes everything (OSV answer, else the scanner's lowest fix)
    floor = res["fixed_version"] or (min(args.scanner_fixed, key=version_key) if args.scanner_fixed else None)
    cands = {v for v in pool if floor is None or version_key(v) >= version_key(floor)}
    if latest and _stable(latest) and (floor is None or version_key(latest) >= version_key(floor)):
        cands.add(latest)
    child_ranges: dict[str, str] = {}  # parent version -> its dependency range for the vulnerable child
    pulls_fixed: list[str] = []  # parent versions proven to pull a fixed child
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
    # drop anything not newer than what is installed (an "upgrade" to the same or older version is meaningless)
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
    """Parse the leading major.minor.patch of a version (missing parts are 0); None if it does not start with digits."""
    m = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", v)
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)) if m else None


def compat_hint(ctx: ToolContext, args: CompatArgs) -> ToolOutput:
    """One `compat_hint` Evidence rating how risky an upgrade is, from semver distance plus npm metadata.

    Base level by semver_delta: major -> high, minor -> medium, patch/none -> low, unknown -> medium (a major bump
    may break the API; patches should not). Raised to high when the target version is deprecated, and low -> medium
    when it declares peerDependencies (the consumer must satisfy them). `engines_ok` stays None: the Node version
    is not known here. registry_checked says whether npm metadata was actually available (false when offline)."""
    name, _, eco = parse_purl(args.purl)
    a, b = _semver(args.from_version), _semver(args.to_version)
    # distance between the two versions: the highest component that differs
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
