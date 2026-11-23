"""Vulnerability scanners (D2-04, Dev2): Grype over the SBOM -> Findings with traced dependency paths.

Tools produce facts. Everything here is deterministic; the LLM never touches these values.
Output uses plain dicts shaped like `Evidence` / `Finding` (plan §5.1) so it works before Dev1's models.py lands;
`to_models()` converts when it exists.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import networkx as nx

from guardian.core.graph_build import paths_to
from guardian.core.models import new_id
from guardian.tools.sbom import find_tool


def _purl(p: str) -> str:
    return p.split("?", 1)[0]


def run_grype(sbom_file: Path, out_json: Path, timeout: int = 900) -> dict:
    """`grype sbom:<file> -o json`. DB must already be present (scripts/install_tools.sh); never auto-updates
    (throttling / offline mode, G7.4). Returns the parsed document."""
    env = dict(os.environ, GRYPE_DB_AUTO_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false",
               GRYPE_DB_VALIDATE_BY_HASH_ON_START="false")  # hash check alone took ~3 min on Windows
    proc = subprocess.run([find_tool("grype"), f"sbom:{sbom_file}", "-o", "json", "-q"],
                          capture_output=True, text=True, timeout=timeout, env=env, encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError(f"grype failed (rc={proc.returncode}): {proc.stderr[-800:]}")
    Path(out_json).write_text(proc.stdout, encoding="utf-8")
    return json.loads(proc.stdout)


def _cvss(vuln: dict, related: list[dict]) -> float | None:
    """Highest base score, preferring CVSS v3.x from NVD-style related records (GHSA entries often carry none)."""
    scores: list[tuple[int, float]] = []
    for v in [vuln, *related]:
        for c in v.get("cvss", []) or []:
            base = (c.get("metrics") or {}).get("baseScore")
            if base is not None:
                scores.append((1 if str(c.get("version", "")).startswith("3") or str(c.get("version", "")).startswith("4")
                               else 0, float(base)))
    if not scores:
        return None
    best_version = max(v for v, _ in scores)
    return max(s for v, s in scores if v == best_version)


def parse_grype(doc: dict, G: nx.DiGraph | None, run_id: str, raw_file: Path | None = None) -> tuple[list[dict], list[dict]]:
    """Grype document -> (findings, evidence). One finding per (purl, vuln_id); duplicates are merged."""
    G = getattr(G, "G", G)  # accept DependencyGraph or a raw networkx graph
    version = (doc.get("descriptor") or {}).get("version", "unknown")
    sha = hashlib.sha256(Path(raw_file).read_bytes()).hexdigest() if raw_file and Path(raw_file).is_file() else None
    now = datetime.now(timezone.utc).isoformat()
    seen: dict[tuple[str, str], dict] = {}
    findings: list[dict] = []
    evidence: list[dict] = []
    for m in doc.get("matches", []):
        vuln, art = m["vulnerability"], m["artifact"]
        purl, vid = _purl(art["purl"]), vuln["id"]
        key = (purl, vid)
        related = m.get("relatedVulnerabilities", []) or []
        aliases = sorted({r["id"] for r in related} - {vid})
        constraint = next((d["found"]["versionConstraint"] for d in m.get("matchDetails", [])
                           if d.get("found", {}).get("versionConstraint")), None)
        fixed = (vuln.get("fix") or {}).get("versions") or []
        if key in seen:  # same package+vuln seen again (e.g. second location): merge fixes only
            f = seen[key]
            f["fixed_versions"] = sorted(set(f["fixed_versions"]) | set(fixed))
            continue
        node = G.nodes[purl] if G is not None and purl in G else {}
        paths = paths_to(G, purl, max_paths=5) if G is not None and purl in G else []
        cvss, severity = _cvss(vuln, related), (vuln.get("severity") or "").lower() or None
        facts = {"vuln_id": vid, "aliases": aliases, "purl": purl, "name": art["name"], "version": art["version"],
                 "cvss": cvss, "severity": severity, "fixed_versions": fixed, "affected_range": constraint,
                 "fix_state": (vuln.get("fix") or {}).get("state"), "data_source": vuln.get("dataSource"),
                 "namespace": vuln.get("namespace"), "dependency_paths": paths}
        ev = {"evidence_id": new_id("ev"), "run_id": run_id, "kind": "scanner_output", "source_tool": f"grype@{version}",
              "created_at": now, "facts": facts, "excerpt": (vuln.get("description") or "")[:300] or None,
              "artifact_path": str(raw_file) if raw_file else None, "sha256": sha}
        f = {"finding_id": new_id("fd"), "run_id": run_id, "category": "cve",
             "title": f"{vid} in {art['name']}@{art['version']}", "detector": "grype", "component_purl": purl,
             "scope": node.get("scope", "unknown"), "project": node.get("project"),
             "dependency_paths": paths, "vuln_id": vid, "aliases": aliases, "cvss": cvss, "severity": severity,
             "fixed_versions": fixed, "affected_range": constraint, "evidence_ids": [ev["evidence_id"]],
             "status": "open"}
        seen[key] = f
        findings.append(f)
        evidence.append(ev)
    return findings, evidence


def scan_sbom(sbom_file: Path, run_path: Path, G: nx.DiGraph, run_id: str) -> tuple[list[dict], list[dict]]:
    """Run Grype on `sbom_file` and return (findings, evidence) with traced paths from graph `G`."""
    raw = Path(run_path) / "grype.json"
    doc = run_grype(sbom_file, raw)
    return parse_grype(doc, G, run_id, raw)


def to_models(findings: list[dict], evidence: list[dict]):
    from guardian.core.models import Evidence, Finding

    return [Finding(**f) for f in findings], [Evidence(**e) for e in evidence]


def grype_scan(ctx):
    """Tool entry point (registry binding `grype`)."""
    from guardian.tools.registry import ToolOutput

    if ctx.sbom_path is None:
        raise RuntimeError("no SBOM available: discovery must run first")
    findings, evidence = scan_sbom(Path(ctx.sbom_path), Path(ctx.run_dir), ctx.graph, ctx.run_id)
    fds, evs = to_models(findings, evidence)
    return ToolOutput(findings=fds, evidence=evs, summary=f"{len(fds)} vulnerabilities (grype, offline DB)")


# ---------------------------------------------------------------- OSV-Scanner cross-check (P1)
def run_osv(lockfiles: list[Path], out_json: Path, timeout: int = 600) -> dict:
    """`osv-scanner scan source -L <lock> ... --format json`. Queries api.osv.dev (allowlisted, §14).
    Exit code 1 means "vulnerabilities found", not failure."""
    args = [find_tool("osv-scanner"), "scan", "source"]
    for lf in lockfiles:
        args += ["-L", str(lf)]
    args += ["--format", "json", "--output-file", str(out_json)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, encoding="utf-8")
    if proc.returncode not in (0, 1) or not Path(out_json).is_file():
        raise RuntimeError(f"osv-scanner failed (rc={proc.returncode}): {proc.stderr[-800:]}")
    return json.loads(Path(out_json).read_text(encoding="utf-8"))


def _osv_range(vuln: dict, name: str) -> tuple[list[str], str | None]:
    """Fixed versions and a readable affected range ("<4.17.21", "<=6.6.1") for this package."""
    fixed, parts = [], []
    for aff in vuln.get("affected", []):
        if (aff.get("package") or {}).get("name") != name:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            intro = None
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif "fixed" in ev:
                    fixed.append(ev["fixed"])
                    parts.append((f">={intro}, " if intro not in (None, "0") else "") + f"<{ev['fixed']}")
                elif "last_affected" in ev:
                    parts.append((f">={intro}, " if intro not in (None, "0") else "") + f"<={ev['last_affected']}")
    return sorted(set(fixed)), (" || ".join(dict.fromkeys(parts)) or None)


def parse_osv(doc: dict, G: nx.DiGraph | None, run_id: str, raw_file: Path | None = None,
              tool_version: str = "unknown") -> tuple[list[dict], list[dict]]:
    """OSV-Scanner JSON -> (findings, evidence). One finding per (purl, alias group)."""
    G = getattr(G, "G", G)
    sha = hashlib.sha256(Path(raw_file).read_bytes()).hexdigest() if raw_file and Path(raw_file).is_file() else None
    now = datetime.now(timezone.utc).isoformat()
    findings, evidence, seen = [], [], set()
    for res in doc.get("results", []):
        src = (res.get("source") or {}).get("path", "").replace("\\", "/")
        project = "frontend" if "/frontend/" in src else "root"
        for pkg in res.get("packages", []):
            info = pkg["package"]
            purl = _purl(info.get("purl") or f"pkg:npm/{info['name']}@{info['version']}")
            by_id = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            for grp in pkg.get("groups", []) or [{"ids": [i]} for i in by_id]:
                ids = grp.get("ids", [])
                vid = next((i for i in ids if i.startswith("GHSA-")), ids[0])  # GHSA first: matches Grype ids
                if (purl, vid) in seen or vid not in by_id:
                    continue
                seen.add((purl, vid))
                v = by_id[vid]
                aliases = sorted((set(grp.get("aliases", [])) | set(v.get("aliases", []))) - {vid})
                fixed, rng = _osv_range(v, info["name"])
                try:
                    cvss = float(grp.get("max_severity")) if grp.get("max_severity") else None
                except ValueError:
                    cvss = None
                severity = ((v.get("database_specific") or {}).get("severity") or "").lower() or None
                if severity == "moderate":
                    severity = "medium"
                node = G.nodes[purl] if G is not None and purl in G else {}
                paths = paths_to(G, purl, 5) if node else []
                facts = {"vuln_id": vid, "aliases": aliases, "purl": purl, "name": info["name"],
                         "version": info["version"], "cvss": cvss, "severity": severity, "fixed_versions": fixed,
                         "affected_range": rng, "lockfile": src, "dependency_paths": paths}
                ev = {"evidence_id": new_id("ev"), "run_id": run_id, "kind": "scanner_output",
                      "source_tool": f"osv-scanner@{tool_version}", "created_at": now, "facts": facts,
                      "excerpt": (v.get("summary") or "")[:300] or None,
                      "artifact_path": str(raw_file) if raw_file else None, "sha256": sha}
                findings.append({
                    "finding_id": new_id("fd"), "run_id": run_id, "category": "cve",
                    "title": f"{vid} in {info['name']}@{info['version']}", "detector": "osv-scanner",
                    "component_purl": purl, "scope": node.get("scope", "unknown"),
                    "project": node.get("project", project), "dependency_paths": paths, "vuln_id": vid,
                    "aliases": aliases, "cvss": cvss, "severity": severity, "fixed_versions": fixed,
                    "affected_range": rng, "evidence_ids": [ev["evidence_id"]], "status": "open"})
                evidence.append(ev)
    return findings, evidence


def _osv_version() -> str:
    out = subprocess.run([find_tool("osv-scanner"), "--version"], capture_output=True, text=True).stdout
    first = out.splitlines()[0] if out else ""  # "osv-scanner version: 2.7.1"
    return first.split(":", 1)[1].strip() if ":" in first else "unknown"


def osv_scan(ctx):
    """Tool entry point (registry binding `osv`): cross-check on the resolved lockfiles.
    Dev1's detection node dedupes against Grype by (purl, id/alias)."""
    from guardian.tools.registry import ToolOutput

    work = Path(ctx.work_dir or ctx.repo)
    locks = [p for p in (work / "package-lock.json", work / "frontend" / "package-lock.json") if p.is_file()]
    if not locks:
        return ToolOutput(summary="no lockfiles to cross-check")
    raw = Path(ctx.run_dir) / "osv.json"
    doc = run_osv(locks, raw)
    fds, evs = to_models(*parse_osv(doc, ctx.graph, ctx.run_id, raw, _osv_version()))
    return ToolOutput(findings=fds, evidence=evs, summary=f"{len(fds)} vulnerabilities (osv-scanner cross-check)")
