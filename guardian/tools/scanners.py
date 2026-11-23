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
