"""D2-04 vulnerability scanners -> CVE Findings with evidence. Owner: Dev2.

grype  : `grype sbom:<run>/sbom.cdx.json -o json`            (primary, fix versions + affected range)
osv    : `osv-scanner scan source -L <lockfile>... --format json`  (cross-check; exit 1 = vulns found)
Duplicates across the two are merged by the detection agent on (purl, id/alias).
"""

from __future__ import annotations

import json
import re

from guardian.adapters.npm import find_projects
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.binaries import find, run, sha256_file, version
from guardian.tools.registry import ToolContext, ToolOutput


def _node_meta(ctx: ToolContext, purl: str | None) -> dict:
    g = ctx.graph
    if g is not None and purl and purl in g.g:
        return g.g.nodes[purl]
    return {}


def _scope(meta: dict) -> Scope:
    return Scope(meta["scope"]) if meta.get("scope") in ("prod", "dev") else Scope.UNKNOWN


def _best_cvss(entries: list[dict]) -> float | None:
    scores = [e.get("metrics", {}).get("baseScore") for e in entries or []]
    scores = [s for s in scores if isinstance(s, int | float)]
    return max(scores) if scores else None


def grype_scan(ctx: ToolContext) -> ToolOutput:
    if ctx.sbom_path is None:
        raise RuntimeError("no SBOM to scan")
    raw_path = ctx.run_dir / "grype.json"
    proc = run([find("grype"), f"sbom:{ctx.sbom_path}", "-o", "json", "-q"], timeout=900)
    raw_path.write_text(proc.stdout, encoding="utf-8")
    data = json.loads(proc.stdout)
    tool = f"grype@{version('grype')}"
    raw_ev = Evidence(run_id=ctx.run_id, kind="scanner_output", source_tool=tool,
                      facts={"matches": len(data.get("matches", []))}, artifact_path="grype.json",
                      sha256=sha256_file(raw_path))
    findings, evidence = [], [raw_ev]
    for m in data.get("matches", []):
        v, art = m.get("vulnerability", {}), m.get("artifact", {})
        related = m.get("relatedVulnerabilities", [])
        aliases = sorted({r["id"] for r in related if r.get("id") and r["id"] != v.get("id")})
        cvss = _best_cvss(v.get("cvss")) or _best_cvss([c for r in related for c in r.get("cvss", [])])
        constraint = next((d.get("found", {}).get("versionConstraint") for d in m.get("matchDetails", [])
                           if d.get("found", {}).get("versionConstraint")), None)
        affected = re.sub(r"\s*\(\w+\)\s*$", "", constraint) if constraint else None
        fixed = v.get("fix", {}).get("versions", []) or []
        p = art.get("purl")
        meta = _node_meta(ctx, p)
        desc = (v.get("description") or next((r.get("description") for r in related if r.get("description")), "")
                or "")[:400]
        ev = Evidence(run_id=ctx.run_id, kind="scanner_output", source_tool=tool,
                      facts={"vuln_id": v.get("id"), "aliases": aliases, "severity": v.get("severity"),
                             "cvss": cvss, "fixed_versions": fixed, "fix_state": v.get("fix", {}).get("state"),
                             "affected_range": affected, "purl": p, "name": art.get("name"),
                             "version": art.get("version"), "data_source": v.get("dataSource")},
                      excerpt=desc or None, artifact_path="grype.json",
                      file_path=(art.get("locations") or [{}])[0].get("path", "").lstrip("/") or None)
        evidence.append(ev)
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.CVE,
            title=f"{v.get('id')} in {art.get('name')}@{art.get('version')}", detector=tool,
            component_purl=p, scope=_scope(meta), project=meta.get("project"), file_path=ev.file_path,
            vuln_id=v.get("id"), aliases=aliases, cvss=cvss, severity=v.get("severity"), fixed_versions=fixed,
            affected_range=affected, evidence_ids=[ev.evidence_id]))
    return ToolOutput(findings=findings, evidence=evidence,
                      summary=f"{len(findings)} vulnerability matches")


def _osv_fixed(vuln: dict, name: str) -> list[str]:
    out = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name") != name:
            continue
        for rng in aff.get("ranges", []):
            out.extend(ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev)
    return sorted(set(out))


def osv_scan(ctx: ToolContext) -> ToolOutput:
    work = ctx.work_dir or ctx.repo
    locks = [p.lockfile for p in find_projects(work) if p.lockfile.exists()]
    if not locks:
        raise RuntimeError("no lockfiles for OSV")
    args = [find("osv-scanner"), "scan", "source", "--format", "json"]
    for lf in locks:
        args += ["-L", str(lf)]
    proc = run(args, timeout=600, ok_codes=(0, 1))
    raw_path = ctx.run_dir / "osv.json"
    raw_path.write_text(proc.stdout, encoding="utf-8")
    data = json.loads(proc.stdout or "{}")
    tool = "osv-scanner@2.7.1"
    evidence = [Evidence(run_id=ctx.run_id, kind="osv", source_tool=tool, facts={"results": len(data.get("results", []))},
                         artifact_path="osv.json", sha256=sha256_file(raw_path))]
    findings = []
    from guardian.adapters.npm import purl as mk_purl

    for res in data.get("results", []):
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            p = mk_purl(info.get("name", ""), info.get("version", ""))
            meta = _node_meta(ctx, p)
            groups = pkg.get("groups", [])
            for vuln in pkg.get("vulnerabilities", []):
                vid = vuln.get("id")
                grp = next((g for g in groups if vid in g.get("ids", [])), {})
                try:
                    cvss = float(grp.get("max_severity")) if grp.get("max_severity") else None
                except ValueError:
                    cvss = None
                aliases = sorted(set(vuln.get("aliases", [])) | set(grp.get("ids", [])) - {vid})
                fixed = _osv_fixed(vuln, info.get("name"))
                ev = Evidence(run_id=ctx.run_id, kind="osv", source_tool=tool,
                              facts={"vuln_id": vid, "aliases": aliases, "cvss": cvss, "fixed_versions": fixed,
                                     "purl": p, "name": info.get("name"), "version": info.get("version")},
                              excerpt=(vuln.get("summary") or "")[:300] or None, artifact_path="osv.json")
                evidence.append(ev)
                findings.append(Finding(
                    run_id=ctx.run_id, category=FindingCategory.CVE,
                    title=f"{vid} in {info.get('name')}@{info.get('version')}", detector=tool, component_purl=p,
                    scope=_scope(meta), project=meta.get("project"), vuln_id=vid, aliases=aliases, cvss=cvss,
                    fixed_versions=fixed, evidence_ids=[ev.evidence_id]))
    return ToolOutput(findings=findings, evidence=evidence, summary=f"{len(findings)} OSV advisories (cross-check)")
