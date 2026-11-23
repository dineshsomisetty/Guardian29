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


def _osv_cache_path(work, locks):
    """OSV-Scanner output cached by the content of the scanned lockfiles (G7.4), so an offline run sees the
    same advisories as the recorded online run (and therefore the same LLM prompts in replay)."""
    import hashlib
    import os
    from pathlib import Path

    from guardian.core.config import REPO_ROOT

    h = hashlib.sha256()
    for lf in sorted(locks, key=lambda p: p.relative_to(work).as_posix()):
        h.update(lf.relative_to(work).as_posix().encode() + b"\0" + lf.read_bytes() + b"\0")
    root = Path(os.environ.get("GUARDIAN_INTEL_CACHE") or REPO_ROOT / "data" / "cache" / "intel")
    return root / "osv-scanner" / f"{h.hexdigest()[:32]}.json"


def osv_scan(ctx: ToolContext) -> ToolOutput:
    work = ctx.work_dir or ctx.repo
    locks = [p.lockfile for p in find_projects(work) if p.lockfile.exists()]
    # pip: OSV-Scanner reads requirements.txt as a lockfile (pinned lines are what it can match)
    from guardian.adapters import pypi

    locks += [r for proj in pypi.find_projects(work) for r in proj.requirements]
    # Maven: OSV-Scanner reads pom.xml (top level and one module level down; never target/ build output)
    locks += [p for p in [work / "pom.xml", *sorted(work.glob("*/pom.xml"))]
              if p.is_file() and "target" not in p.relative_to(work).parts]
    if not locks:
        raise RuntimeError("no lockfiles or requirements files for OSV")
    cache = _osv_cache_path(work, locks)
    if cache.is_file():
        stdout = cache.read_text(encoding="utf-8")
    elif ctx.settings.offline:
        # OSV-Scanner always queries api.osv.dev: offline with no cached result, skip (Grype stays primary)
        raise RuntimeError("offline (GUARDIAN_OFFLINE=1) and no cached OSV result for these lockfiles: skipped")
    else:
        args = [find("osv-scanner"), "scan", "source", "--format", "json"]
        for lf in locks:
            args += ["-L", str(lf)]
        stdout = run(args, timeout=600, ok_codes=(0, 1)).stdout
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(stdout, encoding="utf-8")
    raw_path = ctx.run_dir / "osv.json"
    raw_path.write_text(stdout, encoding="utf-8")
    data = json.loads(stdout or "{}")
    tool = "osv-scanner@2.7.1"
    evidence = [Evidence(run_id=ctx.run_id, kind="osv", source_tool=tool, facts={"results": len(data.get("results", []))},
                         artifact_path="osv.json", sha256=sha256_file(raw_path))]
    findings = []
    from guardian.adapters.npm import purl as npm_purl

    def mk_purl(name: str, version: str, ecosystem: str) -> str:
        return pypi.purl(name, version) if ecosystem.lower() == "pypi" else npm_purl(name, version)

    for res in data.get("results", []):
        for pkg in res.get("packages", []):
            info = pkg.get("package", {})
            p = mk_purl(info.get("name", ""), info.get("version", ""), info.get("ecosystem", "npm"))
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
