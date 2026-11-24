"""Continuous monitoring (D1-11, stretch 6): re-check a finished or paused run against fresh threat intel.

`python -m guardian watch --run <id> [--interval 1h] [--once]`

Reloads the stored inventory (sbom.cdx.json, graph.json, findings.json, risk.json) and does NOT re-run discovery,
scanners or detectors. Each check
  1. refreshes OSV advisories for the SBOM components (cache max-age capped by GUARDIAN_INTEL_MAX_AGE, default 15 min
     in watch mode; offline mode reads the cache only) -> advisories not yet in findings.json become Findings
     (category cve, detector "watch:osv") with an `osv` Evidence;
  2. refreshes EPSS/KEV through the risk analyst's tool path (threat_intel, G3 allowlist, G3.5 network check) and
     re-runs the section-7 scoring (`risk_analyst.build_factors` + `scoring.compute`) for every finding;
  3. writes runs/<id>/watch/<ts>.json {checked_at, new_findings, escalated, unchanged, ...}, updates risk.json,
     appends every changed score to risk.history.jsonl and `watch` decision events (agent "supervisor") to trace.jsonl.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path

from guardian.agents.risk_analyst import (
    NOT_APPLICABLE,
    Gathered,
    _collect,
    build_factors,
    package_of,
    template_summary,
)
from guardian.core.audit import AuditLog
from guardian.core.config import Settings, load_settings
from guardian.core.models import Evidence, Finding, FindingCategory, Priority, RiskAssessment, Scope, utcnow
from guardian.core.plans import load_risks, save_risks
from guardian.core.scoring import compute, initial_risk
from guardian.core.store import JsonStore
from guardian.graph.state import RunContext
from guardian.tools.registry import ToolContext
from guardian.tools.scanners import _osv_fixed
from guardian.tools.threat_intel import IntelClient, parse_purl

DEFAULT_MAX_AGE_S = 900  # watch mode: advisories older than this in the intel cache are refetched
DEFAULT_MAX_COMPONENTS = 400  # OSV lookups per check (cached + throttled); existing findings and direct deps first
_RANK = {Priority.LOW: 0, Priority.MEDIUM: 1, Priority.HIGH: 2, Priority.CRITICAL: 3}


class WatchError(Exception):
    pass


def parse_interval(text: str) -> float:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*", text or "")
    if not m:
        raise ValueError(f"bad interval {text!r}; use e.g. 30s, 15m, 1h, 1d")
    return float(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _vuln_keys(purl: str | None, ids) -> set[tuple[str, str]]:
    return {(purl or "", str(i).upper()) for i in ids if i}


def _inventory(run_dir: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    """({purl: {name, version}} from the SBOM, {purl: graph node} from graph.json)."""
    sbom = run_dir / "sbom.cdx.json"
    if not sbom.exists():
        raise WatchError(f"{run_dir.name} has no sbom.cdx.json: nothing to watch")
    comps = {}
    for c in json.loads(sbom.read_text(encoding="utf-8")).get("components", []):
        if c.get("purl"):
            comps[c["purl"]] = {"name": c.get("name"), "version": c.get("version")}
    nodes: dict[str, dict] = {}
    gpath = run_dir / "graph.json"
    if gpath.exists():
        nodes = {n["id"]: n for n in json.loads(gpath.read_text(encoding="utf-8")).get("nodes", [])
                 if n.get("kind") == "package"}
    return comps, nodes


def _watch_set(comps: dict, nodes: dict, findings: list[Finding], limit: int) -> list[str]:
    with_findings = [f.component_purl for f in findings if f.component_purl in comps]
    direct = sorted(p for p in comps if nodes.get(p, {}).get("direct") and nodes[p].get("scope") != "dev")
    prod = sorted(p for p in comps if nodes.get(p, {}).get("scope") != "dev")
    ordered = list(dict.fromkeys([*with_findings, *direct, *prod]))
    return ordered[:limit]


def _advisory_finding(run_id: str, purl: str, comp: dict, vuln: dict, node: dict, checked_at: str,
                      ) -> tuple[Finding, Evidence]:
    name, version = comp.get("name") or parse_purl(purl)[0], comp.get("version")
    ids = [vuln["id"], *vuln.get("aliases", [])]
    cve = next((i for i in ids if i.upper().startswith("CVE-")), None)
    primary = cve or vuln["id"]
    aliases = [i for i in ids if i != primary]
    severity = ((vuln.get("database_specific") or {}).get("severity") or "").lower() or None
    fixed = _osv_fixed(vuln, name)
    ev = Evidence(run_id=run_id, kind="osv", source_tool="watch:osv",
                  facts={"vuln_id": primary, "aliases": aliases, "severity": severity, "purl": purl, "name": name,
                         "version": version, "fixed_versions": fixed, "published": vuln.get("published"),
                         "modified": vuln.get("modified"), "checked_at": checked_at, "source": "osv.dev",
                         "new_since_scan": True},
                  excerpt=(vuln.get("summary") or vuln.get("details") or "")[:400] or None)
    scope = Scope(node["scope"]) if node.get("scope") in ("prod", "dev") else Scope.UNKNOWN
    f = Finding(run_id=run_id, category=FindingCategory.CVE, title=f"{primary} in {name}@{version}",
                detector="watch:osv", component_purl=purl, scope=scope, project=node.get("project"),
                vuln_id=primary, aliases=aliases, severity=severity, fixed_versions=fixed,
                evidence_ids=[ev.evidence_id])
    f.initial_risk = initial_risk(f)
    f.initial_risk_source = "rule"
    return f, ev


def _rescore(rc: RunContext, findings: list[Finding], old: dict[str, RiskAssessment], has_work: bool,
             ) -> dict[str, RiskAssessment]:
    store = rc.store
    pkgs = {f.finding_id: (None if f.category in NOT_APPLICABLE else package_of(f, store)) for f in findings}
    g: Gathered = _collect(rc, findings, pkgs)
    out: dict[str, RiskAssessment] = {}
    for f in findings:
        factors = build_factors(f, pkgs[f.finding_id], g)
        prev = old.get(f.finding_id)
        if prev is not None:
            if factors.E.unknown and not prev.factors.E.unknown:
                factors.E = prev.factors.E  # a cache miss never de-escalates a known exploitability signal
            if not has_work:  # no work copy to search: keep the earlier R/P/X
                factors.R, factors.P, factors.X = prev.factors.R, prev.factors.P, prev.factors.X
            factors.provenance_modifier = prev.factors.provenance_modifier
            factors.provenance_evidence_ids = prev.factors.provenance_evidence_ids
        c = compute(factors)
        a = RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band, confidence=c.confidence,
                           override_applied=c.override_applied, factors=factors, summary="")
        if prev is not None and abs(prev.score - a.score) < 0.005 and prev.band is a.band:
            out[f.finding_id] = prev  # nothing moved: keep the LLM summary and claims
            continue
        a.summary = template_summary(f, a)
        out[f.finding_id] = a
    return out


def _next_path(wdir: Path, ts: datetime) -> Path:
    base = ts.strftime("%Y%m%dT%H%M%SZ")
    p = wdir / f"{base}.json"
    n = 1
    while p.exists():
        p = wdir / f"{base}-{n}.json"
        n += 1
    return p


def watch_once(run_id: str, settings: Settings | None = None, intel: IntelClient | None = None,
               max_age_s: float = DEFAULT_MAX_AGE_S, max_components: int = DEFAULT_MAX_COMPONENTS,
               echo: bool = False) -> dict:
    settings = settings or load_settings()
    run_dir = settings.runs_dir / run_id
    summary_path = run_dir / "run_summary.json"
    if not summary_path.exists():
        raise WatchError(f"unknown run {run_id}")
    status = json.loads(summary_path.read_text(encoding="utf-8")).get("status")
    if status in ("running", "failed", None):
        raise WatchError(f"run {run_id} is {status}; watch needs a finished or paused run")

    comps, nodes = _inventory(run_dir)
    store = JsonStore(run_dir)
    audit = AuditLog(run_dir, run_id, echo=echo)
    work = run_dir / "work"
    ctx = ToolContext(run_id=run_id, run_dir=run_dir, repo=work if work.is_dir() else run_dir, settings=settings,
                      work_dir=work if work.is_dir() else None)
    ctx.artifacts["graph_json"] = {"nodes": list(nodes.values())}
    rc = RunContext(tool_ctx=ctx, store=store, audit=audit, llm=None)
    checked_at = utcnow()
    stamp = checked_at.isoformat()
    findings = store.list_findings()
    old = load_risks(run_dir)

    prev_env = os.environ.get("GUARDIAN_INTEL_MAX_AGE")
    os.environ["GUARDIAN_INTEL_MAX_AGE"] = str(max_age_s)
    try:
        client = intel or IntelClient(ctx=ctx, agent="supervisor", max_age=max_age_s)
        watch_set = _watch_set(comps, nodes, findings, max_components)
        audit.emit("supervisor", "decision",
                   f"watch: checking {len(watch_set)}/{len(comps)} components against fresh OSV/EPSS/KEV "
                   f"(offline={client.offline}, cache max-age {int(max_age_s)}s); no discovery re-run",
                   data={"watch": True, "phase": "start", "components": len(watch_set), "offline": client.offline})

        known: set[tuple[str, str]] = set()
        for f in findings:
            if f.category is FindingCategory.CVE:
                known |= _vuln_keys(f.component_purl, [f.vuln_id, *f.aliases])
        new_findings: list[Finding] = []
        for purl in watch_set:
            for vuln in client.osv_query(purl):
                if vuln.get("withdrawn"):
                    continue
                ids = [vuln["id"], *vuln.get("aliases", [])]
                if _vuln_keys(purl, ids) & known:
                    continue
                f, ev = _advisory_finding(run_id, purl, comps[purl], vuln, nodes.get(purl, {}), stamp)
                store.add_evidence(ev)
                store.add_finding(f)
                known |= _vuln_keys(purl, ids)
                new_findings.append(f)

        findings = store.list_findings()
        new_ids = {f.finding_id for f in new_findings}
        fresh = _rescore(rc, findings, old, has_work=work.is_dir())
    finally:
        if prev_env is None:
            os.environ.pop("GUARDIAN_INTEL_MAX_AGE", None)
        else:
            os.environ["GUARDIAN_INTEL_MAX_AGE"] = prev_env

    by_id = {f.finding_id: f for f in findings}
    escalated, deescalated, unchanged, history = [], [], 0, []
    hist_path = run_dir / "risk.history.jsonl"
    if not hist_path.exists():
        history += [{"checked_at": stamp, "finding_id": fid, "score": a.score, "band": a.band.value,
                     "reason": "baseline"} for fid, a in old.items()]
    for fid, a in fresh.items():
        if fid in new_ids:
            history.append({"checked_at": stamp, "finding_id": fid, "score": a.score, "band": a.band.value,
                            "reason": "new_advisory"})
            continue
        b = old.get(fid)
        if b is None or (abs(b.score - a.score) < 0.005 and b.band is a.band):
            unchanged += 1
            continue
        row = {"finding_id": fid, "title": by_id[fid].title,
               "before": {"score": b.score, "band": b.band.value}, "after": {"score": a.score, "band": a.band.value}}
        (escalated if a.score > b.score or _RANK[a.band] > _RANK[b.band] else deescalated).append(row)
        history.append({"checked_at": stamp, "finding_id": fid, "score": a.score, "band": a.band.value,
                        "prev_score": b.score, "prev_band": b.band.value, "reason": "rescored"})

    ranked = sorted(fresh.values(), key=lambda a: (-a.score, a.finding_id))
    save_risks(run_dir, ranked)
    if history:
        with hist_path.open("a", encoding="utf-8") as fh:
            fh.writelines(json.dumps(h) + "\n" for h in history)

    result = {
        "run_id": run_id, "checked_at": stamp, "offline": bool(client.offline),
        "components_checked": len(watch_set), "components_total": len(comps),
        "new_findings": [{"finding_id": f.finding_id, "vuln_id": f.vuln_id, "title": f.title,
                          "component_purl": f.component_purl, "detector": f.detector,
                          "evidence_ids": f.evidence_ids, "initial_risk": f.initial_risk.value if f.initial_risk else None,
                          "score": fresh[f.finding_id].score, "band": fresh[f.finding_id].band.value}
                         for f in new_findings],
        "escalated": escalated, "deescalated": deescalated, "unchanged": unchanged,
    }
    wdir = run_dir / "watch"
    wdir.mkdir(exist_ok=True)
    path = _next_path(wdir, checked_at)
    path.write_text(json.dumps(result, indent=1), encoding="utf-8")
    result["path"] = str(path)
    audit.emit("supervisor", "decision",
               f"watch: {len(new_findings)} new advisories, {len(escalated)} escalated, {len(deescalated)} "
               f"de-escalated, {unchanged} unchanged -> watch/{path.name}",
               evidence_ids=sorted({e for f in new_findings for e in f.evidence_ids})[:50],
               data={"watch": True, "phase": "result", "new_findings": [f.finding_id for f in new_findings],
                     "escalated": escalated[:20], "unchanged": unchanged, "file": f"watch/{path.name}"})
    return result


def watch_loop(run_id: str, interval_s: float, once: bool = False, settings: Settings | None = None,
               **kw) -> int:
    settings = settings or load_settings()
    try:
        while True:
            r = watch_once(run_id, settings, **kw)
            print(f"[watch {r['checked_at']}] {len(r['new_findings'])} new, {len(r['escalated'])} escalated, "
                  f"{r['unchanged']} unchanged  ({r['components_checked']}/{r['components_total']} components)"
                  f"  -> {r['path']}")
            if once:
                return 0
            time.sleep(interval_s)
    except KeyboardInterrupt:
        print("watch stopped")
        return 0
