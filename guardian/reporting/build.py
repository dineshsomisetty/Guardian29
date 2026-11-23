"""Build the Guardian Report from a run directory (D4-06).

Reads whatever exists under runs/<run_id>/ and tolerates missing optional files, so the
same code works for the Day-1 output and the full Day-2 run. Files read:

  required   findings.json
  Day 1      graph.json  changes.json  evidence/*.json  trace.jsonl
  Day 2      scores.json            [{finding_id, score, priority, confidence, factors, ...}]
             actions.json           [ActionEntry-shaped]
             approvals.json         [{finding_id, decision, by, at, comment}]
             validations.json       [ValidationEntry-shaped]
             claims.json            {finding_id: [Claim...]}
             guardrail_events.jsonl audit.jsonl

(scores.json / actions.json / approvals.json / validations.json / claims.json are additions
that Dev1's reporter/validator nodes write; shapes follow guardian/reporting/schema.py.)
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from guardian.reporting.schema import Report

LIMITATIONS = [
    "Scoring weights are our own choice (plan section 7); the factor table lets anyone recompute.",
    "Reachability is import-level; function-level 'called' is only shown for hand-picked demo CVEs.",
    "AI-generated explanations are labelled INFERRED unless every asserted value is present in tool evidence.",
    "Findings depend on public advisory data available at scan time (cached copies when offline).",
]


def _read(path: Path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def build_report(run_dir: Path | str, target: str | None = None, now: datetime | None = None) -> Report:
    run = Path(run_dir)
    findings = _read(run / "findings.json", None)
    if findings is None:
        raise FileNotFoundError(f"{run / 'findings.json'} not found; nothing to report")
    graph = _read(run / "graph.json", {"nodes": [], "edges": [], "roots": []})
    changes = _read(run / "changes.json", None)
    scores = {s["finding_id"]: s for s in _read(run / "scores.json", [])}
    claims = _read(run / "claims.json", {})
    actions = _read(run / "actions.json", [])
    approvals = {a["finding_id"]: a for a in _read(run / "approvals.json", [])}
    validations = _read(run / "validations.json", [])

    evidence: dict[str, dict] = {}
    for p in sorted((run / "evidence").glob("*.json")) if (run / "evidence").exists() else []:
        ev = json.loads(p.read_text(encoding="utf-8"))
        evidence[ev.get("evidence_id", p.stem)] = ev

    nodes = graph.get("nodes", [])
    direct = sum(1 for n in nodes if n.get("direct"))
    by_eco: dict[str, int] = {}
    for n in nodes:
        by_eco[n.get("ecosystem", "unknown")] = by_eco.get(n.get("ecosystem", "unknown"), 0) + 1

    f_entries, vuln_paths = [], []
    for f in findings:
        fid = f["finding_id"]
        f_entries.append({
            **{k: f.get(k) for k in ("finding_id", "category", "title", "component_purl", "vuln_id", "severity",
                                     "cvss", "affected_range", "initial_risk", "status") if f.get(k) is not None},
            "scope": f.get("scope", "unknown"),
            "fixed_versions": f.get("fixed_versions", []),
            "dependency_paths": f.get("dependency_paths", []),
            "evidence": [evidence[e] for e in f.get("evidence_ids", []) if e in evidence],
            "claims": claims.get(fid, []),
        })
        if f.get("dependency_paths"):
            vuln_paths.append({"finding_id": fid, "purl": f.get("component_purl"), "paths": f["dependency_paths"]})

    ranking = sorted(
        ({"finding_id": fid, "score": s["score"], "priority": s["priority"], "confidence": s["confidence"],
          "factors": s.get("factors", []), "provenance_bonus": s.get("provenance_bonus", 0),
          "override_applied": s.get("override_applied", False)} for fid, s in scores.items()),
        key=lambda r: -r["score"])

    action_entries = [{**a, "approval": approvals.get(a["finding_id"])} for a in actions]

    verified = {v["finding_id"] for v in validations if v.get("verdict") == "verified"}
    remaining = []
    for f in findings:
        fid = f["finding_id"]
        if fid in verified:
            continue
        appr = approvals.get(fid, {})
        remaining.append({
            "finding_id": fid, "title": f["title"], "status": f.get("status", "open"),
            "reason": "accepted by human" if appr.get("decision") == "accept_risk"
            else "escalated" if f.get("status") == "escalated" else "not verified",
            "priority": scores.get(fid, {}).get("priority") or f.get("initial_risk"),
        })

    summary = {
        "findings_total": len(findings),
        "verified": len(verified),
        "remaining": len(remaining),
        "by_priority": _count([r["priority"] for r in ranking] or [f.get("initial_risk") for f in findings]),
        "by_category": _count([f["category"] for f in findings]),
        "final_confidence": {v["finding_id"]: v.get("final_confidence") for v in validations if v.get("final_confidence")},
    }

    return Report.model_validate({
        "run_id": run.name,
        "target": target,
        "generated_at": (now or datetime.now(UTC)).isoformat(timespec="seconds"),
        "summary": summary,
        "inventory": {
            "component_count": len(nodes), "direct_count": direct, "transitive_count": len(nodes) - direct,
            "roots": graph.get("roots", []), "by_ecosystem": by_eco, "vulnerable_paths": vuln_paths, "changes": changes,
        },
        "findings": f_entries, "ranking": ranking, "actions": action_entries, "validations": validations,
        "remaining_risk": remaining,
        "guardrail_events": _read_jsonl(run / "guardrail_events.jsonl"),
        "audit": _read_jsonl(run / "audit.jsonl"),
        "limitations": LIMITATIONS,
    })


def _count(items) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        if i:
            out[i] = out.get(i, 0) + 1
    return out
