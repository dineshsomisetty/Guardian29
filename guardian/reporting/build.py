"""Build the Guardian report from a run directory (D4-06, D1-09). Owner: Dev1 (shape from dev04's skeleton).

Reads only run output files (findings, risk.json, evidence/, plans/, approvals.jsonl, validation/, trace.jsonl),
so it also works on a finished run from the CLI or the API. Everything is redacted (G1.2) before it is written.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from guardian.core.models import Approval, Confidence, Evidence, Finding, FindingStatus
from guardian.core.plans import list_plans, list_validations, load_risks
from guardian.core.store import JsonStore
from guardian.guardrails.redact import redact_obj
from guardian.reporting.schema import Report

EXCERPT_MAX = 2000
_CONF = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def _trim(ev: Evidence) -> Evidence:
    if ev.excerpt and len(ev.excerpt) > EXCERPT_MAX:
        ev = ev.model_copy(update={"excerpt": ev.excerpt[:EXCERPT_MAX] + "...(truncated)"})
    return ev


def build_report(run_dir: Path, summary: dict | None = None, inventory: dict | None = None,
                 target: str | None = None, commit: str | None = None) -> Report:
    run_dir = Path(run_dir)
    store = JsonStore(run_dir)
    if summary is None:
        f = run_dir / "run_summary.json"
        summary = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    findings: list[Finding] = store.list_findings()
    risks = load_risks(run_dir)
    trace = _read_jsonl(run_dir / "trace.jsonl")
    approvals: dict[str, Approval] = {}
    for a in _read_jsonl(run_dir / "approvals.jsonl"):
        approvals[a["plan_id"]] = Approval.model_validate(a)
    validations = list_validations(run_dir)
    plans = list_plans(run_dir)

    entries = []
    for f in findings:
        evs = [_trim(e) for e in (store.get_evidence(i) for i in f.evidence_ids) if e]
        entries.append({"finding": f, "risk": risks.get(f.finding_id), "evidence": evs, "paths": f.dependency_paths})
    ranking = [fid for fid, _ in sorted(((r.finding_id, r.score) for r in risks.values()), key=lambda x: (-x[1], x[0]))]

    actions = [{"plan": p, "approval": approvals.get(p.plan_id),
                "validations": [v for v in validations if v.plan_id == p.plan_id]} for p in plans]

    remaining = [{"finding_id": f.finding_id, "status": f.status.value,
                  "score": risks[f.finding_id].score if f.finding_id in risks else 0}
                 for f in findings if f.status is not FindingStatus.VERIFIED]

    last: dict[str, Confidence] = {}
    for v in validations:  # sorted by attempt id: the last one per finding wins
        last[v.finding_id] = v.final_confidence
    pool = list(last.values()) or [r.confidence for r in risks.values()]
    final = min(pool, key=_CONF.index).value if pool else "low"

    sbom = summary.get("sbom") or {}
    inv = inventory or {"components": sbom.get("components") or 0, "direct": sbom.get("direct") or 0,
                        "transitive": sbom.get("transitive") or 0}
    report = Report.model_validate({
        "run_id": run_dir.name, "target": target or summary.get("target"), "commit": commit or summary.get("commit"),
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"), "summary": summary, "inventory": inv,
        "findings": entries, "ranking": ranking, "actions": actions, "remaining_risk": remaining,
        "final_confidence": final,
        "guardrail_events": [e for e in trace if e.get("type") == "guardrail"],
        "audit": {"events": len(trace), "llm_calls": sum(1 for e in trace if e.get("type") == "llm_call"),
                  "tool_calls": sum(1 for e in trace if e.get("type") == "tool_call")},
    })
    return Report.model_validate(redact_obj(report.model_dump(mode="json")))  # G1.2
