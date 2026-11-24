"""Build the Guardian report from a run directory (D4-06, D1-09). Owner: Dev1 (shape from dev04's skeleton).

Reads only run output files (findings, risk.json, evidence/, plans/, approvals.jsonl, validation/, trace.jsonl),
so it also works on a finished run from the CLI or the API. Everything is redacted (G1.2) before it is written.

Called by `write_reports` (guardian/reporting/render.py), which the workflow runs when a run ends or pauses.
Input: a run directory (plus optional summary/inventory/target/commit overrides). Output: a validated `Report`
(guardian/reporting/schema.py) whose sections are: findings with their evidence and risk, the risk ranking (factor tables), validation attempts,
before/after comparison,
remediation actions with approvals/validations/PR text, the remaining (unfixed) risk, an overall final
confidence, guardrail events and audit counters.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from guardian.core.models import Approval, Confidence, Evidence, Finding, FindingStatus
from guardian.core.plans import list_plans, list_validations, load_risks, read_approvals
from guardian.core.recs import load_recs
from guardian.core.store import JsonStore
from guardian.guardrails.redact import redact_obj
from guardian.reporting import narrative
from guardian.reporting.schema import Report

EXCERPT_MAX = 2000  # evidence excerpts longer than this are cut so report.json/html stay readable
# Confidence ordered weakest to strongest; the report's overall confidence is the weakest one that applies.
_CONF = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


def _read_jsonl(path: Path) -> list[dict]:
    """Parse a JSON-lines file, skipping unparsable lines (e.g. one still being written). Missing file = []."""
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
    """Copy of the evidence with an over-long excerpt truncated; the stored evidence file is left untouched."""
    if ev.excerpt and len(ev.excerpt) > EXCERPT_MAX:
        ev = ev.model_copy(update={"excerpt": ev.excerpt[:EXCERPT_MAX] + "...(truncated)"})
    return ev


def _supported(f: Finding) -> Finding:
    """Copy of the finding without claims that grounding labelled unsupported (they must not appear, G4.6)."""
    keep = [c for c in f.claims if c.label.value != "unsupported"]
    return f if len(keep) == len(f.claims) else f.model_copy(update={"claims": keep})


def _supported_risk(r):
    """Same filter for the claims of a risk assessment."""
    if r is None:
        return None
    keep = [c for c in r.claims if c.label.value != "unsupported"]
    return r if len(keep) == len(r.claims) else r.model_copy(update={"claims": keep})


def build_report(run_dir: Path, summary: dict | None = None, inventory: dict | None = None,
                 target: str | None = None, commit: str | None = None) -> Report:
    """Assemble the Report for `run_dir` purely from files the run already wrote (nothing is re-analysed).

    summary / inventory / target / commit default to what run_summary.json says; pass them when the caller
    already has fresher values. The result is redacted (G1.2) so secrets that leaked into evidence are masked.
    """
    run_dir = Path(run_dir)
    store = JsonStore(run_dir)
    if summary is None:
        f = run_dir / "run_summary.json"
        summary = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    findings: list[Finding] = store.list_findings()
    risks = load_risks(run_dir)
    trace = _read_jsonl(run_dir / "trace.jsonl")
    approvals: dict[str, Approval] = {}
    decisions_log: list[Approval] = []  # every decision in order: the "who decided what" table keeps rejections too
    for a in read_approvals(run_dir):  # withdrawn decisions are not part of the report
        approvals[a["plan_id"]] = Approval.model_validate(a)
        decisions_log.append(approvals[a["plan_id"]])
    validations = list_validations(run_dir)
    plans = list_plans(run_dir)

    entries = []
    for f in findings:
        evs = [_trim(e) for e in (store.get_evidence(i) for i in f.evidence_ids) if e]
        entries.append({"finding": _supported(f), "risk": _supported_risk(risks.get(f.finding_id)), "evidence": evs,
                        "paths": f.dependency_paths})
    ranking = [fid for fid, _ in sorted(((r.finding_id, r.score) for r in risks.values()), key=lambda x: (-x[1], x[0]))]

    def pr_path(vs: list) -> str | None:
        """Run-relative path of PR.md for the first *verified* attempt of a plan, if that file exists."""
        for v in vs:
            if v.verdict == "verified" and (run_dir / "attempts" / v.attempt_id / "PR.md").is_file():
                return f"attempts/{v.attempt_id}/PR.md"
        return None

    actions = [{"plan": p, "approval": approvals.get(p.plan_id),
                "validations": (vs := [v for v in validations if v.plan_id == p.plan_id]),
                "pr_markdown": pr_path(vs)} for p in plans]

    # finding id -> plan whose validation ended "mitigated" (risk reduced but the vulnerable code stays)
    mitigated = {v.finding_id: p for p in plans for v in validations if v.plan_id == p.plan_id and v.verdict == "mitigated"}
    rec_notes: dict[str, str] = {}  # batch mode: why a finding has no fix (no alternative / needs a person)
    if (run_dir / "recommendations.json").is_file():
        for r in load_recs(run_dir)["items"]:
            if r.outcome in ("no_alternative", "needs_person") and r.reason:
                for fid in r.finding_ids:
                    rec_notes[fid] = r.reason
    # remaining risk = every finding not verified as fixed, with a note on why (accepted mitigation / no fix offered)
    remaining = [{"finding_id": f.finding_id, "status": f.status.value,
                  "score": risks[f.finding_id].score if f.finding_id in risks else 0,
                  "note": (f"accepted mitigation, NOT fixed: {mitigated[f.finding_id].expected_risk_reduction}"
                           if f.finding_id in mitigated and f.status is FindingStatus.ACCEPTED
                           else rec_notes.get(f.finding_id))}
                 for f in findings if f.status is not FindingStatus.VERIFIED]
    remaining.sort(key=lambda r: (-r["score"], r["finding_id"]))  # highest risk first

    last: dict[str, Confidence] = {}
    for v in validations:  # sorted by attempt id: the last one per finding wins
        last[v.finding_id] = v.final_confidence
    # overall confidence is only as strong as the weakest finding: validation results if any, else risk confidence
    pool = list(last.values()) or [r.confidence for r in risks.values()]
    final = min(pool, key=_CONF.index).value if pool else "low"

    sbom = summary.get("sbom") or {}
    inv = inventory or {"components": sbom.get("components") or 0, "direct": sbom.get("direct") or 0,
                        "transitive": sbom.get("transitive") or 0}
    recs = load_recs(run_dir)["items"] if (run_dir / "recommendations.json").is_file() else []
    ctx = narrative.Ctx(run_dir, findings, risks, plans, decisions_log, validations, recs)
    meth = narrative.method(ctx, trace, summary, validations)
    vrows = narrative.validations(ctx, store)
    now = datetime.now(UTC).isoformat(timespec="seconds")
    report = Report.model_validate({
        "run_id": run_dir.name, "target": target or summary.get("target"), "commit": commit or summary.get("commit"),
        "generated_at": now, "summary": summary, "inventory": inv,
        "findings": entries, "ranking": ranking, "actions": actions, "remaining_risk": remaining,
        "final_confidence": final,
        "guardrail_events": [e for e in trace if e.get("type") == "guardrail"],
        "audit": {"events": len(trace), "llm_calls": sum(1 for e in trace if e.get("type") == "llm_call"),
                  "tool_calls": sum(1 for e in trace if e.get("type") == "tool_call")},
        "overview": narrative.overview(ctx, summary, inv, target or summary.get("target"), commit or summary.get("commit"),
                                       now, final, meth),
        "fixes": narrative.fixes(ctx), "decisions": narrative.decisions(ctx), "open_groups": narrative.open_groups(ctx),
        "attention": narrative.attention(ctx), "score_guide": narrative.score_guide(ctx), "method": meth,
        "appendix": narrative.appendix(ctx), "ranked": narrative.ranked(ctx), "validations": vrows,
        "before_after": narrative.before_after(ctx, vrows), "guardrails_triggered": narrative.guardrails(trace),
        "audit_trail": narrative.audit_trail(trace),
    })
    return Report.model_validate(redact_obj(report.model_dump(mode="json")))  # G1.2
