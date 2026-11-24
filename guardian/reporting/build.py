# Document the contract for the surrounding module or callable.
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
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Load json for scan report assembly.
import json
# Import UTC, datetime from datetime.
from datetime import UTC, datetime
# Import Path from pathlib.
from pathlib import Path

# Import Approval, Confidence, Evidence, Finding, FindingStatus from guardian.core.models.
from guardian.core.models import Approval, Confidence, Evidence, Finding, FindingStatus
# Import list_plans, list_validations, load_risks, read_approvals from guardian.core.plans.
from guardian.core.plans import list_plans, list_validations, load_risks, read_approvals
# Import load_recs from guardian.core.recs.
from guardian.core.recs import load_recs
# Import JsonStore from guardian.core.store.
from guardian.core.store import JsonStore
# Import redact_obj from guardian.guardrails.redact.
from guardian.guardrails.redact import redact_obj
# Import narrative from guardian.reporting.
from guardian.reporting import narrative
# Import Report from guardian.reporting.schema.
from guardian.reporting.schema import Report

# Give EXCERPT_MAX its starting value.
# The initial value is 2000.
EXCERPT_MAX = 2000  # evidence excerpts longer than this are cut so report.json/html stay readable
# Confidence ordered weakest to strongest; the report's overall confidence is the weakest one that applies.
# Store an ordered collection in _CONF.
_CONF = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


# Define _read_jsonl for scan report assembly.
# Inputs include path.
def _read_jsonl(path: Path) -> list[dict]:
    # Document the contract for the surrounding module or callable.
    """Parse a JSON-lines file, skipping unparsable lines (e.g. one still being written). Missing file = []."""
    # Check whether not path.exists().
    if not path.exists():
        # Return an ordered collection to the caller.
        return []
    # Store an ordered collection in out.
    out = []
    # Iterate over path.read_text(encoding='utf-8').splitlines().
    # Bind each item to ln before processing it.
    for ln in path.read_text(encoding="utf-8").splitlines():
        # Run the following operation with exception handling.
        # The handlers below determine how the listed failures are handled.
        try:
            # Call out.append at this point.
            out.append(json.loads(ln))
        # Handle ValueError from the preceding block.
        except ValueError:
            # Skip the remaining work for this item.
            continue
    # Return out to the caller.
    return out


# Define _trim for scan report assembly.
# Inputs include ev.
def _trim(ev: Evidence) -> Evidence:
    # Document the contract for the surrounding module or callable.
    """Copy of the evidence with an over-long excerpt truncated; the stored evidence file is left untouched."""
    # Check whether ev.excerpt and len(ev.excerpt) > EXCERPT_MAX.
    if ev.excerpt and len(ev.excerpt) > EXCERPT_MAX:
        # Store the result of ev.model_copy in ev.
        ev = ev.model_copy(update={"excerpt": ev.excerpt[:EXCERPT_MAX] + "...(truncated)"})
    # Return ev to the caller.
    return ev


# Define _supported for scan report assembly.
# Inputs include f.
def _supported(f: Finding) -> Finding:
    # Document the contract for the surrounding module or callable.
    """Copy of the finding without claims that grounding labelled unsupported (they must not appear, G4.6)."""
    # Store values selected or transformed from the input in keep.
    keep = [c for c in f.claims if c.label.value != "unsupported"]
    # Return the expression on this line to the caller.
    return f if len(keep) == len(f.claims) else f.model_copy(update={"claims": keep})


# Define _supported_risk for scan report assembly.
# Inputs include r.
def _supported_risk(r):
    # Document the contract for the surrounding module or callable.
    """Same filter for the claims of a risk assessment."""
    # Check whether r is None.
    if r is None:
        # Return None to represent an absent value to the caller.
        return None
    # Store values selected or transformed from the input in keep.
    keep = [c for c in r.claims if c.label.value != "unsupported"]
    # Return the expression on this line to the caller.
    return r if len(keep) == len(r.claims) else r.model_copy(update={"claims": keep})


# Assemble the run artifacts and available snapshots into a report.
# Inputs include run_dir, summary, inventory, target, commit.
def build_report(run_dir: Path, summary: dict | None = None, inventory: dict | None = None,
                 # Continue the function signature with its remaining arguments.
                 target: str | None = None, commit: str | None = None) -> Report:
    # Document the contract for the surrounding module or callable.
    """Assemble the Report for `run_dir` purely from files the run already wrote (nothing is re-analysed).

    summary / inventory / target / commit default to what run_summary.json says; pass them when the caller
    already has fresher values. The result is redacted (G1.2) so secrets that leaked into evidence are masked.
    """
    # Store the result of Path in run_dir.
    run_dir = Path(run_dir)
    # Store the result of JsonStore in store.
    store = JsonStore(run_dir)
    # Check whether summary is None.
    if summary is None:
        # Store run_dir / 'run_summary.json' in f.
        f = run_dir / "run_summary.json"
        # Store the expression on this line in summary.
        summary = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    # Declare findings with type list[Finding].
    # Use the result of store.list_findings as its initial value.
    findings: list[Finding] = store.list_findings()
    # Store the result of load_risks in risks.
    risks = load_risks(run_dir)
    # Store the result of _read_jsonl in trace.
    trace = _read_jsonl(run_dir / "trace.jsonl")
    # Declare approvals with type dict[str, Approval].
    # Use a mapping keyed by the fields below as its initial value.
    approvals: dict[str, Approval] = {}
    # Declare decisions_log with type list[Approval].
    # Use an ordered collection as its initial value.
    decisions_log: list[Approval] = []  # every decision in order: the "who decided what" table keeps rejections too
    # Iterate over read_approvals(run_dir).
    # Bind each item to a before processing it.
    for a in read_approvals(run_dir):  # withdrawn decisions are not part of the report
        # Store the result of Approval.model_validate in approvals[a['plan_id']].
        approvals[a["plan_id"]] = Approval.model_validate(a)
        # Call decisions_log.append at this point.
        decisions_log.append(approvals[a["plan_id"]])
    # Store the result of list_validations in validations.
    validations = list_validations(run_dir)
    # Store the result of list_plans in plans.
    plans = list_plans(run_dir)

    # Store an ordered collection in entries.
    entries = []
    # Iterate over findings.
    # Bind each item to f before processing it.
    for f in findings:
        # Store values selected or transformed from the input in evs.
        evs = [_trim(e) for e in (store.get_evidence(i) for i in f.evidence_ids) if e]
        # Call entries.append at this point.
        entries.append({"finding": _supported(f), "risk": _supported_risk(risks.get(f.finding_id)), "evidence": evs,
                        # Provide the mapping fields paths on this line.
                        "paths": f.dependency_paths})
    # Store values selected or transformed from the input in ranking.
    ranking = [fid for fid, _ in sorted(((r.finding_id, r.score) for r in risks.values()), key=lambda x: (-x[1], x[0]))]

    # Define pr_path for scan report assembly.
    # Inputs include vs.
    def pr_path(vs: list) -> str | None:
        # Document the contract for the surrounding module or callable.
        """Run-relative path of PR.md for the first *verified* attempt of a plan, if that file exists."""
        # Iterate over vs.
        # Bind each item to v before processing it.
        for v in vs:
            # Check whether the expression on this line.
            if v.verdict == "verified" and (run_dir / "attempts" / v.attempt_id / "PR.md").is_file():
                # Return f'attempts/{v.attempt_id}/PR.md' to the caller.
                return f"attempts/{v.attempt_id}/PR.md"
        # Return None to represent an absent value to the caller.
        return None

    # Store values selected or transformed from the input in actions.
    actions = [{"plan": p, "approval": approvals.get(p.plan_id),
                # Provide the mapping fields validations on this line.
                "validations": (vs := [v for v in validations if v.plan_id == p.plan_id]),
                # Provide the mapping fields pr_markdown on this line.
                "pr_markdown": pr_path(vs)} for p in plans]

    # finding id -> plan whose validation ended "mitigated" (risk reduced but the vulnerable code stays)
    # Store a lookup built from the input records in mitigated.
    mitigated = {v.finding_id: p for p in plans for v in validations if v.plan_id == p.plan_id and v.verdict == "mitigated"}
    # Declare rec_notes with type dict[str, str].
    # Use a mapping keyed by the fields below as its initial value.
    rec_notes: dict[str, str] = {}  # batch mode: why a finding has no fix (no alternative / needs a person)
    # Check whether (run_dir / 'recommendations.json').is_file().
    if (run_dir / "recommendations.json").is_file():
        # Iterate over load_recs(run_dir)['items'].
        # Bind each item to r before processing it.
        for r in load_recs(run_dir)["items"]:
            # Check whether r.outcome in ('no_alternative', 'needs_person') and r.reason.
            if r.outcome in ("no_alternative", "needs_person") and r.reason:
                # Iterate over r.finding_ids.
                # Bind each item to fid before processing it.
                for fid in r.finding_ids:
                    # Store r.reason in rec_notes[fid].
                    rec_notes[fid] = r.reason
    # remaining risk = every finding not verified as fixed, with a note on why (accepted mitigation / no fix offered)
    # Store values selected or transformed from the input in remaining.
    remaining = [{"finding_id": f.finding_id, "status": f.status.value,
                  # Provide the mapping fields score on this line.
                  "score": risks[f.finding_id].score if f.finding_id in risks else 0,
                  # Provide the mapping fields note on this line.
                  "note": (f"accepted mitigation, NOT fixed: {mitigated[f.finding_id].expected_risk_reduction}"
                           # Use this clause to iterate or filter the surrounding expression.
                           # The collection includes the results of the completed expression.
                           if f.finding_id in mitigated and f.status is FindingStatus.ACCEPTED
                           # Supply the alternative for the preceding condition.
                           # This path covers the case where the earlier branch does not apply.
                           else rec_notes.get(f.finding_id))}
                 # Use this clause to iterate or filter the surrounding expression.
                 # The collection includes the results of the completed expression.
                 for f in findings if f.status is not FindingStatus.VERIFIED]
    # Call remaining.sort at this point.
    remaining.sort(key=lambda r: (-r["score"], r["finding_id"]))  # highest risk first

    # Declare last with type dict[str, Confidence].
    # Use a mapping keyed by the fields below as its initial value.
    last: dict[str, Confidence] = {}
    # Iterate over validations.
    # Bind each item to v before processing it.
    for v in validations:  # sorted by attempt id: the last one per finding wins
        # Store v.final_confidence in last[v.finding_id].
        last[v.finding_id] = v.final_confidence
    # overall confidence is only as strong as the weakest finding: validation results if any, else risk confidence
    # Store list(last.values()) or [r.confidence for r in risks.values()] in pool.
    pool = list(last.values()) or [r.confidence for r in risks.values()]
    # Store min(pool, key=_CONF.index).value if pool else 'low' in final.
    final = min(pool, key=_CONF.index).value if pool else "low"

    # Store summary.get('sbom') or {} in sbom.
    sbom = summary.get("sbom") or {}
    # Store the expression on this line in inv.
    inv = inventory or {"components": sbom.get("components") or 0, "direct": sbom.get("direct") or 0,
                        # Provide the mapping fields transitive on this line.
                        "transitive": sbom.get("transitive") or 0}
    # Store the expression on this line in recs.
    recs = load_recs(run_dir)["items"] if (run_dir / "recommendations.json").is_file() else []
    # Store the result of narrative.Ctx in ctx.
    ctx = narrative.Ctx(run_dir, findings, risks, plans, decisions_log, validations, recs)
    # Store the result of narrative.method in meth.
    meth = narrative.method(ctx, trace, summary, validations)
    # Store the result of narrative.validations in vrows.
    vrows = narrative.validations(ctx, store)
    # Store the result of datetime.now(UTC).isoformat in now.
    now = datetime.now(UTC).isoformat(timespec="seconds")
    # Store the result of Report.model_validate in report.
    report = Report.model_validate({
        # Provide the mapping fields run_id, target, commit on this line.
        "run_id": run_dir.name, "target": target or summary.get("target"), "commit": commit or summary.get("commit"),
        # Provide the mapping fields generated_at, summary, inventory on this line.
        "generated_at": now, "summary": summary, "inventory": inv,
        # Provide the mapping fields findings, ranking, actions, remaining_risk on this line.
        "findings": entries, "ranking": ranking, "actions": actions, "remaining_risk": remaining,
        # Provide the mapping fields final_confidence on this line.
        "final_confidence": final,
        # Provide the mapping fields guardrail_events on this line.
        "guardrail_events": [e for e in trace if e.get("type") == "guardrail"],
        # Provide the mapping fields audit, llm_calls on this line.
        "audit": {"events": len(trace), "llm_calls": sum(1 for e in trace if e.get("type") == "llm_call"),
                  # Provide the mapping fields tool_calls on this line.
                  "tool_calls": sum(1 for e in trace if e.get("type") == "tool_call")},
        # Provide the mapping fields overview on this line.
        "overview": narrative.overview(ctx, summary, inv, target or summary.get("target"), commit or summary.get("commit"),
                                       # Supply the next part of the expression started above.
                                       now, final, meth),
        # Provide the mapping fields fixes, decisions, open_groups on this line.
        "fixes": narrative.fixes(ctx), "decisions": narrative.decisions(ctx), "open_groups": narrative.open_groups(ctx),
        # Provide the mapping fields attention, score_guide, method on this line.
        "attention": narrative.attention(ctx), "score_guide": narrative.score_guide(ctx), "method": meth,
        # Provide the mapping fields appendix, ranked, validations on this line.
        "appendix": narrative.appendix(ctx), "ranked": narrative.ranked(ctx), "validations": vrows,
        # Provide the mapping fields before_after, guardrails_triggered on this line.
        "before_after": narrative.before_after(ctx, vrows), "guardrails_triggered": narrative.guardrails(trace),
        # Provide the mapping fields audit_trail on this line.
        "audit_trail": narrative.audit_trail(trace),
    # Close the current expression or collection.
    })
    # Return the result of Report.model_validate to the caller.
    return Report.model_validate(redact_obj(report.model_dump(mode="json")))  # G1.2
