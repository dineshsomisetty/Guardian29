"""Reporter (D1-09/D4-06): per-finding outcome lines in the trace and `report.json` + `report.html`. Owner: Dev1.

`remediation_outcomes` also feeds `run_summary.json["remediation"]` (written by the run driver).

Role in the pipeline
  Last node of both modes: sequential (remediation loop done) and batch (validate_batch / record_batch routed to
  "report"), or straight after detection when nothing was found. It is read-only with respect to findings and plans:
  it never changes a status, it only summarises what the earlier agents did.

Inputs
  Graph state: run_id. Store: all findings. Run files: plans/*.json (every plan ever proposed), validation/*.json
  (every ValidationResult, one per attempt or per plan of a combined run), run_summary.json (only for `started_at`),
  the dependency graph's stats (inventory counts), and ctx.artifacts["run_llm"] (LLM usage totals).

Outputs
  State key {"status": "done"}. Files under runs/<id>/: report.json and report.html (reporting.render.write_reports);
  the summary dict it builds carries "remediation" (per-finding attempts with action, target, verdict, attempt_id).
  Audit events: agent_start, one "decision" line per finding (final status and number of plans), agent_end, or an
  "error" when the report cannot be written.

Tools, LLM, guardrails
  No tool calls and no LLM: the report is rendered from stored data only, so it cannot say more than the evidence
  and the validator recorded (an accepted risk is listed as remaining risk, a failed fix as failed).
  A report failure is logged and swallowed on purpose: a rendering bug must not turn a finished run into a failed one.
"""

from __future__ import annotations

import json
from datetime import datetime

from guardian.core.models import utcnow
from guardian.core.plans import list_plans, list_validations
from guardian.graph.state import GraphState, get_ctx
from guardian.reporting.render import write_reports

AGENT = "reporter"


def remediation_outcomes(run_dir, store) -> list[dict]:
    """One entry per finding that got at least one plan: its title, category, final status and every attempt.

    An attempt is {plan_id, action, target, verdict, attempt_id}; verdict / attempt_id are None for a plan that was
    never validated (rejected, accepted as risk, or still waiting). A plan validated several times (combined run
    plus isolation runs) yields one attempt per validation. Pure read of plans/ and validation/ plus the store."""
    validations: dict[str, list] = {}
    for v in list_validations(run_dir):
        validations.setdefault(v.plan_id, []).append(v)
    out: dict[str, dict] = {}
    for p in list_plans(run_dir):
        f = store.get_finding(p.finding_id)
        entry = out.setdefault(p.finding_id, {"finding_id": p.finding_id, "title": f.title if f else None,
                                              "category": f.category.value if f else None, "attempts": []})
        entry["status"] = f.status.value if f else None
        # `or [None]`: a plan with no validation result still shows up as an attempt, with an empty verdict
        for v in validations.get(p.plan_id, []) or [None]:
            entry["attempts"].append({"plan_id": p.plan_id, "action": p.action, "target": p.target_version,
                                      "verdict": v.verdict if v else None,
                                      "attempt_id": v.attempt_id if v else None})
    return list(out.values())


def reporter_node(state: GraphState) -> dict:
    """Write report.json + report.html (D4-06). Runs after the remediation loop, or straight after detection
    when there were no findings."""
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    audit.emit(AGENT, "agent_start", "Building the Guardian report")
    # always returns {"status": "done"}, also when rendering fails (see the module docstring)
    outcomes = remediation_outcomes(ctx.run_dir, store)
    for o in outcomes:
        audit.emit(AGENT, "decision", f"{o['status']}: {(o['title'] or '')[:90]} ({len(o['attempts'])} plan(s))",
                   finding_id=o["finding_id"])
    from guardian.graph.workflow import build_summary  # lazy: workflow imports this module

    # keep the original start time when run_summary.json already exists (the run driver wrote it earlier), so the
    # report's duration covers the whole run and not just this node
    started = utcnow()
    prev = ctx.run_dir / "run_summary.json"
    if prev.exists():
        try:
            started = datetime.fromisoformat(json.loads(prev.read_text(encoding="utf-8"))["started_at"])
        except (KeyError, ValueError):
            pass
    findings = store.list_findings()
    summary = build_summary(ctx.run_id, ctx, findings, "done", started, ctx.settings, rc.llm.model if rc.llm else None)
    if "run_llm" in ctx.artifacts:
        summary["llm"] = ctx.artifacts["run_llm"]
    summary["remediation"] = outcomes
    inventory = None  # SBOM component counts for the report header; None when no dependency graph was built
    if ctx.graph is not None and hasattr(ctx.graph, "stats"):
        st = ctx.graph.stats()
        inventory = {"components": st.get("components", 0), "direct": st.get("direct", 0),
                     "transitive": st.get("transitive", 0)}
    try:
        j, h = write_reports(ctx.run_dir, summary=summary, inventory=inventory, target=ctx.repo.name,
                             commit=summary.get("commit"))
    except Exception as exc:  # noqa: BLE001  a report failure must not fail the run
        audit.emit(AGENT, "error", f"report failed: {type(exc).__name__}: {str(exc)[:200]}")
        return {"status": "done"}
    audit.emit(AGENT, "agent_end", f"{len(outcomes)} findings went through the remediation loop; wrote {j.name} "
                                   f"and {h.name}", data={"files": [j.name, h.name]})
    return {"status": "done"}
