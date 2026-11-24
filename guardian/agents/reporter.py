"""Reporter (D1-09/D4-06): per-finding outcome lines in the trace and `report.json` + `report.html`. Owner: Dev1.

`remediation_outcomes` also feeds `run_summary.json["remediation"]` (written by the run driver).
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
    validations: dict[str, list] = {}
    for v in list_validations(run_dir):
        validations.setdefault(v.plan_id, []).append(v)
    out: dict[str, dict] = {}
    for p in list_plans(run_dir):
        f = store.get_finding(p.finding_id)
        entry = out.setdefault(p.finding_id, {"finding_id": p.finding_id, "title": f.title if f else None,
                                              "category": f.category.value if f else None, "attempts": []})
        entry["status"] = f.status.value if f else None
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
    outcomes = remediation_outcomes(ctx.run_dir, store)
    for o in outcomes:
        audit.emit(AGENT, "decision", f"{o['status']}: {(o['title'] or '')[:90]} ({len(o['attempts'])} plan(s))",
                   finding_id=o["finding_id"])
    from guardian.graph.workflow import build_summary  # lazy: workflow imports this module

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
    inventory = None
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
