"""Reporter (Day-1 stub): close the remediation loop with a per-finding outcome line. Owner: Dev1.

The Guardian report itself (JSON + HTML, D4-06) is Dev4's; until it is wired this node records the outcome of
every planned finding in the trace and `run_summary.json["remediation"]` (written by the run driver).
"""

from __future__ import annotations

from guardian.core.plans import list_plans, list_validations
from guardian.graph.state import GraphState, get_ctx

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
    rc = get_ctx(state["run_id"])
    outcomes = remediation_outcomes(rc.tool_ctx.run_dir, rc.store)
    rc.audit.emit(AGENT, "agent_start", "Summarising remediation outcomes")
    for o in outcomes:
        rc.audit.emit(AGENT, "decision", f"{o['status']}: {o['title'][:90]} ({len(o['attempts'])} plan(s))",
                      finding_id=o["finding_id"])
    rc.audit.emit(AGENT, "agent_end", f"{len(outcomes)} findings went through the remediation loop "
                                      f"(JSON/HTML report: D4-06)")
    return {"status": "done"}
