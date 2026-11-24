"""Demo sandbox run before the human gate (GUARDIAN_DEMO_VALIDATOR=1). Owner: Dev1.

The real validator (Docker install/build/tests + SBOM rescan) takes minutes, too long for a live demo. In demo mode
this node plays the sandbox phases for the pending plan over GUARDIAN_DEMO_SANDBOX_SECONDS (default 6s) and then
opens the human gate. Nothing is applied or executed here: every event carries data.simulated=True, and the
validator that runs after the approval still applies the plan to a fresh copy and re-runs the detectors for real
(without the Docker sandbox). Events are emitted as the `validator` agent so the pipeline view lights "Validation"
before "Approval".
"""

from __future__ import annotations

import time

from guardian.core.plans import load_plan
from guardian.graph.state import GraphState, get_ctx

AGENT = "validator"

# (phase, weight of the total duration, summary template)
STEPS = [
    ("isolate", 0.10, "Sandbox: fresh copy of {target} in an isolated container (network: package registry only)"),
    ("apply", 0.12, "Sandbox: applying plan {plan_id} - {change}"),
    ("install", 0.22, "Sandbox: installing dependencies with scripts disabled (--ignore-scripts)"),
    ("build", 0.16, "Sandbox: build OK"),
    ("tests", 0.22, "Sandbox: unit tests passed, no new failures versus the unpatched baseline"),
    ("rescan", 0.18, "Sandbox: SBOM rescan + diff - {vuln} no longer reported, 0 new vulnerabilities"),
]


def _change(plan, f) -> str:
    pkg = (f.component_purl or f.file_path or f.title).split("/")[-1].split("@")[0]
    if plan.target_version:
        return f"{plan.action} {pkg} -> {plan.target_version}"
    return f"{plan.action} {pkg} ({len(plan.ops)} ops)"


def sandbox_preview_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    plan = load_plan(ctx.run_dir, state["plan_id"])
    f = store.get_finding(plan.finding_id)
    total = max(0.0, float(ctx.settings.demo_sandbox_seconds))
    common = {"plan_id": plan.plan_id, "simulated": True, "demo": True}
    values = {"target": ctx.repo.name, "plan_id": plan.plan_id, "change": _change(plan, f),
              "vuln": f.vuln_id or f.title[:60]}

    audit.emit(AGENT, "agent_start", f"Sandbox validation (demo) for plan {plan.plan_id}: {f.title[:80]}",
               finding_id=f.finding_id, evidence_ids=plan.evidence_ids, data={**common, "seconds": total})
    started = time.monotonic()
    for phase, weight, text in STEPS:
        time.sleep(total * weight)
        audit.emit(AGENT, "sandbox_step", text.format(**values), finding_id=f.finding_id,
                   data={**common, "phase": phase})
    took = time.monotonic() - started
    audit.emit(AGENT, "agent_end", f"Sandbox validation (demo) finished in {took:.1f}s -> human approval",
               finding_id=f.finding_id, data={**common, "seconds": round(took, 1)})
    audit.emit("human_gate", "gate_wait", f"Waiting for a human decision on plan {plan.plan_id} "
                                         f"(guardian decide --run {state['run_id']} --plan {plan.plan_id} ...)",
               finding_id=f.finding_id, data={"plan_id": plan.plan_id, "plan_hash": plan.plan_hash})
    return {}
