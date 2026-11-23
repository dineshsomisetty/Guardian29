"""LangGraph orchestration + run driver. Owner: Dev1.

Day-1 graph (§2.2; investigator = D1-08 and the full §7 risk analyst = D1-06 come on Day 2):

    START -> discovery -> detection -> evidence_analyst -> risk_analyst
          -> [ remediation -> human_gate -> record_decision -> validator ]*  -> reporter -> END
                 ^  reject / failed validation: re-plan (different plan)  |
                 |________________________________________________________|

The human gate is its own node containing only `interrupt()` (C6). State is checkpointed in
runs/<id>/checkpoints.sqlite (thread id = run id), so a run paused at the gate is resumed later — from the CLI
(`guardian decide`) or the API — in a new process, with the same plan_id. Every routing choice is a `decision`
event with its reason (§2.4).
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from datetime import datetime
from pathlib import Path

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from guardian.agents.detection import detection_node
from guardian.agents.discovery import discovery_node
from guardian.agents.evidence_analyst import evidence_analyst_node
from guardian.agents.human_gate import human_gate_node, record_decision_node
from guardian.agents.remediation import remediation_node
from guardian.agents.reporter import remediation_outcomes, reporter_node
from guardian.agents.risk_analyst import risk_analyst_node
from guardian.agents.validator import validator_node
from guardian.core.audit import AuditLog
from guardian.core.config import Settings, load_settings
from guardian.core.models import Approval, Finding, FindingCategory, Priority, utcnow
from guardian.core.plans import get_pending
from guardian.core.store import JsonStore
from guardian.graph.state import GraphState, RunContext, get_ctx, register, unregister
from guardian.guardrails.approval import check_decision
from guardian.guardrails.budgets import Budget
from guardian.llm.provider import LLMProvider
from guardian.tools.registry import ToolContext, ToolUnavailable, resolve

# ---------------------------------------------------------------- supervisor routing


def route_after_discovery(state: GraphState) -> str:
    audit = get_ctx(state["run_id"]).audit
    if not state.get("sbom_evidence_id"):
        audit.emit("supervisor", "decision",
                   "No SBOM evidence from discovery -> still routing to detection (detectors work on files)")
    else:
        audit.emit("supervisor", "decision", "SBOM + graph ready -> detection", evidence_ids=[state["sbom_evidence_id"]])
    return "detection"


def route_after_detection(state: GraphState) -> str:
    audit = get_ctx(state["run_id"]).audit
    n = len(state.get("finding_ids", []))
    if n == 0:
        audit.emit("supervisor", "decision", "No findings -> end of run (nothing to analyse)")
        return END
    audit.emit("supervisor", "decision", f"{n} findings with evidence -> evidence_analyst for explanation + initial risk")
    return "evidence_analyst"


def route_next(state: GraphState) -> str:
    """Next finding in the remediation queue, or the reporter when the queue is done."""
    audit = get_ctx(state["run_id"]).audit
    queue = state.get("plan_queue") or []
    if queue:
        audit.emit("supervisor", "decision", f"{len(queue)} finding(s) left in the remediation queue -> remediation")
        return "remediation"
    audit.emit("supervisor", "decision", "Remediation queue empty -> reporter")
    return "reporter"


def route_after_remediation(state: GraphState) -> str:
    if state.get("route") == "gate":
        get_ctx(state["run_id"]).audit.emit("supervisor", "decision",
                                            f"Plan {state['plan_id']} ready -> human_gate (no change without approval)")
        return "human_gate"
    return route_next(state)


def route_after_decision(state: GraphState) -> str:
    audit = get_ctx(state["run_id"]).audit
    route = state.get("route")
    if route == "validate":
        audit.emit("supervisor", "decision", f"Plan {state['plan_id']} approved -> validator")
        return "validator"
    if route == "replan":
        audit.emit("supervisor", "decision", "Plan rejected -> remediation must propose a different plan")
        return "remediation"
    if route == "gate":
        return "human_gate"
    return route_next(state)


def route_after_validation(state: GraphState) -> str:
    if state.get("route") == "replan":
        get_ctx(state["run_id"]).audit.emit(
            "supervisor", "decision",
            f"Validation {state['last_validation']['verdict']} -> remediation re-plans (different plan)")
        return "remediation"
    return route_next(state)


def route_after_risk(state: GraphState) -> str:
    return "remediation" if state.get("plan_queue") else route_next(state)


def build_graph(checkpointer=None):
    g = StateGraph(GraphState)
    for name, fn in [("discovery", discovery_node), ("detection", detection_node),
                     ("evidence_analyst", evidence_analyst_node), ("risk_analyst", risk_analyst_node),
                     ("remediation", remediation_node), ("human_gate", human_gate_node),
                     ("record_decision", record_decision_node), ("validator", validator_node),
                     ("reporter", reporter_node)]:
        g.add_node(name, fn)
    g.add_edge(START, "discovery")
    g.add_conditional_edges("discovery", route_after_discovery, ["detection"])
    g.add_conditional_edges("detection", route_after_detection, ["evidence_analyst", END])
    g.add_edge("evidence_analyst", "risk_analyst")
    g.add_conditional_edges("risk_analyst", route_after_risk, ["remediation", "reporter"])
    g.add_conditional_edges("remediation", route_after_remediation, ["human_gate", "remediation", "reporter"])
    g.add_edge("human_gate", "record_decision")
    g.add_conditional_edges("record_decision", route_after_decision,
                            ["validator", "remediation", "human_gate", "reporter"])
    g.add_conditional_edges("validator", route_after_validation, ["remediation", "reporter"])
    g.add_edge("reporter", END)
    return g.compile(checkpointer=checkpointer)


# ---------------------------------------------------------------- outputs

_RISK_ORDER = [Priority.CRITICAL, Priority.HIGH, Priority.MEDIUM, Priority.LOW]
_PSEUDO_KIND = {
    FindingCategory.UNPINNED_CI: "ci",
    FindingCategory.UNTRUSTED_IMAGE: "image",
    FindingCategory.LOCKFILE: "config",
}


def _max_risk(risks: list[Priority | None]) -> str | None:
    for r in _RISK_ORDER:
        if r in risks:
            return r.value
    return None


def pseudo_node_id(f: Finding) -> str:
    kind = _PSEUDO_KIND.get(f.category, "config")
    if kind == "image" and f.component_purl:
        return f"image:{f.component_purl}"
    return f"{kind}:{f.file_path or f.title}"


def build_graph_json(ctx: ToolContext, findings: list[Finding]) -> dict:
    graph = ctx.graph
    data: dict = {"nodes": [], "edges": [], "roots": ["root"]}
    if graph is not None:
        if hasattr(graph, "add_pseudo_nodes"):
            try:
                graph.add_pseudo_nodes(findings)
            except Exception:  # noqa: BLE001  Dev1 adds them below if Dev2's helper fails
                pass
        data = graph.to_json() if hasattr(graph, "to_json") else dict(graph)
    elif "graph_json" in ctx.artifacts:
        data = ctx.artifacts["graph_json"]

    nodes = {n["id"]: n for n in data.get("nodes", [])}
    edges = data.setdefault("edges", [])
    roots = data.setdefault("roots", ["root"])
    by_node: dict[str, list[Finding]] = {}
    for f in findings:
        nid = f.component_purl if f.component_purl in nodes else None
        if nid is None:
            if f.category is FindingCategory.CVE or (f.component_purl and f.component_purl.startswith("pkg:")):
                nid = f.component_purl or pseudo_node_id(f)
                if nid not in nodes:
                    nodes[nid] = {"id": nid, "kind": "package", "label": nid.split("/")[-1], "direct": None,
                                  "project": f.project}
            else:
                nid = pseudo_node_id(f)
                if nid not in nodes:
                    kind = nid.split(":", 1)[0]
                    nodes[nid] = {"id": nid, "kind": kind, "label": nid.split(":", 1)[1].split("/")[-1]}
                    edges.append({"source": f.project if f.project in roots else roots[0], "target": nid,
                                  "type": "uses"})
        by_node.setdefault(nid, []).append(f)
    for nid, fs in by_node.items():
        n = nodes[nid]
        n["finding_ids"] = sorted({*n.get("finding_ids", []), *(f.finding_id for f in fs)})
        n["risk"] = _max_risk([f.initial_risk for f in fs])
    data["nodes"] = list(nodes.values())
    return data


def git_commit(repo: Path) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def build_summary(run_id: str, ctx: ToolContext, findings: list[Finding], status: str, started: datetime,
                  settings: Settings, llm_model: str | None) -> dict:
    stats = {}
    if ctx.graph is not None and hasattr(ctx.graph, "stats"):
        try:
            stats = ctx.graph.stats()
        except Exception:  # noqa: BLE001
            stats = {}
    by_risk = {r.value: 0 for r in _RISK_ORDER}
    by_cat: dict[str, int] = {}
    for f in findings:
        if f.initial_risk:
            by_risk[f.initial_risk.value] += 1
        by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
    return {
        "run_id": run_id,
        "target": ctx.repo.name,
        "commit": git_commit(ctx.repo),
        "started_at": started.isoformat(),
        "finished_at": utcnow().isoformat(),
        "status": status,
        "sbom": {"file": "sbom.cdx.json" if (ctx.run_dir / "sbom.cdx.json").exists() else None,
                 "components": stats.get("components"), "direct": stats.get("direct"),
                 "transitive": stats.get("transitive")},
        "projects": stats.get("projects") or ["root"],
        "findings": {"total": len(findings), "by_risk": by_risk, "by_category": by_cat},
        "llm": {"mode": settings.llm_mode, "model": llm_model},
        "offline": settings.offline,
    }


# ---------------------------------------------------------------- driver


class DecisionRejected(ValueError):
    """The decision does not match the pending plan (G5.1) or lacks a required comment (G5.2)."""


def new_run_id() -> str:
    return "run_" + datetime.now().strftime("%Y%m%d_%H%M%S")


def _config(run_id: str) -> dict:
    return {"configurable": {"thread_id": run_id}, "recursion_limit": 200}


def _rebuild_graph(ctx: ToolContext) -> None:
    """A resumed process has no live graph object: rebuild it from the work copy's lockfiles (cheap,
    deterministic), else fall back to the graph.json already written."""
    try:
        ctx.graph = resolve("guardian.core.graph_build:build_graph")(ctx).artifacts.get("graph")
    except (ToolUnavailable, Exception):  # noqa: BLE001
        ctx.graph = None
    if ctx.graph is None and (ctx.run_dir / "graph.json").exists():
        ctx.artifacts["graph_json"] = json.loads((ctx.run_dir / "graph.json").read_text(encoding="utf-8"))


def _finalize(run_id: str, rc: RunContext, settings: Settings, started: datetime, status: str) -> dict:
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    run_dir = ctx.run_dir
    findings = store.list_findings()
    (run_dir / "graph.json").write_text(json.dumps(build_graph_json(ctx, findings), indent=1), encoding="utf-8")
    if "changes" in ctx.artifacts:
        (run_dir / "changes.json").write_text(json.dumps(ctx.artifacts["changes"], indent=2, default=str),
                                              encoding="utf-8")
    summary = build_summary(run_id, ctx, findings, status, started, settings, rc.llm.model if rc.llm else None)
    summary["remediation"] = remediation_outcomes(run_dir, store)
    pending = get_pending(run_dir)
    summary["pending_plan"] = {"plan_id": pending.plan_id, "plan_hash": pending.plan_hash,
                               "finding_id": pending.finding_id} if pending and status == "awaiting_human" else None
    if ctx.budget is not None:
        summary["budget"] = ctx.budget.snapshot()
    (run_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (settings.runs_dir / "LATEST").write_text(run_id, encoding="utf-8")
    end = (f"Run paused at the human gate: plan {pending.plan_id} awaits a decision"
           if status == "awaiting_human" and pending else
           f"Run {status}: {summary['findings']['total']} findings, by risk {summary['findings']['by_risk']}")
    audit.emit("supervisor", "agent_end", end)
    return summary


def _drive(run_id: str, rc: RunContext, settings: Settings, started: datetime, graph_input) -> Path:
    run_dir = rc.tool_ctx.run_dir
    conn = sqlite3.connect(run_dir / "checkpoints.sqlite", check_same_thread=False)
    register(rc)
    status = "failed"
    try:
        app = build_graph(SqliteSaver(conn))
        final = app.invoke(graph_input, _config(run_id))
        status = "awaiting_human" if final.get("__interrupt__") else "done"
        if final.get("errors") and status == "done":
            rc.audit.emit("supervisor", "decision", f"Run finished with {len(final['errors'])} degraded steps",
                          data={"errors": final["errors"]})
    except Exception as exc:
        rc.audit.emit("supervisor", "error", f"Run failed: {type(exc).__name__}: {str(exc)[:300]}")
        raise
    finally:
        try:
            _finalize(run_id, rc, settings, started, status)
        finally:
            unregister(run_id)
            conn.close()
    return run_dir


def _write_running(run_dir: Path, run_id: str, started: datetime) -> None:
    (run_dir / "run_summary.json").write_text(
        json.dumps({"run_id": run_id, "status": "running", "started_at": started.isoformat()}, indent=2),
        encoding="utf-8")


def run(repo: Path, run_id: str | None = None, settings: Settings | None = None,
        llm: LLMProvider | None = None, echo: bool = True, compare_ref: str | None = None) -> Path:
    settings = settings or load_settings()
    run_id = run_id or new_run_id()
    run_dir = settings.runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    started = utcnow()
    _write_running(run_dir, run_id, started)

    audit = AuditLog(run_dir, run_id, echo=echo)
    store = JsonStore(run_dir)
    tool_ctx = ToolContext(run_id=run_id, run_dir=run_dir, repo=repo.resolve(), settings=settings,
                           budget=Budget(max_llm_tokens=settings.max_llm_tokens))
    if compare_ref:
        tool_ctx.artifacts["compare_ref"] = compare_ref
    if llm is None:
        llm = LLMProvider.from_settings(settings)
    rc = RunContext(tool_ctx=tool_ctx, store=store, audit=audit, llm=llm)
    audit.emit("supervisor", "agent_start", f"Run {run_id} on {tool_ctx.repo.name}",
               data={"llm": settings.describe(), "compare_ref": compare_ref})
    return _drive(run_id, rc, settings, started, {
        "run_id": run_id, "status": "discovering", "finding_ids": [], "errors": [], "repo": str(tool_ctx.repo),
        "compare_ref": compare_ref, "plan_queue": [], "current": None, "attempt": 0, "plan_id": None,
        "decision": None, "route": None, "last_validation": None})


def resume(run_id: str, approval: Approval, settings: Settings | None = None, llm: LLMProvider | None = None,
           echo: bool = True) -> Path:
    """Continue a run paused at the human gate with a human decision. The decision is checked against the
    pending plan first (G5.1/G5.2); an invalid one raises DecisionRejected and nothing resumes."""
    settings = settings or load_settings()
    run_dir = settings.runs_dir / run_id
    pending = get_pending(run_dir)
    if pending is None:
        raise DecisionRejected(f"run {run_id} is not waiting for a decision")
    reason = check_decision(pending, approval)
    if reason:
        raise DecisionRejected(reason)
    lock = run_dir / ".resume.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise DecisionRejected(f"run {run_id} is already resuming") from exc
    os.close(fd)
    try:
        summary = json.loads((run_dir / "run_summary.json").read_text(encoding="utf-8"))
        started = datetime.fromisoformat(summary["started_at"])
        conn = sqlite3.connect(run_dir / "checkpoints.sqlite", check_same_thread=False)
        try:
            values = build_graph(SqliteSaver(conn)).get_state(_config(run_id)).values
        finally:
            conn.close()
        audit = AuditLog(run_dir, run_id, echo=echo)
        store = JsonStore(run_dir)
        tool_ctx = ToolContext(run_id=run_id, run_dir=run_dir, repo=Path(values["repo"]), settings=settings,
                               work_dir=Path(values["work_dir"]) if values.get("work_dir") else None,
                               sbom_path=Path(values["sbom_path"]) if values.get("sbom_path") else None,
                               budget=Budget(max_llm_tokens=settings.max_llm_tokens))
        if values.get("compare_ref"):
            tool_ctx.artifacts["compare_ref"] = values["compare_ref"]
        if (run_dir / "changes.json").exists():
            tool_ctx.artifacts["changes"] = json.loads((run_dir / "changes.json").read_text(encoding="utf-8"))
        _rebuild_graph(tool_ctx)
        rc = RunContext(tool_ctx=tool_ctx, store=store, audit=audit, llm=llm)
        _write_running(run_dir, run_id, started)
        audit.emit("supervisor", "agent_start", f"Resuming {run_id}: {approval.decision} on plan {approval.plan_id}")
        return _drive(run_id, rc, settings, started, Command(resume=approval.model_dump(mode="json")))
    finally:
        lock.unlink(missing_ok=True)
