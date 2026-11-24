"""LangGraph orchestration + run driver. Owner: Dev1.

Graph (§2.2; the investigator is D1-08, the full §7 risk analyst D1-06 is still the Day-1 form):

    START -> discovery -> detection -> evidence_analyst -> investigator -> risk_analyst
          -> [ remediation -> (sandbox_preview) -> human_gate -> record_decision -> validator ]*  -> reporter -> END
                 ^  reject / failed validation: re-plan (different plan)  |
                 |________________________________________________________|     (sequential mode)
          -> [ recommend -> batch_gate -> record_batch -> validate_batch ]*  -> reporter -> END   (batch mode)

Batch mode (the default): `recommend` gives every finding a recommendation and opens one pending batch; the run waits
at `batch_gate` until every fix has a decision (approvals are held, not validated one by one); `validate_batch` then
validates all approved fixes together. Rejected or failed items loop back to `recommend` for their next alternative.

The human gate is its own node containing only `interrupt()` (C6). State is checkpointed in
runs/<id>/checkpoints.sqlite (thread id = run id), so a run paused at the gate is resumed later — from the CLI
(`guardian decide`) or the API — in a new process, with the same plan_id. Every routing choice is a `decision`
event with its reason (§2.4).

Reading guide for this file, top to bottom:
  1. routing functions `route_*`   the supervisor: pure decisions over GraphState, each emitting a `decision` event
  2. `build_graph`                 wires nodes and conditional edges (the only place the topology is defined)
  3. output helpers                graph.json / run_summary.json content written when a run ends or pauses
  4. driver: `run`, `resume`, `resume_batch`   start a run or continue one paused at the gate; they validate the
                                   human decision (G5.1/G5.2) BEFORE touching the graph, then `_drive` it

A run that reaches the gate ends the `invoke` call with an interrupt, not an exception: `_drive` records
status "awaiting_human", `_finalize` writes the summary (including the pending plan/batch) and the process may exit.
The `Command(resume=...)` of a later `resume` continues from the checkpoint with the human's decision as the value.

Demo mode (GUARDIAN_DEMO_VALIDATOR=1): one critical finding, a ~6s simulated sandbox run (sandbox_preview) before
the gate, and no Docker sandbox in the validator after approval.
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

from guardian.agents.batch import batch_gate_node, recommend_node, record_batch_node, validate_batch_node
from guardian.agents.detection import detection_node
from guardian.agents.discovery import discovery_node
from guardian.agents.evidence_analyst import evidence_analyst_node
from guardian.agents.human_gate import human_gate_node, record_decision_node
from guardian.agents.investigator import investigator_node
from guardian.agents.remediation import remediation_node
from guardian.agents.reporter import remediation_outcomes, reporter_node
from guardian.agents.risk_analyst import risk_analyst_node
from guardian.agents.sandbox_preview import sandbox_preview_node
from guardian.agents.validator import validator_node
from guardian.core.audit import AuditLog
from guardian.core.config import Settings, load_settings
from guardian.core.models import Approval, Finding, FindingCategory, Priority, utcnow
from guardian.core.plans import get_pending, get_pending_batch
from guardian.core.recs import load_recs
from guardian.core.store import JsonStore
from guardian.graph.state import GraphState, RunContext, get_ctx, register, unregister
from guardian.guardrails.approval import check_batch, check_decision
from guardian.guardrails.budgets import Budget
from guardian.llm.provider import LLMProvider
from guardian.tools.registry import ToolContext, ToolUnavailable, resolve

# ---------------------------------------------------------------- supervisor routing


def route_after_discovery(state: GraphState) -> str:
    """Always go to detection; only the logged reason differs (detectors also work on plain files, so a
    missing SBOM degrades the run but does not stop it)."""
    audit = get_ctx(state["run_id"]).audit
    if not state.get("sbom_evidence_id"):
        audit.emit("supervisor", "decision",
                   "No SBOM evidence from discovery -> still routing to detection (detectors work on files)")
    else:
        audit.emit("supervisor", "decision", "SBOM + graph ready -> detection", evidence_ids=[state["sbom_evidence_id"]])
    return "detection"


def route_after_detection(state: GraphState) -> str:
    """No findings -> straight to the reporter (a clean report is still written); else evidence analyst."""
    audit = get_ctx(state["run_id"]).audit
    n = len(state.get("finding_ids", []))
    if n == 0:
        audit.emit("supervisor", "decision", "No findings -> reporter (nothing to analyse, report still written)")
        return "reporter"
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
    """Sequential mode: a plan is ready (route "gate") -> human gate; nothing planned -> next finding or report."""
    if state.get("route") == "gate":
        rc = get_ctx(state["run_id"])
        if rc.tool_ctx.settings.demo_validator:
            rc.audit.emit("supervisor", "decision",
                          f"Plan {state['plan_id']} ready -> sandbox validation (demo, nothing applied) -> human_gate")
            return "sandbox_preview"
        rc.audit.emit("supervisor", "decision",
                      f"Plan {state['plan_id']} ready -> human_gate (no change without approval)")
        return "human_gate"
    return route_next(state)


def route_after_decision(state: GraphState) -> str:
    """After the human's decision (sequential mode), by `state["route"]` set in record_decision:
    validate (approved), replan (rejected: remediation must offer a different plan), gate (decision refused,
    ask again), anything else: this finding is finished (e.g. risk accepted) -> next in the queue."""
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
    """A failed validation (route "replan") sends the finding back to remediation for a different plan, until
    the attempt limit (G5.4) escalates it; otherwise continue with the queue."""
    if state.get("route") == "replan":
        get_ctx(state["run_id"]).audit.emit(
            "supervisor", "decision",
            f"Validation {state['last_validation']['verdict']} -> remediation re-plans (different plan)")
        return "remediation"
    return route_next(state)


def route_after_risk(state: GraphState) -> str:
    """Pick the remediation style after scoring: batch mode (setting) -> recommend for all findings at once;
    sequential -> remediation of the first queued finding; nothing queued -> reporter."""
    rc = get_ctx(state["run_id"])
    if rc.tool_ctx.settings.batch_remediation and state.get("plan_queue"):
        rc.audit.emit("supervisor", "decision", "Batch remediation -> recommend (a recommendation for every finding)")
        return "recommend"
    return "remediation" if state.get("plan_queue") else route_next(state)


def route_after_recommend(state: GraphState) -> str:
    """recommend_node sets state["route"]: "gate" (decisions needed), "validate" (all decided) or neither (done)."""
    audit = get_ctx(state["run_id"]).audit
    if state.get("route") == "gate":
        audit.emit("supervisor", "decision", f"Batch {state.get('batch_id')} ready -> batch_gate (no validation "
                                             f"until every fix has a decision)")
        return "batch_gate"
    if state.get("route") == "validate":
        return "validate_batch"
    audit.emit("supervisor", "decision", "No fix waits for a decision -> reporter")
    return "reporter"


def route_after_record_batch(state: GraphState) -> str:
    """After decisions were recorded: back to the gate (refused/incomplete), validate the held approvals, re-plan
    rejected or failed items, or report. record_batch_node has already worked out which."""
    route = state.get("route")
    if route == "gate":
        return "batch_gate"
    if route == "validate":
        return "validate_batch"
    if route == "recommend":
        return "recommend"
    return "reporter"


def route_after_validate_batch(state: GraphState) -> str:
    """Items that failed validation (or are still undecided) go back to recommend; otherwise the run is finished."""
    return "recommend" if state.get("route") == "recommend" else "reporter"


def build_graph(checkpointer=None):
    """Compile the pipeline graph (both remediation styles live in it; the routes pick one per run).

    `checkpointer` is a SqliteSaver for real runs (state persists across the human gate); None is for tests that
    only inspect the topology. The node lists in `add_conditional_edges` declare every possible target, which
    LangGraph needs to draw and validate the graph."""
    g = StateGraph(GraphState)
    for name, fn in [("discovery", discovery_node), ("detection", detection_node),
                     ("evidence_analyst", evidence_analyst_node), ("investigator", investigator_node),
                     ("risk_analyst", risk_analyst_node),
                     ("remediation", remediation_node), ("sandbox_preview", sandbox_preview_node),
                     ("human_gate", human_gate_node),
                     ("record_decision", record_decision_node), ("validator", validator_node),
                     ("recommend", recommend_node), ("batch_gate", batch_gate_node),
                     ("record_batch", record_batch_node), ("validate_batch", validate_batch_node),
                     ("reporter", reporter_node)]:
        g.add_node(name, fn)
    g.add_edge(START, "discovery")
    g.add_conditional_edges("discovery", route_after_discovery, ["detection"])
    g.add_conditional_edges("detection", route_after_detection, ["evidence_analyst", "reporter"])
    g.add_edge("evidence_analyst", "investigator")
    g.add_edge("investigator", "risk_analyst")
    g.add_conditional_edges("risk_analyst", route_after_risk, ["remediation", "recommend", "reporter"])
    g.add_conditional_edges("recommend", route_after_recommend, ["batch_gate", "validate_batch", "reporter"])
    g.add_edge("batch_gate", "record_batch")
    g.add_conditional_edges("record_batch", route_after_record_batch,
                            ["validate_batch", "batch_gate", "recommend", "reporter"])
    g.add_conditional_edges("validate_batch", route_after_validate_batch, ["recommend", "reporter"])
    g.add_conditional_edges("remediation", route_after_remediation,
                            ["sandbox_preview", "human_gate", "remediation", "reporter"])
    g.add_edge("sandbox_preview", "human_gate")
    g.add_edge("human_gate", "record_decision")
    g.add_conditional_edges("record_decision", route_after_decision,
                            ["validator", "remediation", "human_gate", "reporter"])
    g.add_conditional_edges("validator", route_after_validation, ["remediation", "reporter"])
    g.add_edge("reporter", END)
    return g.compile(checkpointer=checkpointer)


# ---------------------------------------------------------------- outputs

# Highest first; the first level present among a node's findings becomes the node's colour in the graph view.
_RISK_ORDER = [Priority.CRITICAL, Priority.HIGH, Priority.MEDIUM, Priority.LOW]
# Findings about things that are not packages get a pseudo node in the graph so the UI can show them:
# category -> node kind (prefix of the node id). Anything not listed here is shown as "config".
_PSEUDO_KIND = {
    FindingCategory.UNPINNED_CI: "ci",
    FindingCategory.UNTRUSTED_IMAGE: "image",
    FindingCategory.LOCKFILE: "config",
}


def _max_risk(risks: list[Priority | None]) -> str | None:
    """Highest risk band (as its string value) among `risks`, or None if none of them has one."""
    for r in _RISK_ORDER:
        if r in risks:
            return r.value
    return None


def pseudo_node_id(f: Finding) -> str:
    """Graph node id for a non-package finding: "ci:<workflow file>", "image:<image purl>" or
    "config:<file or title>"."""
    kind = _PSEUDO_KIND.get(f.category, "config")
    if kind == "image" and f.component_purl:
        return f"image:{f.component_purl}"
    return f"{kind}:{f.file_path or f.title}"


def build_graph_json(ctx: ToolContext, findings: list[Finding]) -> dict:
    """The content of graph.json: the dependency graph with every finding attached to its node.

    Starts from the in-memory graph (or graph.json of an earlier process when resumed), makes sure a root exists
    even for a target without resolved packages, creates a node for a finding whose package the graph does not
    know (so no finding is invisible in the UI), adds pseudo nodes (CI file, image, config) for non-package
    findings with a "uses" edge from the project, and sets each node's `finding_ids` and `risk` (highest initial
    risk of its findings). Returns the dict; the caller writes it."""
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
    roots = data.get("roots") or ["root"]  # a target with no resolved packages still gets a root to hang findings on
    data["roots"] = roots
    for r in roots:
        nodes.setdefault(r, {"id": r, "kind": "project", "label": r, "project": r})
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
    """HEAD commit of the analysed repository for the run header, or None if it is not a git checkout or git
    is unavailable. Never raises: the commit is informational."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def build_summary(run_id: str, ctx: ToolContext, findings: list[Finding], status: str, started: datetime,
                  settings: Settings, llm_model: str | None) -> dict:
    """The header of run_summary.json: target, commit, timings, SBOM and finding counts (by initial risk and by
    category), LLM mode/model and offline flag. `_finalize` adds the remediation, budget and pending-gate parts."""
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
    """Local-time, sortable run id like run_20260101_120000 (also the LangGraph thread id and the folder name)."""
    return "run_" + datetime.now().strftime("%Y%m%d_%H%M%S")


def _config(run_id: str) -> dict:
    """LangGraph config: thread id = run id (selects the checkpoint) and a high recursion limit, since the
    remediation loops revisit nodes once per finding / attempt."""
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


def _interim_report(rc: RunContext, summary: dict) -> None:
    """report.json + report.html for a run paused at the human gate (status "awaiting_human"): the same renderer
    as the reporter node, so verified / failed fixes and the decisions still pending are all shown as they stand."""
    from guardian.reporting.render import write_reports

    ctx, audit = rc.tool_ctx, rc.audit
    inventory = None
    if ctx.graph is not None and hasattr(ctx.graph, "stats"):
        st = ctx.graph.stats()
        inventory = {k: st.get(k, 0) for k in ("components", "direct", "transitive")}
    try:
        j, h = write_reports(ctx.run_dir, summary=summary, inventory=inventory, target=ctx.repo.name,
                             commit=summary.get("commit"))
    except Exception as exc:  # noqa: BLE001  a report failure must not fail the pause
        audit.emit("reporter", "error", f"interim report failed: {type(exc).__name__}: {str(exc)[:200]}")
        return
    audit.emit("reporter", "agent_end", f"Interim report (decisions still pending): wrote {j.name} and {h.name}",
               data={"files": [j.name, h.name], "interim": True})


def _finalize(run_id: str, rc: RunContext, settings: Settings, started: datetime, status: str) -> dict:
    """Write the end-of-drive files for a finished OR paused run and return the summary dict.

    Writes graph.json, changes.json (if the change detector ran), run_summary.json (status, counts, remediation
    outcomes, recommendations, pending plan/batch, budget use) and runs/LATEST; emits the closing `agent_end`
    event (which says what the run is waiting for, if paused). Runs in a `finally`, so a failed run still leaves
    a summary with status "failed"."""
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    run_dir = ctx.run_dir
    findings = store.list_findings()
    (run_dir / "graph.json").write_text(json.dumps(build_graph_json(ctx, findings), indent=1), encoding="utf-8")
    if "changes" in ctx.artifacts:
        (run_dir / "changes.json").write_text(json.dumps(ctx.artifacts["changes"], indent=2, default=str),
                                              encoding="utf-8")
    summary = build_summary(run_id, ctx, findings, status, started, settings, rc.llm.model if rc.llm else None)
    if "run_llm" in ctx.artifacts:
        # a resumed run makes no LLM calls: keep the provenance of the process that did (mode, model)
        summary["llm"] = ctx.artifacts["run_llm"]
    summary["remediation"] = remediation_outcomes(run_dir, store)
    if status == "awaiting_human" and any((run_dir / "validation").glob("*.json")):
        # paused at the gate after at least one fix was validated (e.g. one at a time while others wait): write an
        # interim report now, so the validated fix is reported without waiting for every other decision. The
        # reporter node overwrites it when the run finishes. A rendering failure must not fail the pause.
        _interim_report(rc, summary)
    summary["has_report"] =(run_dir / "report.json").is_file() and (run_dir / "report.html").is_file()
    pending = get_pending(run_dir)
    pending_batch = get_pending_batch(run_dir) if status == "awaiting_human" else None
    summary["pending_plan"] = {"plan_id": pending.plan_id, "plan_hash": pending.plan_hash,
                               "finding_id": pending.finding_id} if pending and status == "awaiting_human" else None
    if (run_dir / "recommendations.json").is_file():
        recs = load_recs(run_dir)
        by_outcome: dict[str, int] = {}
        for r in recs["items"]:
            by_outcome[r.outcome] = by_outcome.get(r.outcome, 0) + 1
        summary["recommendations"] = {"round": recs["round"], "status": recs["status"], "items": len(recs["items"]),
                                      "by_outcome": by_outcome}
    if pending_batch is not None:
        summary["pending_batch"] = {"batch_id": pending_batch["batch_id"], "round": pending_batch["round"],
                                    "count": len(pending_batch["items"])}
    if ctx.budget is not None:
        summary["budget"] = ctx.budget.snapshot()
    (run_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (settings.runs_dir / "LATEST").write_text(run_id, encoding="utf-8")
    end = (f"Run paused at the human gate: plan {pending.plan_id} awaits a decision"
           if status == "awaiting_human" and pending else
           f"Run paused at the human gate: batch {pending_batch['batch_id']} awaits "
           f"{len(pending_batch['items'])} decisions" if pending_batch else
           f"Run {status}: {summary['findings']['total']} findings, by risk {summary['findings']['by_risk']}")
    audit.emit("supervisor", "agent_end", end)
    return summary


def _drive(run_id: str, rc: RunContext, settings: Settings, started: datetime, graph_input) -> Path:
    """Run the graph from `graph_input` (initial state, or a resume Command) until it ends or pauses.

    Opens the checkpoint database, registers the live RunContext for the nodes, then invokes the graph. Status:
    "awaiting_human" when the graph stopped at an interrupt, "done" when it ran to the end, "failed" when an
    exception escaped (re-raised after logging). Always finalises and unregisters the context. Returns run_dir."""
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
    """Mark the run as running. On a resume the earlier summary (target, commit, counts, ...) is kept, so the
    UI does not lose the run's header for the whole validation; only what no longer holds is cleared."""
    path = run_dir / "run_summary.json"
    try:
        prev = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    except (OSError, ValueError):
        prev = {}
    prev = prev if isinstance(prev, dict) else {}  # a corrupt or non-object summary is ignored, not fatal
    body = {**prev, "run_id": run_id, "status": "running", "started_at": started.isoformat(),
            "pending_plan": None, "pending_batch": None}
    body.pop("finished_at", None)
    path.write_text(json.dumps(body, indent=2), encoding="utf-8")


def run(repo: Path, run_id: str | None = None, settings: Settings | None = None,
        llm: LLMProvider | None = None, echo: bool = True, compare_ref: str | None = None) -> Path:
    """Start a new run on `repo` and drive it until it ends or pauses at the human gate. Returns the run dir.

    `llm` can be injected (tests use a fake); otherwise it is built from the settings. `compare_ref` is an
    optional git ref for the "what changed" detector. `echo` mirrors events to stderr. Creates
    runs/<run_id>/ (it must not exist: ids are never reused) with the audit/trace files, evidence, findings and
    the checkpoint database; see the module docstring for the node order."""
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
    return _resume(run_id, settings, llm, echo, Command(resume=approval.model_dump(mode="json")),
                   f"Resuming {run_id}: {approval.decision} on plan {approval.plan_id}")


def resume_batch(run_id: str, batch_id: str, approvals: list[Approval], settings: Settings | None = None,
                 llm: LLMProvider | None = None, echo: bool = True, partial: bool = False) -> Path:
    """Continue a batch-mode run paused at the gate with one decision for EVERY fix of the batch (or, with
    `partial=True`, for one or more of them: the rest stay pending). The set is checked first (every item decided
    unless partial, none extra, G5.1 hashes, G5.2 comments); an invalid one raises DecisionRejected and nothing
    resumes. The graph re-checks the same set in record_batch_node: a resume value is never trusted blindly.
    """
    settings = settings or load_settings()
    run_dir = settings.runs_dir / run_id
    reason = check_batch(get_pending_batch(run_dir), batch_id, approvals, partial=partial)
    if reason:
        raise DecisionRejected(reason)
    value = {"batch_id": batch_id, "partial": partial, "decisions": [a.model_dump(mode="json") for a in approvals]}
    return _resume(run_id, settings, llm, echo, Command(resume=value),
                   f"Resuming {run_id}: batch {batch_id} with {len(approvals)} decisions")


def resume_validate_now(run_id: str, batch_id: str, plan_ids: list[str] | None = None, requested_by: str = "human",
                        settings: Settings | None = None, llm: LLMProvider | None = None, echo: bool = True) -> Path:
    """Validate held approved fixes of a batch run NOW (`plan_ids`, default all held; together if several) while the
    other fixes keep waiting for decisions. Refused (DecisionRejected, nothing resumes) unless the batch id is the
    pending one and every plan is an approved held fix with a matching recorded approval (G5.1)."""
    from guardian.agents.batch import check_validate_now

    settings = settings or load_settings()
    run_dir = settings.runs_dir / run_id
    checked = check_validate_now(run_dir, get_pending_batch(run_dir), batch_id, plan_ids)
    if isinstance(checked, tuple):
        raise DecisionRejected(checked[1])
    value = {"batch_id": batch_id, "decisions": [], "partial": True, "validate_now": checked,
             "requested_by": requested_by}
    return _resume(run_id, settings, llm, echo, Command(resume=value),
                   f"Resuming {run_id}: validate {len(checked)} approved fix(es) now (batch {batch_id})")


def _resume(run_id: str, settings: Settings, llm: LLMProvider | None, echo: bool, graph_input, message: str) -> Path:
    """Shared resume path: take a per-run lock (one resume at a time), rebuild the run context from the saved
    summary and checkpoint, then drive the graph on from the gate with `graph_input` (a Command(resume=...))."""
    run_dir = settings.runs_dir / run_id
    lock = run_dir / ".resume.lock"  # created exclusively: a second resume of the same run is refused
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
        if summary.get("llm"):
            tool_ctx.artifacts["run_llm"] = summary["llm"]
        if (run_dir / "changes.json").exists():
            tool_ctx.artifacts["changes"] = json.loads((run_dir / "changes.json").read_text(encoding="utf-8"))
        _rebuild_graph(tool_ctx)
        rc = RunContext(tool_ctx=tool_ctx, store=store, audit=audit, llm=llm)
        _write_running(run_dir, run_id, started)
        audit.emit("supervisor", "agent_start", message)
        return _drive(run_id, rc, settings, started, graph_input)
    finally:
        lock.unlink(missing_ok=True)
