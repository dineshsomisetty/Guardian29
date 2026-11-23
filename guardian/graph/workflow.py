"""LangGraph orchestration + run driver. Owner: Dev1.

CP1 graph (3 agents, rules-first supervisor routing between them):

    START -> discovery --(supervisor)--> detection --(supervisor)--> evidence_analyst -> END

Every routing decision is logged as a `decision` event with its reason (§2.4).
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path

from langgraph.graph import END, START, StateGraph

from guardian.agents.detection import detection_node
from guardian.agents.discovery import discovery_node
from guardian.agents.evidence_analyst import evidence_analyst_node
from guardian.core.audit import AuditLog
from guardian.core.config import Settings, load_settings
from guardian.core.models import Finding, FindingCategory, Priority, utcnow
from guardian.core.store import JsonStore
from guardian.graph.state import GraphState, RunContext, get_ctx, register, unregister
from guardian.llm.provider import LLMProvider
from guardian.tools.registry import ToolContext

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


def build_graph():
    g = StateGraph(GraphState)
    g.add_node("discovery", discovery_node)
    g.add_node("detection", detection_node)
    g.add_node("evidence_analyst", evidence_analyst_node)
    g.add_edge(START, "discovery")
    g.add_conditional_edges("discovery", route_after_discovery, ["detection"])
    g.add_conditional_edges("detection", route_after_detection, ["evidence_analyst", END])
    g.add_edge("evidence_analyst", END)
    return g.compile()


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


def new_run_id() -> str:
    return "run_" + datetime.now().strftime("%Y%m%d_%H%M%S")


def run(repo: Path, run_id: str | None = None, settings: Settings | None = None,
        llm: LLMProvider | None = None, echo: bool = True) -> Path:
    settings = settings or load_settings()
    run_id = run_id or new_run_id()
    run_dir = settings.runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    started = utcnow()

    audit = AuditLog(run_dir, run_id, echo=echo)
    store = JsonStore(run_dir)
    tool_ctx = ToolContext(run_id=run_id, run_dir=run_dir, repo=repo.resolve(), settings=settings)
    if llm is None:
        llm = LLMProvider.from_settings(settings)
    register(RunContext(tool_ctx=tool_ctx, store=store, audit=audit, llm=llm))

    audit.emit("supervisor", "agent_start", f"Run {run_id} on {tool_ctx.repo.name}", data={"llm": settings.describe()})
    status = "failed"
    try:
        final = build_graph().invoke({"run_id": run_id, "status": "discovering", "finding_ids": [], "errors": []})
        status = "done" if final.get("status") in {"done", "analysing"} else final.get("status", "done")
        if final.get("errors"):
            audit.emit("supervisor", "decision", f"Run finished with {len(final['errors'])} degraded steps",
                       data={"errors": final["errors"]})
    except Exception as exc:
        audit.emit("supervisor", "error", f"Run failed: {type(exc).__name__}: {str(exc)[:300]}")
        raise
    finally:
        findings = store.list_findings()
        (run_dir / "graph.json").write_text(json.dumps(build_graph_json(tool_ctx, findings), indent=1), encoding="utf-8")
        if "changes" in tool_ctx.artifacts:
            (run_dir / "changes.json").write_text(json.dumps(tool_ctx.artifacts["changes"], indent=2, default=str),
                                                  encoding="utf-8")
        summary = build_summary(run_id, tool_ctx, findings, status, started, settings, llm.model if llm else None)
        (run_dir / "run_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (settings.runs_dir / "LATEST").write_text(run_id, encoding="utf-8")
        audit.emit("supervisor", "agent_end", f"Run {status}: {summary['findings']['total']} findings, "
                                              f"by risk {summary['findings']['by_risk']}")
        unregister(run_id)
    return run_dir
