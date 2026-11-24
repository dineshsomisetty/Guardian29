"""Discovery agent (tool agent, deterministic): work copy -> lockfiles -> SBOM -> dependency graph. Owner: Dev1.

Deterministic on purpose: inventory facts must not be hallucinated (§2.4).
"""

from __future__ import annotations

from guardian.graph.state import GraphState, get_ctx
from guardian.tools.registry import BINDINGS, call_tool

AGENT = "discovery"


def discovery_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    ctx, audit, store = rc.tool_ctx, rc.audit, rc.store
    audit.emit(AGENT, "agent_start", f"Discovering inventory of {ctx.repo.name}")

    sbom_ev = graph_ev = None
    errors: list[str] = []
    for name, target in BINDINGS[AGENT]:
        out = call_tool(AGENT, name, target, ctx, store, audit)
        if out is None:
            errors.append(f"discovery:{name}")
            if name == "workspace" and ctx.work_dir is None:
                # Fallback: read-only scan of the target in place. Nothing is installed or executed.
                ctx.work_dir = ctx.repo
                audit.emit("supervisor", "decision",
                           "workspace tool unavailable -> scanning target in place (read-only, no installs)")
            continue
        for ev in out.evidence:
            if ev.kind == "sbom":
                sbom_ev = ev.evidence_id
            elif ev.kind == "graph":
                graph_ev = ev.evidence_id

    stats = {}
    if ctx.graph is not None and hasattr(ctx.graph, "stats"):
        try:
            stats = ctx.graph.stats()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"discovery:graph_stats:{exc}")
    handoff = [e for e in (sbom_ev, graph_ev) if e]
    audit.emit(AGENT, "agent_end",
               f"Inventory: {stats.get('components', '?')} components "
               f"({stats.get('direct', '?')} direct, {stats.get('transitive', '?')} transitive)",
               evidence_ids=handoff, data={"stats": stats})
    audit.emit(AGENT, "handoff", "SBOM + dependency graph -> detection", evidence_ids=handoff)
    return {"status": "detecting", "sbom_evidence_id": sbom_ev, "graph_evidence_id": graph_ev, "errors": errors,
            "work_dir": str(ctx.work_dir) if ctx.work_dir else None,
            "sbom_path": str(ctx.sbom_path) if ctx.sbom_path else None}
