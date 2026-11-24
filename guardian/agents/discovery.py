"""Discovery agent (tool agent, deterministic): work copy -> lockfiles -> SBOM -> dependency graph. Owner: Dev1.

Role: first node of the pipeline. It builds the factual inventory (what is in the project) that every later agent
reasons about. It is deterministic on purpose: inventory facts must not be hallucinated (section 2.4), so this
agent never calls the LLM.

Inputs:  graph state `run_id` only; everything else comes from the run context (`get_ctx`): the target repo path,
         the evidence store, the audit log and the tool context.
Tools:   run in the fixed order of `BINDINGS["discovery"]` through `call_tool` (so the per-agent allowlist G3.1,
         typed args G3.2 and budgets G3.6 apply): `workspace` (isolated read-only work copy under
         runs/<id>/work), `resolve_lockfiles`, `sbom` (CycloneDX file runs/<id>/sbom.cdx.json) and
         `graph_build` (dependency graph, kept on `ctx.graph`).
Outputs: evidence of kind `sbom` and `graph` (stored by the registry, append-only), and the state keys
         `status`, `sbom_evidence_id`, `graph_evidence_id`, `errors`, `work_dir`, `sbom_path`.
Audit:   `agent_start`, one `decision` (supervisor) when the workspace fallback kicks in, `agent_end` with the
         component counts, and a `handoff` to detection citing the SBOM and graph evidence ids.
Failure: a failing tool never aborts the run; its name is appended to `errors` ("discovery:<tool>") and the
         pipeline continues with whatever was produced. If the workspace tool fails, the target is scanned in
         place, read-only, with nothing installed or executed.
"""

from __future__ import annotations

from guardian.graph.state import GraphState, get_ctx
from guardian.tools.registry import BINDINGS, call_tool

AGENT = "discovery"


def discovery_node(state: GraphState) -> dict:
    """LangGraph node: build the inventory (SBOM + dependency graph) for the run's target.

    Runs every discovery tool in order, remembers the evidence ids of the SBOM and the graph, and reads component
    statistics from the graph for the audit summary.

    Args: state - the graph state; only `run_id` is used (to find the run context).
    Returns: a partial state update: `status` ("detecting"), the SBOM / graph evidence ids (None if a tool failed),
             the list of tool errors, and the string paths of the work copy and SBOM file (None if absent).
    Side effects: tool calls (which store Evidence and write the SBOM file), audit events, and `ctx.work_dir` /
             `ctx.graph` / `ctx.sbom_path` being filled in by the tools.
    """
    rc = get_ctx(state["run_id"])
    ctx, audit, store = rc.tool_ctx, rc.audit, rc.store
    audit.emit(AGENT, "agent_start", f"Discovering inventory of {ctx.repo.name}")

    # Evidence ids handed to detection; stay None if the matching tool failed.
    sbom_ev = graph_ev = None
    # Tool failures as "discovery:<tool>"; recorded in state, never raised.
    errors: list[str] = []
    for name, target in BINDINGS[AGENT]:
        out = call_tool(AGENT, name, target, ctx, store, audit)
        # call_tool returns None when the tool was blocked, errored or hit a budget (already audited).
        if out is None:
            errors.append(f"discovery:{name}")
            if name == "workspace" and ctx.work_dir is None:
                # Fallback: read-only scan of the target in place. Nothing is installed or executed.
                ctx.work_dir = ctx.repo
                audit.emit("supervisor", "decision",
                           "workspace tool unavailable -> scanning target in place (read-only, no installs)")
            continue
        # Pick out the two evidence records later agents need by kind.
        for ev in out.evidence:
            if ev.kind == "sbom":
                sbom_ev = ev.evidence_id
            elif ev.kind == "graph":
                graph_ev = ev.evidence_id

    # Validation speed: the unpatched sandbox baseline depends only on the discovered lockfiles, so it is computed in
    # a background thread now (while detection, the LLM and the human gate run) instead of after approval.
    # No-op without Docker / with GUARDIAN_SANDBOX=off; never blocks and never fails the run.
    try:
        if ctx.work_dir is not None and (ctx.run_dir / "work").is_dir():
            from guardian.tools import sandbox

            sandbox.prewarm_baseline(ctx)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"discovery:prewarm:{exc}")

    # Component counts for the summary line only (components / direct / transitive); best-effort.
    stats = {}
    if ctx.graph is not None and hasattr(ctx.graph, "stats"):
        try:
            stats = ctx.graph.stats()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"discovery:graph_stats:{exc}")
    # Evidence ids cited by the handoff event so the trace links to them.
    handoff = [e for e in (sbom_ev, graph_ev) if e]
    audit.emit(AGENT, "agent_end",
               f"Inventory: {stats.get('components', '?')} components "
               f"({stats.get('direct', '?')} direct, {stats.get('transitive', '?')} transitive)",
               evidence_ids=handoff, data={"stats": stats})
    audit.emit(AGENT, "handoff", "SBOM + dependency graph -> detection", evidence_ids=handoff)
    return {"status": "detecting", "sbom_evidence_id": sbom_ev, "graph_evidence_id": graph_ev, "errors": errors,
            "work_dir": str(ctx.work_dir) if ctx.work_dir else None,
            "sbom_path": str(ctx.sbom_path) if ctx.sbom_path else None}
