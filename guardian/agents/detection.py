"""Detection agent (tool agent, deterministic): scanners + detectors -> Findings. Owner: Dev1.

Role: second node of the pipeline. It turns the inventory into a list of `Finding` objects: known CVEs from
vulnerability scanners and supply-chain anomalies from heuristic detectors. It never calls the LLM: whether
something is a finding is decided by tools and code, so it can be audited and replayed.

Inputs:  state keys `run_id`, `sbom_evidence_id`, `graph_evidence_id` (only cited in the start event); the work
         copy, SBOM and dependency graph held in the tool context by discovery.
Tools:   everything in `BINDINGS["detection"]`, in order, via `call_tool` (allowlist G3.1, typed args G3.2,
         budgets G3.6): Grype and OSV scanners (CVEs), then detectors for lockfile problems, typosquats,
         unpinned CI actions / images, install scripts, unexpected manifest changes, package risk signals, and
         the policy check. Each returns `ToolOutput(findings=..., evidence=...)`; the registry stores the evidence.
Outputs: `Finding` records written with `store.add_finding` (findings.json), each citing evidence ids; state keys
         `status`, `finding_ids`, `errors`.
Audit:   `agent_start`, a `decision` when duplicates were merged, `agent_end` with per-category counts and a
         `handoff` to evidence_analyst citing up to 50 evidence ids.
Also dedupes Grype/OSV results by (purl, vuln id or any alias) and fills dependency paths from the graph.
Failure: a failed tool is logged as "detection:<tool>" in `errors`; the other tools still run. Path lookup in the
         graph is best-effort.
"""

from __future__ import annotations

from guardian.core.models import Finding, FindingCategory
from guardian.graph.state import GraphState, get_ctx
from guardian.tools.registry import BINDINGS, call_tool

AGENT = "detection"


def _vuln_keys(f: Finding) -> set[tuple[str, str]]:
    """Identity keys of a CVE finding, used to spot the same advisory reported by two scanners.

    Returns one (purl, ID) tuple per known identifier (vuln_id plus every alias), upper-cased because Grype and OSV
    disagree on case. Two findings are duplicates when they share any tuple (e.g. CVE-... vs the GHSA alias).
    """
    ids = {i.upper() for i in [f.vuln_id, *f.aliases] if i}
    return {(f.component_purl or "", i) for i in ids}


def dedupe(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Merge CVE findings reported by several scanners for the same package and advisory.

    Args: findings - raw findings in tool order (Grype first, then OSV, then detectors).
    Returns: (kept, merged) - the findings to keep and how many duplicates were folded into an earlier one.
    Non-CVE findings are never merged. For a duplicate, the first one seen wins and absorbs the extras: evidence ids
    (order-preserving union), aliases, and fixed versions / CVSS / affected range where the winner had none. This
    mutates the winner in place.
    """
    # kept = output list; index maps every (purl, id) key to the finding that owns it.
    kept: list[Finding] = []
    index: dict[tuple[str, str], Finding] = {}
    merged = 0
    for f in findings:
        if f.category is not FindingCategory.CVE:
            kept.append(f)
            continue
        # An earlier finding already owns one of this finding's keys -> it is a duplicate.
        hit = next((index[k] for k in _vuln_keys(f) if k in index), None)
        if hit is None:
            kept.append(f)
            for k in _vuln_keys(f):
                index[k] = f
            continue
        merged += 1
        hit.evidence_ids = list(dict.fromkeys([*hit.evidence_ids, *f.evidence_ids]))
        extra = [a for a in [f.vuln_id, *f.aliases] if a and a != hit.vuln_id and a not in hit.aliases]
        hit.aliases.extend(extra)
        hit.fixed_versions = hit.fixed_versions or f.fixed_versions
        hit.cvss = hit.cvss if hit.cvss is not None else f.cvss
        hit.affected_range = hit.affected_range or f.affected_range
        # The winner gained aliases, so register its new keys for later duplicates.
        for k in _vuln_keys(hit):
            index[k] = hit
    return kept, merged


def detection_node(state: GraphState) -> dict:
    """LangGraph node: run all scanners/detectors, dedupe, attach dependency paths, store findings.

    Args: state - the graph state; `run_id` finds the run context, the SBOM/graph evidence ids go in the start event.
    Returns: partial state update with `status` ("analysing"), `finding_ids` (ids of every stored finding, in order)
             and `errors` (names of tools that failed).
    Side effects: tool calls (evidence stored by the registry), `store.add_finding` for each finding, audit events.
    """
    rc = get_ctx(state["run_id"])
    ctx, audit, store = rc.tool_ctx, rc.audit, rc.store
    audit.emit(AGENT, "agent_start", "Detecting vulnerabilities and supply-chain anomalies",
               evidence_ids=[e for e in (state.get("sbom_evidence_id"), state.get("graph_evidence_id")) if e])

    # raw = every finding from every tool before deduplication.
    raw: list[Finding] = []
    errors: list[str] = []
    for name, target in BINDINGS[AGENT]:
        out = call_tool(AGENT, name, target, ctx, store, audit)
        if out is None:
            errors.append(f"detection:{name}")
            continue
        raw.extend(out.findings)

    findings, merged = dedupe(raw)
    if merged:
        audit.emit(AGENT, "decision", f"Deduplicated {merged} Grype/OSV duplicates by (purl, id/alias)")

    # Ensure each finding shows how the package is reached (up to 5 paths from the project root);
    # scanners do not know this, the dependency graph does.
    graph = ctx.graph
    for f in findings:
        if not f.dependency_paths and f.component_purl and graph is not None and hasattr(graph, "paths_to"):
            try:
                f.dependency_paths = graph.paths_to(f.component_purl, max_paths=5)
            except Exception:  # noqa: BLE001  path lookup is best-effort
                pass
        store.add_finding(f)

    # Per-category counts for the summary line.
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
    ids = [f.finding_id for f in findings]
    audit.emit(AGENT, "agent_end", f"{len(findings)} findings: {by_cat}", data={"by_category": by_cat})
    audit.emit(AGENT, "handoff", f"{len(findings)} findings with evidence -> evidence_analyst",
               evidence_ids=sorted({e for f in findings for e in f.evidence_ids})[:50])
    return {"status": "analysing", "finding_ids": ids, "errors": errors}
