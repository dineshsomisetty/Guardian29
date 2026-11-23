"""Detection agent (tool agent, deterministic): scanners + detectors -> Findings. Owner: Dev1.

Also dedupes Grype/OSV results by (purl, vuln id or any alias) and fills dependency paths from the graph.
"""

from __future__ import annotations

from guardian.core.models import Finding, FindingCategory
from guardian.graph.state import GraphState, get_ctx
from guardian.tools.registry import BINDINGS, call_tool

AGENT = "detection"


def _vuln_keys(f: Finding) -> set[tuple[str, str]]:
    ids = {i.upper() for i in [f.vuln_id, *f.aliases] if i}
    return {(f.component_purl or "", i) for i in ids}


def dedupe(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Merge CVE findings that share (purl, id/alias). First seen wins (Grype runs before OSV)."""
    kept: list[Finding] = []
    index: dict[tuple[str, str], Finding] = {}
    merged = 0
    for f in findings:
        if f.category is not FindingCategory.CVE:
            kept.append(f)
            continue
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
        for k in _vuln_keys(hit):
            index[k] = hit
    return kept, merged


def detection_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    ctx, audit, store = rc.tool_ctx, rc.audit, rc.store
    audit.emit(AGENT, "agent_start", "Detecting vulnerabilities and supply-chain anomalies",
               evidence_ids=[e for e in (state.get("sbom_evidence_id"), state.get("graph_evidence_id")) if e])

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

    graph = ctx.graph
    for f in findings:
        if not f.dependency_paths and f.component_purl and graph is not None and hasattr(graph, "paths_to"):
            try:
                f.dependency_paths = graph.paths_to(f.component_purl, max_paths=5)
            except Exception:  # noqa: BLE001  path lookup is best-effort
                pass
        store.add_finding(f)

    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f.category.value] = by_cat.get(f.category.value, 0) + 1
    ids = [f.finding_id for f in findings]
    audit.emit(AGENT, "agent_end", f"{len(findings)} findings: {by_cat}", data={"by_category": by_cat})
    audit.emit(AGENT, "handoff", f"{len(findings)} findings with evidence -> evidence_analyst",
               evidence_ids=sorted({e for f in findings for e in f.evidence_ids})[:50])
    return {"status": "analysing", "finding_ids": ids, "errors": errors}
