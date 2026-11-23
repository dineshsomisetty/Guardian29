"""Detector `typosquat` (D2-05, Dev2): direct dependencies whose names imitate popular packages.

Name matching is Dev4's `similarity.check_name` (D4-01); this module adds the file/line/excerpt evidence and the
Finding. Heuristic findings may later only be removed/replaced/blocked/escalated (G5.3).
"""
from __future__ import annotations

from pathlib import Path

from guardian.adapters.npm import find_projects
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.detectors.similarity import check_name
from guardian.tools.registry import ToolOutput

DETECTOR = "detector:typosquat"


def detect(ctx) -> ToolOutput:
    base = Path(ctx.work_dir or ctx.repo)
    graph = ctx.graph
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    for proj in find_projects(base):
        for dep in proj.deps:
            hit = check_name(dep.name)
            if not hit:
                continue
            file_path = proj.relpath("package.json")
            ex = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool=DETECTOR, file_path=file_path,
                          line=dep.line, excerpt=dep.excerpt,
                          facts={"name": dep.name, "spec": dep.spec, "section": dep.section, "project": proj.name})
            sim = Evidence(run_id=ctx.run_id, kind="detector_result", source_tool=DETECTOR,
                           facts={"candidate": hit.candidate, "popular_name": hit.popular, "distance": hit.distance,
                                  "reason": hit.reason, "popular_list": "data/popular_packages/npm.txt"})
            node = graph.node_for_name(dep.name) if graph is not None and hasattr(graph, "node_for_name") else None
            findings.append(Finding(
                run_id=ctx.run_id, category=FindingCategory.TYPOSQUAT, detector=DETECTOR,
                title=f"Possible typosquat: '{dep.name}' resembles popular package '{hit.popular}' ({hit.reason})",
                component_purl=node["id"] if node else None, scope=Scope(dep.scope), project=proj.name,
                file_path=file_path, line=dep.line, evidence_ids=[ex.evidence_id, sim.evidence_id]))
            evidence += [ex, sim]
    names = [f.title.split("'")[1] for f in findings]
    return ToolOutput(findings=findings, evidence=evidence, summary=f"{len(findings)} possible typosquat(s): {names}")
