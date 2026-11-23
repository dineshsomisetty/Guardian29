"""D2-05 typosquat detector: direct dependency names close to popular packages (Dev4 similarity). Owner: Dev2.

Scans current manifests plus legacy/backup manifests (`ftp/package.json.bak`) that ship with the target.
"""

from __future__ import annotations

from pathlib import Path

from guardian.adapters.npm import find_projects, manifest_deps, purl
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.detectors.similarity import check_name
from guardian.tools.registry import ToolContext, ToolOutput

LEGACY_MANIFESTS = ["ftp/package.json.bak"]


def _scan(ctx: ToolContext, manifest: Path, rel: str, project: str, legacy: bool) -> tuple[list, list]:
    findings, evidence = [], []
    for name, rng, section, line in manifest_deps(manifest):
        hit = check_name(name)
        if not hit:
            continue
        version = rng.lstrip("^~=<> ")
        installed = None
        if ctx.graph is not None and not legacy:
            installed = next((n for n, d in ctx.graph.g.nodes(data=True)
                              if d.get("label") == name and project in d.get("projects", [])), None)
        ev =Evidence(run_id=ctx.run_id, kind="detector_result", source_tool="detector:typosquat",
                      facts={"name": name, "range": rng, "section": section, "similar_to": hit.popular,
                             "distance": hit.distance, "reason": hit.reason, "legacy_manifest": legacy},
                      file_path=rel, line=line, excerpt=f'"{name}": "{rng}"')
        evidence.append(ev)
        where = "legacy backup manifest" if legacy else section
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.TYPOSQUAT,
            title=f"Possible typosquat '{name}' (looks like '{hit.popular}') in {where}",
            detector="detector:typosquat", component_purl=None if legacy else (installed or purl(name, version)),
            scope=Scope.DEV if section == "devDependencies" else Scope.PROD, project=project,
            file_path=rel, line=line, evidence_ids=[ev.evidence_id]))
    return findings, evidence


def detect(ctx: ToolContext) -> ToolOutput:
    work = ctx.work_dir or ctx.repo
    findings, evidence = [], []
    for proj in find_projects(work):
        f, e = _scan(ctx, proj.manifest, proj.manifest.relative_to(work).as_posix(), proj.name, legacy=False)
        findings += f
        evidence += e
    for rel in LEGACY_MANIFESTS:
        path = work / rel
        if path.exists():
            f, e = _scan(ctx, path, rel, "root", legacy=True)
            findings += f
            evidence += e
    return ToolOutput(findings=findings, evidence=evidence, summary=f"{len(findings)} typosquat suspects")
