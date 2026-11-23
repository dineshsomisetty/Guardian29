"""D4-12 image_pin: Dockerfile base images referenced by tag only (no @sha256 digest). Owner: Dev4."""

from __future__ import annotations

from guardian.adapters import dockerfile
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools.registry import ToolContext, ToolOutput


def detect(ctx: ToolContext) -> ToolOutput:
    root = ctx.work_dir or ctx.repo
    images, ports = dockerfile.parse(root)
    findings, evidence = [], []
    for img in images:
        if img.digest:
            continue
        ref = f"{img.image}:{img.tag}" if img.tag else img.image
        ev = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool="detector:image_pin",
                      facts={"image": img.image, "tag": img.tag or "latest (implicit)", "digest": None,
                             "stage": img.stage, "exposed_ports": ports},
                      file_path=img.file, line=img.line, excerpt=img.raw)
        evidence.append(ev)
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.UNTRUSTED_IMAGE,
            title=f"Base image {ref} referenced by tag only (no digest)", detector="detector:image_pin",
            component_purl=ref, scope=Scope.PROD, project="image", file_path=img.file, line=img.line,
            evidence_ids=[ev.evidence_id]))
    return ToolOutput(findings=findings, evidence=evidence,
                      summary=f"{len(images)} base images, {len(findings)} tag-only")
