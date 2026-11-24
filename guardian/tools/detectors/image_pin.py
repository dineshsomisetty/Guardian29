"""D4-12 image_pin: Dockerfile base images referenced by tag only (no @sha256 digest). Owner: Dev4."""

from __future__ import annotations

from guardian.adapters import dockerfile, gitlab_ci
from guardian.core.models import Evidence, Finding, FindingCategory, Scope
from guardian.tools import threat_intel
from guardian.tools.image_tags import newer_tags
from guardian.tools.registry import ToolContext, ToolOutput


def detect(ctx: ToolContext) -> ToolOutput:
    root = ctx.work_dir or ctx.repo
    images, ports = dockerfile.parse(root)
    findings, evidence = [], []
    for img in images:
        if img.digest:
            continue
        ref = f"{img.image}:{img.tag}" if img.tag else img.image
        offline = bool(getattr(ctx.settings, "offline", False)) or threat_intel.is_offline()
        newer, tags_source = newer_tags(img.image, img.tag or "", offline=offline, ctx=ctx)
        ev = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool="detector:image_pin",
                      facts={"image": img.image, "tag": img.tag or "latest (implicit)", "digest": None,
                             "stage": img.stage, "exposed_ports": ports,
                             # explicit releases on the same line (update_base_image candidates, D2-07b)
                             "newer_tags": newer, "source": tags_source},
                      file_path=img.file, line=img.line, excerpt=img.raw)
        evidence.append(ev)
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.UNTRUSTED_IMAGE,
            title=f"Base image {ref} referenced by tag only (no digest)", detector="detector:image_pin",
            component_purl=ref, scope=Scope.PROD, project="image", file_path=img.file, line=img.line,
            evidence_ids=[ev.evidence_id]))
    # GitLab CI: job and service containers run the pipeline (with its credentials): same rule, same fix
    ci_images, _ = gitlab_ci.parse(root)
    for img in ci_images:
        if img.digest:
            continue
        ref = f"{img.image}:{img.tag}" if img.tag else img.image
        offline = bool(getattr(ctx.settings, "offline", False)) or threat_intel.is_offline()
        newer, tags_source = newer_tags(img.image, img.tag or "", offline=offline, ctx=ctx)
        ev = Evidence(run_id=ctx.run_id, kind="file_excerpt", source_tool="detector:image_pin",
                      facts={"image": img.image, "tag": img.tag or "latest (implicit)", "digest": None,
                             "stage": None, "ci_role": img.role, "exposed_ports": [],
                             "newer_tags": newer, "source": tags_source},
                      file_path=img.file, line=img.line, excerpt=img.raw)
        evidence.append(ev)
        what = "service container" if img.role == "service" else "job image"
        findings.append(Finding(
            run_id=ctx.run_id, category=FindingCategory.UNTRUSTED_IMAGE,
            title=f"GitLab CI {what} {ref} referenced by tag only (no digest)", detector="detector:image_pin",
            component_purl=ref, scope=Scope.PROD, project="ci", file_path=img.file, line=img.line,
            evidence_ids=[ev.evidence_id]))
    return ToolOutput(findings=findings, evidence=evidence,
                      summary=f"{len(images) + len(ci_images)} images (Dockerfile + CI), {len(findings)} tag-only")
