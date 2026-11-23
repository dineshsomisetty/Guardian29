"""D2-02 SBOM: `syft scan dir:<work> -o cyclonedx-json=<run>/sbom.cdx.json`. Owner: Dev2."""

from __future__ import annotations

import json
import os

from guardian.core.models import Evidence
from guardian.tools.binaries import find, run, sha256_file, version
from guardian.tools.registry import ToolContext, ToolOutput

# Legacy/backup and challenge folders are not part of the shipped app; analysed separately (what changed).
EXCLUDES = ["./ftp/**", "./**/node_modules/**", "./test/**", "./data/static/**"]


def generate_sbom(ctx: ToolContext) -> ToolOutput:
    work = ctx.work_dir or ctx.repo
    out = ctx.run_dir / "sbom.cdx.json"
    args = [find("syft"), "scan", f"dir:{work}", "-o", f"cyclonedx-json={out}", "-q"]
    for ex in EXCLUDES:
        args += ["--exclude", ex]
    # Syft's npm lockfile cataloger omits devDependencies by default. Build tooling is part of the supply chain
    # (and the graph, scope=dev), so include them: otherwise Grype never scans ~600 packages.
    run(args, timeout=900, env={**os.environ, "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"})
    bom = json.loads(out.read_text(encoding="utf-8"))
    comps = bom.get("components", [])
    npm = sum(1 for c in comps if str(c.get("purl", "")).startswith("pkg:npm/"))
    ev = Evidence(run_id=ctx.run_id, kind="sbom", source_tool=f"syft@{version('syft')}",
                  facts={"format": "CycloneDX", "spec_version": bom.get("specVersion"), "components": len(comps),
                         "npm_components": npm, "dependency_entries": len(bom.get("dependencies", [])),
                         "includes_dev_dependencies": True,
                         "unique_purls": len({c["purl"] for c in comps if c.get("purl")})},
                  artifact_path="sbom.cdx.json", sha256=sha256_file(out))
    return ToolOutput(evidence=[ev], artifacts={"sbom_path": out}, summary=f"CycloneDX SBOM: {len(comps)} components")
