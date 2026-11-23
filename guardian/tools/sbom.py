"""SBOM generation with Syft (D2-02, Dev2). Output name must end `.cdx.json` so OSV-Scanner recognises it."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def find_tool(name: str) -> str:
    local = ROOT / "tools" / "bin" / (name + (".exe" if os.name == "nt" else ""))
    if local.is_file():
        return str(local)
    exe = shutil.which(name)
    if not exe:
        raise RuntimeError(f"{name} not found; run scripts/install_tools.sh")
    return exe


def run_syft(source: str, out_file: Path, timeout: int = 600) -> dict:
    """`source` is e.g. `dir:<work>` or an image ref. Returns facts for an Evidence(kind='sbom')."""
    out_file = Path(out_file)
    if not out_file.name.endswith(".cdx.json"):
        raise ValueError("SBOM file name must end with .cdx.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    # Syft omits npm devDependencies by default; we want them (they run at build time). Scope is kept
    # per package (prod/dev) in the graph and lowers priority via factor P.
    env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false", SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES="true")
    proc = subprocess.run([find_tool("syft"), source, "-o", f"cyclonedx-json={out_file}", "-q"],
                          capture_output=True, text=True, timeout=timeout, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"syft failed: {proc.stderr[-800:]}")
    data = json.loads(out_file.read_text(encoding="utf-8"))
    comps = data.get("components", [])
    version = subprocess.run([find_tool("syft"), "version"], capture_output=True, text=True).stdout
    ver = next((ln.split()[-1] for ln in version.splitlines() if ln.startswith("Version:")), "unknown")
    return {
        "source_tool": f"syft@{ver}",
        "artifact_path": str(out_file),
        "sha256": hashlib.sha256(out_file.read_bytes()).hexdigest(),
        "facts": {"components": len(comps), "has_dependencies": bool(data.get("dependencies")),
                  "dependency_edges": sum(len(d.get("dependsOn", [])) for d in data.get("dependencies", []))},
    }


def generate_sbom(ctx):
    """Tool entry point (registry binding `sbom`): Syft CycloneDX of the work copy -> Evidence(kind='sbom')."""
    from guardian.core.models import Evidence
    from guardian.tools.registry import ToolOutput

    out = Path(ctx.run_dir) / "sbom.cdx.json"
    r = run_syft(f"dir:{Path(ctx.work_dir or ctx.repo)}", out)
    ev = Evidence(run_id=ctx.run_id, kind="sbom", source_tool=r["source_tool"], facts=r["facts"],
                  artifact_path=r["artifact_path"], sha256=r["sha256"])
    return ToolOutput(evidence=[ev], artifacts={"sbom_path": out},
                      summary=f"{r['facts']['components']} components in CycloneDX SBOM")


# ---------------------------------------------------------------- container image SBOM (D2-11)
# Published image used when nothing else is configured. Juice Shop: `snapshot` tag (closest to the pinned
# develop commit 20.4.0-SNAPSHOT), pinned by digest so results do not drift. Read straight from the registry by
# Syft: no Docker daemon and nothing is executed.
KNOWN_IMAGES = {
    "juice-shop": "registry:bkimminich/juice-shop@sha256:"
                  "ec3504cf36610deca5b8716421fc5acca1be6510cb796737ed6b2f24c24a8748",
}


def image_source(ctx) -> str | None:
    """Image to inventory: ctx.artifacts['image_ref'] (e.g. the sandbox-built `docker:<tag>`) >
    $GUARDIAN_IMAGE_REF > KNOWN_IMAGES[target name]."""
    return (ctx.artifacts.get("image_ref") or os.environ.get("GUARDIAN_IMAGE_REF")
            or KNOWN_IMAGES.get(Path(ctx.repo).name))


def image_sbom(ctx):
    """Tool entry point (registry binding `image_sbom`): Syft SBOM of the container image, merged into the graph
    under root `image` (OS + app packages). Evidence records WHICH image (published vs local build)."""
    from guardian.core.models import Evidence
    from guardian.tools.registry import ToolOutput

    src = image_source(ctx)
    if not src:
        return ToolOutput(summary="no container image configured (set GUARDIAN_IMAGE_REF)")
    out = Path(ctx.run_dir) / "sbom.image.cdx.json"
    plat = ["--platform", "linux/amd64"] if src.startswith("registry:") else []
    env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false")
    proc = subprocess.run([find_tool("syft"), src, *plat, "-o", f"cyclonedx-json={out}", "-q"],
                          capture_output=True, text=True, timeout=1200, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"syft (image) failed: {proc.stderr[-800:]}")
    merged = {}
    if ctx.graph is not None and hasattr(ctx.graph, "merge_image"):
        merged = ctx.graph.merge_image(out, src.split(":", 1)[1])
    kind = "published registry image" if src.startswith("registry:") else "local image"
    ev = Evidence(run_id=ctx.run_id, kind="sbom", source_tool="syft (image)", artifact_path=str(out),
                  sha256=hashlib.sha256(out.read_bytes()).hexdigest(),
                  facts={"image_ref": src, "image_source": kind, **merged})
    return ToolOutput(evidence=[ev], artifacts={"image_sbom_path": out},
                      summary=f"image {src.split('@')[0]} ({kind}): +{merged.get('added', '?')} packages "
                              f"({merged.get('os_packages', '?')} OS), {merged.get('shared_with_app', '?')} shared")
