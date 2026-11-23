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


def generate_sbom(source: str, out_file: Path, timeout: int = 600) -> dict:
    """`source` is e.g. `dir:<work>` or an image ref. Returns facts for an Evidence(kind='sbom')."""
    out_file = Path(out_file)
    if not out_file.name.endswith(".cdx.json"):
        raise ValueError("SBOM file name must end with .cdx.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false")
    proc = subprocess.run([find_tool("syft"), source, "-o", f"cyclonedx-json={out_file}", "-q"],
                          capture_output=True, text=True, timeout=timeout, env=env)
    if proc.returncode != 0:
        raise RuntimeError(f"syft failed: {proc.stderr[-800:]}")
    data = json.loads(out_file.read_text(encoding="utf-8"))
    comps = data.get("components", [])
    version = subprocess.run([find_tool("syft"), "version"], capture_output=True, text=True).stdout
    ver = next((l.split()[-1] for l in version.splitlines() if l.startswith("Version:")), "unknown")
    return {
        "source_tool": f"syft@{ver}",
        "artifact_path": str(out_file),
        "sha256": hashlib.sha256(out_file.read_bytes()).hexdigest(),
        "facts": {"components": len(comps), "has_dependencies": bool(data.get("dependencies")),
                  "dependency_edges": sum(len(d.get("dependsOn", [])) for d in data.get("dependencies", []))},
    }
