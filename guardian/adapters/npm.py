"""npm ecosystem adapter: find projects, read manifests with line numbers, purls. Owner: Dev2."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "ftp", "dist", "build", "test", "tests", "data", "cypress", ".angular"}
DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


@dataclass
class NpmProject:
    name: str  # "root" | "frontend" | relative dir
    dir: Path
    manifest: Path
    lockfile: Path


def purl(name: str, version: str) -> str:
    """Same encoding Syft/Grype use: scoped names keep '@' percent-encoded."""
    return f"pkg:npm/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{version}"


def find_projects(root: Path) -> list[NpmProject]:
    out = []
    for manifest in sorted(root.rglob("package.json")):
        rel = manifest.parent.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts) or len(rel.parts) > 2:
            continue
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not any(data.get(s) for s in DEP_SECTIONS):
            continue
        name = "root" if not rel.parts else rel.as_posix()
        out.append(NpmProject(name, manifest.parent, manifest, manifest.parent / "package-lock.json"))
    return out


def manifest_deps(manifest: Path) -> list[tuple[str, str, str, int]]:
    """[(name, range, section, line)] with 1-based line numbers from the raw file."""
    text = manifest.read_text(encoding="utf-8")
    data = json.loads(text)
    lines = text.splitlines()
    out = []
    for section in DEP_SECTIONS:
        deps = data.get(section) or {}
        sec_line = next((i for i, ln in enumerate(lines) if re.search(rf'"{section}"\s*:', ln)), 0)
        for name, rng in deps.items():
            pat = re.compile(rf'^\s*"{re.escape(name)}"\s*:')
            line = next((i + 1 for i in range(sec_line, len(lines)) if pat.search(lines[i])), None)
            out.append((name, str(rng), section, line))
    return out


def line_of(path: Path, pattern: str) -> int | None:
    rx = re.compile(pattern)
    for i, ln in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if rx.search(ln):
            return i
    return None
