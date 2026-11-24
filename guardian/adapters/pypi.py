"""PyPI ecosystem adapter (D2-09): find pip projects, read requirements pins with line numbers, purls. Owner: Dev1.

Nothing is installed or executed: a project's dependencies are what `requirements*.txt` pins (`name==version`);
unpinned lines are reported as such, not resolved. Syft/Grype then scan the directory / SBOM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build", "tests", "test", "docs"}
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*((?:[<>=!~]=?|===)[^;#\s]*)?")


@dataclass
class PipProject:
    name: str  # "root" | relative dir
    dir: Path
    requirements: list[Path]


def purl(name: str, version: str) -> str:
    """Syft/Grype style: lower-case, `_` and `.` folded to `-` (PEP 503)."""
    return f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{version}"


def find_projects(root: Path) -> list[PipProject]:
    by_dir: dict[Path, list[Path]] = {}
    for req in sorted(root.rglob("requirements*.txt")):
        rel = req.parent.relative_to(root)
        if any(p in SKIP_DIRS for p in rel.parts) or len(rel.parts) > 2:
            continue
        by_dir.setdefault(req.parent, []).append(req)
    return [PipProject("root" if d == root else d.relative_to(root).as_posix(), d, reqs)
            for d, reqs in sorted(by_dir.items())]


def requirement_pins(path: Path) -> list[tuple[str, str | None, str | None, int]]:
    """[(name, exact version or None, raw specifier, 1-based line)] for the requirement lines of a file."""
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith(("#", "-", "git+", "http")):
            continue
        m = _REQ.match(s)
        if not m:
            continue
        spec = m.group(3)
        version = spec[2:] if spec and spec.startswith("==") else None
        out.append((m.group(1), version, spec, i))
    return out
