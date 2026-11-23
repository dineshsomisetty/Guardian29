"""Import-level reachability (D4-05; ported from dev04, one-pass index added by Dev1).

Searches production source for imports of a package and returns a tier with file+line evidence. Only "imported"
is proven; "called" (function-level) is out of scope. Tiers: imported | not_imported | unknown (nothing scanned).
The source tree is scanned once per (root, ecosystem) into an index {package: hits}, so scoring hundreds of
findings does not rescan the tree.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__", ".venv", "venv", "ftp"}
TEST_HINTS = {"test", "tests", "spec", "specs", "__tests__", "e2e", "cypress", "fixtures", "mocks"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
PY_EXT = {".py"}
MAX_FILE_BYTES = 1_000_000

_JS = re.compile(r"""(?:require\(\s*|\bfrom\s+|\bimport\s+|\bimport\(\s*)['"]((?:@[\w.-]+/)?[\w.-]+)(?:/[^'"]*)?['"]""")
_PY = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][\w]*)", re.M)


@dataclass
class ReachabilityResult:
    tier: str
    hits: list[dict]  # [{file, line, excerpt}]
    files_scanned: int


def _is_test_path(rel: Path) -> bool:
    if any(p.lower() in TEST_HINTS for p in rel.parts[:-1]):
        return True
    n = rel.name.lower()
    return ".test." in n or ".spec." in n or n.startswith("test_") or n.endswith("_test.py")


def norm(name: str, ecosystem: str) -> str:
    return name.lower().replace("-", "_") if ecosystem == "pypi" else name


_INDEX: dict[tuple[str, str, bool], tuple[dict[str, list[dict]], int]] = {}


def import_index(root: Path | str, ecosystem: str = "npm", include_tests: bool = False
                 ) -> tuple[dict[str, list[dict]], int]:
    root = Path(root).resolve()
    key = (str(root), ecosystem, include_tests)
    if key in _INDEX:
        return _INDEX[key]
    exts, pat = (JS_EXT, _JS) if ecosystem == "npm" else (PY_EXT, _PY)
    index: dict[str, list[dict]] = {}
    scanned = 0
    for path in sorted(root.rglob("*")):
        if path.suffix not in exts or not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts) or (not include_tests and _is_test_path(rel)):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        scanned += 1
        for i, line in enumerate(lines, 1):
            for m in pat.finditer(line):
                hits = index.setdefault(norm(m.group(1), ecosystem), [])
                if len(hits) < 5:
                    hits.append({"file": rel.as_posix(), "line": i, "excerpt": line.strip()[:200]})
    _INDEX[key] = (index, scanned)
    return index, scanned


def reachability_import(root: Path | str, package: str, ecosystem: str = "npm",
                        include_tests: bool = False, max_hits: int = 5) -> ReachabilityResult:
    index, scanned = import_index(root, ecosystem, include_tests)
    if scanned == 0:
        return ReachabilityResult("unknown", [], 0)
    hits = index.get(norm(package, ecosystem), [])[:max_hits]
    return ReachabilityResult("imported" if hits else "not_imported", hits, scanned)
