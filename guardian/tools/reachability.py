"""Import-level reachability (D4-05).

Searches production source for imports of a package and returns a tier with file+line evidence.
We only prove "imported"; "called" (function-level) is out of scope except for hand-picked demo CVEs.
Tiers: imported | not_imported | unknown (nothing scanned).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__", ".venv", "venv"}
TEST_HINTS = {"test", "tests", "spec", "specs", "__tests__", "e2e", "cypress", "fixtures", "mocks"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
PY_EXT = {".py"}


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


def _js_patterns(name: str) -> list[re.Pattern]:
    q = re.escape(name)
    mod = rf"""['"]{q}(?:/[^'"]*)?['"]"""
    return [re.compile(rf"require\(\s*{mod}\s*\)"), re.compile(rf"\bfrom\s+{mod}"),
            re.compile(rf"\bimport\s+{mod}"), re.compile(rf"\bimport\(\s*{mod}\s*\)")]


def _py_patterns(name: str) -> list[re.Pattern]:
    mods = {name.replace("-", "_").lower(), name.lower()}
    alt = "|".join(re.escape(m) for m in mods)
    return [re.compile(rf"^\s*import\s+(?:{alt})(?:\.\w+)*\b", re.IGNORECASE),
            re.compile(rf"^\s*from\s+(?:{alt})(?:\.\w+)*\s+import\b", re.IGNORECASE)]


def reachability_import(root: Path | str, package: str, ecosystem: str = "npm",
                        include_tests: bool = False, max_hits: int = 5) -> ReachabilityResult:
    root = Path(root)
    exts, pats = (JS_EXT, _js_patterns(package)) if ecosystem == "npm" else (PY_EXT, _py_patterns(package))
    hits: list[dict] = []
    scanned = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in exts:
            continue
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if not include_tests and _is_test_path(rel):
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        scanned += 1
        for i, line in enumerate(lines, 1):
            if any(p.search(line) for p in pats) and len(hits) < max_hits:
                hits.append({"file": rel.as_posix(), "line": i, "excerpt": line.strip()[:200]})
    if scanned == 0:
        return ReachabilityResult("unknown", [], 0)
    return ReachabilityResult("imported" if hits else "not_imported", hits, scanned)
