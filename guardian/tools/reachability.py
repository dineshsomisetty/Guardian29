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

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__", ".venv", "venv", "ftp",
             "target", ".gradle"}
TEST_HINTS = {"test", "tests", "spec", "specs", "__tests__", "e2e", "cypress", "fixtures", "mocks", "it",
              "integration-test", "testfixtures"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
PY_EXT = {".py"}
JVM_EXT = {".java", ".kt", ".scala", ".groovy"}
MAX_FILE_BYTES = 1_000_000

_JS = re.compile(r"""(?:require\(\s*|\bfrom\s+|\bimport\s+|\bimport\(\s*)['"]((?:@[\w.-]+/)?[\w.-]+)(?:/[^'"]*)?['"]""")
_PY = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][\w]*)", re.M)
# Java/Kotlin: `import com.thoughtworks.xstream.XStream;` -> indexed under every dotted prefix, so a Maven
# package is found by its groupId (com.thoughtworks.xstream)
_JVM = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)")


@dataclass
class ReachabilityResult:
    tier: str
    hits: list[dict]  # [{file, line, excerpt}]
    files_scanned: int


def _is_test_path(rel: Path) -> bool:
    if any(p.lower() in TEST_HINTS for p in rel.parts[:-1]):
        return True
    n = rel.name.lower()
    # JVM conventions: FooTest.java, FooTests.kt, FooIT.java (failsafe integration tests), src/it/...
    jvm = n.rsplit(".", 1)[0].endswith(("test", "tests", "it")) and n.endswith((".java", ".kt", ".scala", ".groovy"))
    return ".test." in n or ".spec." in n or n.startswith("test_") or n.endswith("_test.py") or jvm


def norm(name: str, ecosystem: str) -> str:
    if ecosystem == "pypi":
        return name.lower().replace("-", "_")
    if ecosystem == "maven":
        return name.split("/", 1)[0]  # groupId: what Java code imports
    return name


_INDEX: dict[tuple[str, str, bool], tuple[dict[str, list[dict]], int]] = {}


def import_index(root: Path | str, ecosystem: str = "npm", include_tests: bool = False
                 ) -> tuple[dict[str, list[dict]], int]:
    root = Path(root).resolve()
    key = (str(root), ecosystem, include_tests)
    if key in _INDEX:
        return _INDEX[key]
    exts, pat = {"npm": (JS_EXT, _JS), "pypi": (PY_EXT, _PY), "maven": (JVM_EXT, _JVM)}.get(ecosystem, (set(), None))
    if pat is None:
        _INDEX[key] = ({}, 0)  # no scanner for this ecosystem: unknown, never "not imported"
        return _INDEX[key]
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
                names = [norm(m.group(1), ecosystem)]
                if ecosystem == "maven":
                    parts = m.group(1).split(".")
                    names = [".".join(parts[:k]) for k in range(2, len(parts) + 1)]
                for name in names:
                    hits = index.setdefault(name, [])
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


# ---------------------------------------------------------------- function-level ("called", stretch goal 1)

RULES_FILE = Path(__file__).resolve().parents[2] / "data" / "reachability" / "vulnerable_functions.yaml"
_RULES: dict | None = None


def vulnerable_functions(package: str, ecosystem: str = "npm") -> list[dict]:
    """Reviewed rules for `package`: [{vuln_ids, functions, why}] (empty when none)."""
    global _RULES
    if _RULES is None:
        import yaml

        try:
            _RULES = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8")) or {}
        except (OSError, ValueError):
            _RULES = {}
    return list((_RULES.get(ecosystem) or {}).get(package) or [])


def _bindings(text: str, package: str) -> tuple[set[str], dict[str, str]]:
    """Local names a file gives `package`: (namespaces/default bindings, {imported function: local name})."""
    q = re.escape(package)
    spaces: set[str] = set()
    named: dict[str, str] = {}
    for m in re.finditer(rf"""import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{{([^}}]*)\}})?\s*from\s*['"]{q}['"]""", text):
        spaces.add(m.group(1))
        for part in (m.group(2) or "").split(","):
            _named(part, named)
    for m in re.finditer(rf"""import\s*\{{([^}}]*)\}}\s*from\s*['"]{q}['"]""", text):
        for part in m.group(1).split(","):
            _named(part, named)
    for m in re.finditer(rf"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]{q}['"]\s*\)""", text):
        spaces.add(m.group(1))
    for m in re.finditer(rf"""(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*require\(\s*['"]{q}['"]\s*\)""", text):
        for part in m.group(1).split(","):
            _named(part.replace(":", " as "), named)
    return spaces, named


def _named(part: str, named: dict[str, str]) -> None:
    bits = part.strip().split(" as ")
    if bits and bits[0].strip():
        named[bits[0].strip()] = (bits[1] if len(bits) > 1 else bits[0]).strip()


def call_sites(root: Path | str, package: str, functions: list[str], ecosystem: str = "npm",
               max_hits: int = 5) -> list[dict]:
    """Call sites of `functions` of `package` in production code ([{function, file, line, excerpt}]).
    `__call__` is a call of the default export itself. Only files that import the package are read."""
    if ecosystem != "npm":
        return []
    root = Path(root).resolve()
    index, _ = import_index(root, ecosystem)
    files = sorted({h["file"] for h in index.get(package, [])})
    out: list[dict] = []
    for rel in files:
        try:
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        spaces, named = _bindings(text, package)
        pats = []
        for fn in functions:
            if fn == "__call__":
                pats += [(fn, rf"(?<![\w$.]){re.escape(s)}\s*\(") for s in spaces]
            else:
                # a call, or a reference used as a value (`(jws.verify as Fn)(token)`, a callback): not an assignment
                pats += [(fn, rf"(?<![\w$]){re.escape(s)}\.{re.escape(fn)}\b(?!\s*=[^=])") for s in spaces]
                if fn in named:
                    pats.append((fn, rf"(?<![\w$.]){re.escape(named[fn])}\s*\("))
        for i, line in enumerate(text.splitlines(), 1):
            if re.match(r"\s*(import\b|//|\*)", line) or "require(" in line:
                continue
            for fn, pat in pats:
                if re.search(pat, line):
                    out.append({"function": fn, "file": rel, "line": i, "excerpt": line.strip()[:200]})
                    break
            if len(out) >= max_hits:
                return out
    return out


def reachability_called(root: Path | str, package: str, ecosystem: str = "npm") -> list[dict]:
    """For each reviewed rule of `package` with a call site: {vuln_ids, functions, why, sites}."""
    found = []
    for rule in vulnerable_functions(package, ecosystem):
        sites = call_sites(root, package, list(rule.get("functions") or []), ecosystem)
        if sites:
            found.append({"vuln_ids": list(rule.get("vuln_ids") or []), "functions": list(rule["functions"]),
                          "why": rule.get("why"), "sites": sites})
    return found
