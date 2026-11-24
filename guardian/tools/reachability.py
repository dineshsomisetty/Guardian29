"""Import-level and function-level reachability (D4-05; ported from dev04, one-pass index added by Dev1).

Called by: tools/risk_tools.py (`reachability` and `exposure` tools of the risk analyst) and the risk scoring that
turns the tier into a reachability factor.
Question answered: does production code actually use a vulnerable package, so its CVE can matter?

Tiers (ReachabilityResult.tier):
  imported      the package is imported/required in at least one production source file (proven, with file+line)
  not_imported  source files were scanned and none imports it (likely only a transitive/unused dependency)
  unknown       nothing could be scanned for this ecosystem (no scanner, no source files): never read as safe
Function level (`reachability_called`, stretch goal 1): for packages with a reviewed rule in
data/reachability/vulnerable_functions.yaml, find call sites of the known-vulnerable functions (npm only).
Evidence `called` entries: {vuln_ids, functions, why, sites:[{function, file, line, excerpt}]}.

Inputs: the work copy of the target. Test paths, build output and vendored dirs are skipped (SKIP_DIRS,
TEST_HINTS), files over MAX_FILE_BYTES are ignored. Ecosystems: npm (JS/TS), pypi (.py), maven (Java/Kotlin...).
The tree is scanned once per (root, ecosystem, include_tests) into an in-memory index {package: first 5 hits}, so
scoring hundreds of findings does not rescan the tree. No network, no disk cache; read errors skip the file.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Directories never scanned: dependencies, VCS, build output, virtualenvs, and "ftp" (Juice Shop ships
# deliberately vulnerable legacy files there that are not part of the running app).
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__", ".venv", "venv", "ftp",
             "target", ".gradle"}
# Directory names that mark test/fixture code: an import there does not make a package reachable in production.
TEST_HINTS = {"test", "tests", "spec", "specs", "__tests__", "e2e", "cypress", "fixtures", "mocks", "it",
              "integration-test", "testfixtures"}
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
PY_EXT = {".py"}
JVM_EXT = {".java", ".kt", ".scala", ".groovy"}
MAX_FILE_BYTES = 1_000_000  # skip huge generated/minified files (also keeps the regex scan fast)

# JS/TS: require("x"), from "x", import "x", import("x"); group 1 = package name (scoped names kept, subpath dropped)
_JS = re.compile(r"""(?:require\(\s*|\bfrom\s+|\bimport\s+|\bimport\(\s*)['"]((?:@[\w.-]+/)?[\w.-]+)(?:/[^'"]*)?['"]""")
# Python: `import x` / `from x ...` at line start; group 1 = top-level module name
_PY = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][\w]*)", re.M)
# Java/Kotlin: `import com.thoughtworks.xstream.XStream;` -> indexed under every dotted prefix, so a Maven
# package is found by its groupId (com.thoughtworks.xstream)
_JVM = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)")


@dataclass
class ReachabilityResult:
    """Outcome of an import search: the tier, up to max_hits import sites, and how many source files were read."""

    tier: str
    hits: list[dict]  # [{file, line, excerpt}]
    files_scanned: int


def _is_test_path(rel: Path) -> bool:
    """True for paths that look like test code (test dirs, *.test.js, test_*.py, FooTest.java ...)."""
    if any(p.lower() in TEST_HINTS for p in rel.parts[:-1]):
        return True
    n = rel.name.lower()
    # JVM conventions: FooTest.java, FooTests.kt, FooIT.java (failsafe integration tests), src/it/...
    jvm = n.rsplit(".", 1)[0].endswith(("test", "tests", "it")) and n.endswith((".java", ".kt", ".scala", ".groovy"))
    return ".test." in n or ".spec." in n or n.startswith("test_") or n.endswith("_test.py") or jvm


def norm(name: str, ecosystem: str) -> str:
    """Key under which a package is looked up in the import index: PyPI names are case-folded with - as _
    (import names use underscores); Maven uses the groupId; npm names are used as is."""
    if ecosystem == "pypi":
        return name.lower().replace("-", "_")
    if ecosystem == "maven":
        return name.split("/", 1)[0]  # groupId: what Java code imports
    return name


# Process-wide memo of scan results; keyed by absolute root so a patched copy is scanned separately.
_INDEX: dict[tuple[str, str, bool], tuple[dict[str, list[dict]], int]] = {}


def import_index(root: Path | str, ecosystem: str = "npm", include_tests: bool = False
                 ) -> tuple[dict[str, list[dict]], int]:
    """Scan `root` once and return ({normalised package: up to 5 hits [{file, line, excerpt}]}, files scanned).
    `include_tests` also reads test paths (used to tell "only tests import it" from "nothing imports it").
    Results are memoised per (root, ecosystem, include_tests); an unsupported ecosystem yields ({}, 0)."""
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
                names = [norm(m.group(1), ecosystem)]  # normally one name per import
                if ecosystem == "maven":
                    # com.a.b.C is recorded under com.a, com.a.b and com.a.b.C so a Maven groupId prefix matches
                    parts = m.group(1).split(".")
                    names = [".".join(parts[:k]) for k in range(2, len(parts) + 1)]
                for name in names:
                    hits = index.setdefault(name, [])
                    if len(hits) < 5:  # a few sites are enough as evidence; keeps the index small
                        hits.append({"file": rel.as_posix(), "line": i, "excerpt": line.strip()[:200]})
    _INDEX[key] = (index, scanned)
    return index, scanned


def reachability_import(root: Path | str, package: str, ecosystem: str = "npm",
                        include_tests: bool = False, max_hits: int = 5) -> ReachabilityResult:
    """Tier for one package: imported / not_imported / unknown (nothing scanned), with its import sites."""
    index, scanned = import_index(root, ecosystem, include_tests)
    if scanned == 0:
        return ReachabilityResult("unknown", [], 0)
    hits = index.get(norm(package, ecosystem), [])[:max_hits]
    return ReachabilityResult("imported" if hits else "not_imported", hits, scanned)


# ---------------------------------------------------------------- function-level ("called", stretch goal 1)

# Reviewed (human-curated) list of vulnerable functions per package; function-level proof only exists for these.
RULES_FILE = Path(__file__).resolve().parents[2] / "data" / "reachability" / "vulnerable_functions.yaml"
_RULES: dict | None = None  # lazily loaded copy of RULES_FILE; {} when the file is missing or unreadable


def vulnerable_functions(package: str, ecosystem: str = "npm") -> list[dict]:
    """Reviewed rules for `package`: [{vuln_ids, functions, why}] (empty when none). Loads the YAML once."""
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
    q = re.escape(package)  # the package name as a literal inside the patterns below
    # Four binding shapes: `import ns[, {a, b as c}] from "pkg"`, `import {a} from "pkg"`,
    # `const ns = require("pkg")` and `const {a, b: c} = require("pkg")`
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
    """Record one `name` or `name as local` import specifier into `named` as {imported name: local name}."""
    bits = part.strip().split(" as ")
    if bits and bits[0].strip():
        named[bits[0].strip()] = (bits[1] if len(bits) > 1 else bits[0]).strip()


def call_sites(root: Path | str, package: str, functions: list[str], ecosystem: str = "npm",
               max_hits: int = 5) -> list[dict]:
    """Call sites of `functions` of `package` in production code ([{function, file, line, excerpt}]).
    `__call__` is a call of the default export itself. Only files that import the package are read."""
    if ecosystem != "npm":
        return []  # function-level search is implemented for JS/TS only
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
        pats = []  # (function, regex) pairs that count as a call or use of a vulnerable function in this file
        for fn in functions:
            if fn == "__call__":
                pats += [(fn, rf"(?<![\w$.]){re.escape(s)}\s*\(") for s in spaces]
            else:
                # a call, or a reference used as a value (`(jws.verify as Fn)(token)`, a callback): not an assignment
                pats += [(fn, rf"(?<![\w$]){re.escape(s)}\.{re.escape(fn)}\b(?!\s*=[^=])") for s in spaces]
                if fn in named:
                    pats.append((fn, rf"(?<![\w$.]){re.escape(named[fn])}\s*\("))
        for i, line in enumerate(text.splitlines(), 1):
            if re.match(r"\s*(import\b|//|\*)", line) or "require(" in line:  # imports and comments are not calls
                continue
            for fn, pat in pats:
                if re.search(pat, line):
                    out.append({"function": fn, "file": rel, "line": i, "excerpt": line.strip()[:200]})
                    break
            if len(out) >= max_hits:  # enough sites to show a human; stop early
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
