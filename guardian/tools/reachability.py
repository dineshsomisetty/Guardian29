# Document the contract for the surrounding module or callable.
"""Import-level and function-level reachability (D4-05; ported from dev04, one-pass index added by Dev1).

Called by: tools/risk_tools.py (`reachability` and `exposure` tools of the risk analyst) and the risk scoring that
turns the tier into a reachability factor.
Question answered: does production code actually use a vulnerable package, so its CVE can matter?

Tiers (ReachabilityResult.tier):
  imported      the package is imported/required in at least one production source file (proven, with file+line)
  not_imported  source files were scanned and no supported import pattern matched
  unknown       nothing could be scanned for this ecosystem (no scanner, no source files): never read as safe
Function level (`reachability_called`, stretch goal 1): for packages with a reviewed rule in
data/reachability/vulnerable_functions.yaml, find call sites of the known-vulnerable functions (npm only).
Evidence `called` entries: {vuln_ids, functions, why, sites:[{function, file, line, excerpt}]}.
These are static text-pattern checks, not runtime traces or a whole-program call graph.
Dynamic loading, aliases outside the supported patterns, and transitive use can be missed;
neither not_imported nor a matching call site establishes exploitability on its own.

Inputs: the work copy of the target. Test paths, build output and vendored dirs are skipped (SKIP_DIRS,
TEST_HINTS), files over MAX_FILE_BYTES are ignored. Ecosystems: npm (JS/TS), pypi (.py), maven (Java/Kotlin...).
The tree is scanned once per (root, ecosystem, include_tests) into an in-memory index {package: first 5 hits}, so
scoring hundreds of findings does not rescan the tree. No network, no disk cache; read errors skip the file.
"""
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Load re for source import scanning.
import re
# Import dataclass from dataclasses.
from dataclasses import dataclass
# Import Path from pathlib.
from pathlib import Path

# Directories never scanned: dependencies, VCS, build output, virtualenvs, and "ftp" (Juice Shop ships
# deliberately vulnerable legacy files there that are not part of the running app).
# Store a collection of distinct values in SKIP_DIRS.
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", "__pycache__", ".venv", "venv", "ftp",
             # Supply the next part of the expression started above.
             "target", ".gradle"}
# Directory names that mark test/fixture code: an import there does not make a package reachable in production.
# Store a collection of distinct values in TEST_HINTS.
TEST_HINTS = {"test", "tests", "spec", "specs", "__tests__", "e2e", "cypress", "fixtures", "mocks", "it",
              # Supply the next part of the expression started above.
              "integration-test", "testfixtures"}
# Store a collection of distinct values in JS_EXT.
JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
# Store a collection of distinct values in PY_EXT.
PY_EXT = {".py"}
# Store a collection of distinct values in JVM_EXT.
JVM_EXT = {".java", ".kt", ".scala", ".groovy"}
# Give MAX_FILE_BYTES its starting value.
# The initial value is 1000000.
MAX_FILE_BYTES = 1_000_000  # skip huge generated/minified files (also keeps the regex scan fast)

# JS/TS: require("x"), from "x", import "x", import("x"); group 1 = package name (scoped names kept, subpath dropped)
# Store the result of re.compile in _JS.
_JS = re.compile(r"""(?:require\(\s*|\bfrom\s+|\bimport\s+|\bimport\(\s*)['"]((?:@[\w.-]+/)?[\w.-]+)(?:/[^'"]*)?['"]""")
# Python: `import x` / `from x ...` at line start; group 1 = top-level module name
# Store the result of re.compile in _PY.
_PY = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][\w]*)", re.M)
# Java/Kotlin: `import com.thoughtworks.xstream.XStream;` -> indexed under every dotted prefix, so a Maven
# package is found by its groupId (com.thoughtworks.xstream)
# Store the result of re.compile in _JVM.
_JVM = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)")


# Apply the dataclass decorator to the declaration below.
@dataclass
# Define ReachabilityResult for source import scanning.
# Group the related fields or methods under this type.
class ReachabilityResult:
    # Document the contract for the surrounding module or callable.
    """Outcome of an import search: the tier, up to max_hits import sites, and how many source files were read."""

    # Declare tier with type str.
    # The caller or container supplies the value.
    tier: str
    # Declare hits with type list[dict].
    # The caller or container supplies the value.
    hits: list[dict]  # [{file, line, excerpt}]
    # Declare files_scanned with type int.
    # The caller or container supplies the value.
    files_scanned: int


# Define _is_test_path for source import scanning.
# Inputs include rel.
def _is_test_path(rel: Path) -> bool:
    # Document the contract for the surrounding module or callable.
    """True for paths that look like test code (test dirs, *.test.js, test_*.py, FooTest.java ...)."""
    # Check whether any((p.lower() in TEST_HINTS for p in rel.parts[:-1])).
    if any(p.lower() in TEST_HINTS for p in rel.parts[:-1]):
        # Return True to the caller.
        return True
    # Store the result of rel.name.lower in n.
    n = rel.name.lower()
    # JVM conventions: FooTest.java, FooTests.kt, FooIT.java (failsafe integration tests), src/it/...
    # Store the expression on this line in jvm.
    jvm = n.rsplit(".", 1)[0].endswith(("test", "tests", "it")) and n.endswith((".java", ".kt", ".scala", ".groovy"))
    # Return the expression on this line to the caller.
    return ".test." in n or ".spec." in n or n.startswith("test_") or n.endswith("_test.py") or jvm


# Define norm for source import scanning.
# Inputs include name, ecosystem.
def norm(name: str, ecosystem: str) -> str:
    # Document the contract for the surrounding module or callable.
    """Key under which a package is looked up in the import index: PyPI names are case-folded with - as _
    (import names use underscores); Maven uses the groupId; npm names are used as is."""
    # Check whether ecosystem == 'pypi'.
    if ecosystem == "pypi":
        # Return the result of name.lower().replace to the caller.
        return name.lower().replace("-", "_")
    # Check whether ecosystem == 'maven'.
    if ecosystem == "maven":
        # Return name.split('/', 1)[0] to the caller.
        return name.split("/", 1)[0]  # groupId: what Java code imports
    # Return name to the caller.
    return name


# Process-wide memo of scan results; keyed by absolute root so a patched copy is scanned separately.
# Declare _INDEX with type dict[tuple[str, str, bool], tuple[dict[str, list[dict]], int]].
# Use a mapping keyed by the fields below as its initial value.
_INDEX: dict[tuple[str, str, bool], tuple[dict[str, list[dict]], int]] = {}


# Define import_index for source import scanning.
# Inputs include root, ecosystem, include_tests.
def import_index(root: Path | str, ecosystem: str = "npm", include_tests: bool = False
                 # Close the current expression or collection.
                 ) -> tuple[dict[str, list[dict]], int]:
    # Document the contract for the surrounding module or callable.
    """Scan `root` once and return ({normalised package: up to 5 hits [{file, line, excerpt}]}, files scanned).
    `include_tests` also reads test paths (used to tell "only tests import it" from "nothing imports it").
    Results are memoised per (root, ecosystem, include_tests); an unsupported ecosystem yields ({}, 0)."""
    # Store the result of Path(root).resolve in root.
    root = Path(root).resolve()
    # Store (str(root), ecosystem, include_tests) in key.
    key = (str(root), ecosystem, include_tests)
    # Check whether key in _INDEX.
    if key in _INDEX:
        # Return _INDEX[key] to the caller.
        return _INDEX[key]
    # Store the result of the expression on this line in (exts, pat).
    exts, pat = {"npm": (JS_EXT, _JS), "pypi": (PY_EXT, _PY), "maven": (JVM_EXT, _JVM)}.get(ecosystem, (set(), None))
    # Check whether pat is None.
    if pat is None:
        # Store ({}, 0) in _INDEX[key].
        _INDEX[key] = ({}, 0)  # no scanner for this ecosystem: unknown, never "not imported"
        # Return _INDEX[key] to the caller.
        return _INDEX[key]
    # Declare index with type dict[str, list[dict]].
    # Use a mapping keyed by the fields below as its initial value.
    index: dict[str, list[dict]] = {}
    # Give scanned its starting value.
    # The initial value is 0.
    scanned = 0
    # Iterate over sorted(root.rglob('*')).
    # Bind each item to path before processing it.
    for path in sorted(root.rglob("*")):
        # Check whether path.suffix not in exts or not path.is_file().
        if path.suffix not in exts or not path.is_file():
            # Skip the remaining work for this item.
            continue
        # Store the result of path.relative_to in rel.
        rel = path.relative_to(root)
        # Check whether the expression on this line.
        if any(part in SKIP_DIRS for part in rel.parts) or (not include_tests and _is_test_path(rel)):
            # Skip the remaining work for this item.
            continue
        # Run the following operation with exception handling.
        # The handlers below determine how the listed failures are handled.
        try:
            # Check whether path.stat().st_size > MAX_FILE_BYTES.
            if path.stat().st_size > MAX_FILE_BYTES:
                # Skip the remaining work for this item.
                continue
            # Store the result of path.read_text(encoding='utf-8', errors='replace').splitlines in lines.
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        # Handle OSError from the preceding block.
        except OSError:
            # Skip the remaining work for this item.
            continue
        # Update the existing value of scanned.
        # The update incorporates 1.
        scanned += 1
        # Iterate over enumerate(lines, 1).
        # Bind each item to (i, line) before processing it.
        for i, line in enumerate(lines, 1):
            # Iterate over pat.finditer(line).
            # Bind each item to m before processing it.
            for m in pat.finditer(line):
                # Store an ordered collection in names.
                names = [norm(m.group(1), ecosystem)]  # normally one name per import
                # Check whether ecosystem == 'maven'.
                if ecosystem == "maven":
                    # com.a.b.C is recorded under com.a, com.a.b and com.a.b.C so a Maven groupId prefix matches
                    # Store the result of m.group(1).split in parts.
                    parts = m.group(1).split(".")
                    # Store values selected or transformed from the input in names.
                    names = [".".join(parts[:k]) for k in range(2, len(parts) + 1)]
                # Iterate over names.
                # Bind each item to name before processing it.
                for name in names:
                    # Store the result of index.setdefault in hits.
                    hits = index.setdefault(name, [])
                    # Check whether len(hits) < 5.
                    if len(hits) < 5:  # a few sites are enough as evidence; keeps the index small
                        # Call hits.append at this point.
                        hits.append({"file": rel.as_posix(), "line": i, "excerpt": line.strip()[:200]})
    # Store (index, scanned) in _INDEX[key].
    _INDEX[key] = (index, scanned)
    # Return (index, scanned) to the caller.
    return index, scanned


# Look up import evidence for a package in the source index.
# Inputs include root, package, ecosystem, include_tests, max_hits.
def reachability_import(root: Path | str, package: str, ecosystem: str = "npm",
                        # Continue the function signature with its remaining arguments.
                        include_tests: bool = False, max_hits: int = 5) -> ReachabilityResult:
    # Document the contract for the surrounding module or callable.
    """Tier for one package: imported / not_imported / unknown (nothing scanned), with its import sites."""
    # Store the result of import_index in (index, scanned).
    index, scanned = import_index(root, ecosystem, include_tests)
    # Check whether scanned == 0.
    if scanned == 0:
        # Return the result of ReachabilityResult to the caller.
        return ReachabilityResult("unknown", [], 0)
    # Store index.get(norm(package, ecosystem), [])[:max_hits] in hits.
    hits = index.get(norm(package, ecosystem), [])[:max_hits]
    # Return the result of ReachabilityResult to the caller.
    return ReachabilityResult("imported" if hits else "not_imported", hits, scanned)


# ---------------------------------------------------------------- function-level ("called", stretch goal 1)

# Reviewed (human-curated) list of vulnerable functions per package; function-level proof only exists for these.
# Store the expression on this line in RULES_FILE.
RULES_FILE = Path(__file__).resolve().parents[2] / "data" / "reachability" / "vulnerable_functions.yaml"
# Declare _RULES with type dict | None.
# Use None to represent an absent value as its initial value.
_RULES: dict | None = None  # lazily loaded copy of RULES_FILE; {} when the file is missing or unreadable


# Define vulnerable_functions for source import scanning.
# Inputs include package, ecosystem.
def vulnerable_functions(package: str, ecosystem: str = "npm") -> list[dict]:
    # Document the contract for the surrounding module or callable.
    """Reviewed rules for `package`: [{vuln_ids, functions, why}] (empty when none). Loads the YAML once."""
    # Use the module-level binding for _RULES.
    # Assignments to the name update the shared module state.
    global _RULES
    # Check whether _RULES is None.
    if _RULES is None:
        # Load yaml for source import scanning.
        import yaml

        # Run the following operation with exception handling.
        # The handlers below determine how the listed failures are handled.
        try:
            # Store yaml.safe_load(RULES_FILE.read_text(encoding='utf-8')) or {} in _RULES.
            _RULES = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8")) or {}
        # Handle (OSError, ValueError) from the preceding block.
        except (OSError, ValueError):
            # Store a mapping keyed by the fields below in _RULES.
            _RULES = {}
    # Return the result of list to the caller.
    return list((_RULES.get(ecosystem) or {}).get(package) or [])


# Define _bindings for source import scanning.
# Inputs include text, package.
def _bindings(text: str, package: str) -> tuple[set[str], dict[str, str]]:
    # Document the contract for the surrounding module or callable.
    """Local names a file gives `package`: (namespaces/default bindings, {imported function: local name})."""
    # Store the result of re.escape in q.
    q = re.escape(package)  # the package name as a literal inside the patterns below
    # Four binding shapes: `import ns[, {a, b as c}] from "pkg"`, `import {a} from "pkg"`,
    # `const ns = require("pkg")` and `const {a, b: c} = require("pkg")`
    # Declare spaces with type set[str].
    # Use the result of set as its initial value.
    spaces: set[str] = set()
    # Declare named with type dict[str, str].
    # Use a mapping keyed by the fields below as its initial value.
    named: dict[str, str] = {}
    # Iterate over re.finditer(...).
    # Bind each item to m before processing it.
    for m in re.finditer(rf"""import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s*(?:,\s*\{{([^}}]*)\}})?\s*from\s*['"]{q}['"]""", text):
        # Call spaces.add at this point.
        spaces.add(m.group(1))
        # Iterate over (m.group(2) or '').split(',').
        # Bind each item to part before processing it.
        for part in (m.group(2) or "").split(","):
            # Call _named at this point.
            _named(part, named)
    # Iterate over re.finditer(...).
    # Bind each item to m before processing it.
    for m in re.finditer(rf"""import\s*\{{([^}}]*)\}}\s*from\s*['"]{q}['"]""", text):
        # Iterate over m.group(1).split(',').
        # Bind each item to part before processing it.
        for part in m.group(1).split(","):
            # Call _named at this point.
            _named(part, named)
    # Iterate over re.finditer(...).
    # Bind each item to m before processing it.
    for m in re.finditer(rf"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]{q}['"]\s*\)""", text):
        # Call spaces.add at this point.
        spaces.add(m.group(1))
    # Iterate over re.finditer(...).
    # Bind each item to m before processing it.
    for m in re.finditer(rf"""(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*require\(\s*['"]{q}['"]\s*\)""", text):
        # Iterate over m.group(1).split(',').
        # Bind each item to part before processing it.
        for part in m.group(1).split(","):
            # Call _named at this point.
            _named(part.replace(":", " as "), named)
    # Return (spaces, named) to the caller.
    return spaces, named


# Define _named for source import scanning.
# Inputs include part, named.
def _named(part: str, named: dict[str, str]) -> None:
    # Document the contract for the surrounding module or callable.
    """Record one `name` or `name as local` import specifier into `named` as {imported name: local name}."""
    # Store the result of part.strip().split in bits.
    bits = part.strip().split(" as ")
    # Check whether bits and bits[0].strip().
    if bits and bits[0].strip():
        # Store the result of (bits[1] if len(bits) > 1 else bits[0]).strip in named[bits[0].strip()].
        named[bits[0].strip()] = (bits[1] if len(bits) > 1 else bits[0]).strip()


# Define call_sites for source import scanning.
# Inputs include root, package, functions, ecosystem, max_hits.
def call_sites(root: Path | str, package: str, functions: list[str], ecosystem: str = "npm",
               # Continue the function signature with its remaining arguments.
               max_hits: int = 5) -> list[dict]:
    # Document the contract for the surrounding module or callable.
    """Call sites of `functions` of `package` in production code ([{function, file, line, excerpt}]).
    `__call__` is a call of the default export itself. Only files that import the package are read."""
    # Check whether ecosystem != 'npm'.
    if ecosystem != "npm":
        # Return an ordered collection to the caller.
        return []  # function-level search is implemented for JS/TS only
    # Store the result of Path(root).resolve in root.
    root = Path(root).resolve()
    # Store the result of import_index in (index, _).
    index, _ = import_index(root, ecosystem)
    # Store the result of sorted in files.
    files = sorted({h["file"] for h in index.get(package, [])})
    # Declare out with type list[dict].
    # Use an ordered collection as its initial value.
    out: list[dict] = []
    # Iterate over files.
    # Bind each item to rel before processing it.
    for rel in files:
        # Run the following operation with exception handling.
        # The handlers below determine how the listed failures are handled.
        try:
            # Store the result of (root / rel).read_text in text.
            text = (root / rel).read_text(encoding="utf-8", errors="replace")
        # Handle OSError from the preceding block.
        except OSError:
            # Skip the remaining work for this item.
            continue
        # Store the result of _bindings in (spaces, named).
        spaces, named = _bindings(text, package)
        # Store an ordered collection in pats.
        pats = []  # (function, regex) pairs that count as a call or use of a vulnerable function in this file
        # Iterate over functions.
        # Bind each item to fn before processing it.
        for fn in functions:
            # Check whether fn == '__call__'.
            if fn == "__call__":
                # Update the existing value of pats.
                # The update incorporates values selected or transformed from the input.
                pats += [(fn, rf"(?<![\w$.]){re.escape(s)}\s*\(") for s in spaces]
            # Supply the alternative for the preceding condition.
            # This path covers the case where the earlier branch does not apply.
            else:
                # a call, or a reference used as a value (`(jws.verify as Fn)(token)`, a callback): not an assignment
                # Update the existing value of pats.
                # The update incorporates values selected or transformed from the input.
                pats += [(fn, rf"(?<![\w$]){re.escape(s)}\.{re.escape(fn)}\b(?!\s*=[^=])") for s in spaces]
                # Check whether fn in named.
                if fn in named:
                    # Call pats.append at this point.
                    pats.append((fn, rf"(?<![\w$.]){re.escape(named[fn])}\s*\("))
        # Iterate over enumerate(text.splitlines(), 1).
        # Bind each item to (i, line) before processing it.
        for i, line in enumerate(text.splitlines(), 1):
            # Check whether re.match('\\s*(import\\b|//|\\*)', line) or 'require(' in line.
            if re.match(r"\s*(import\b|//|\*)", line) or "require(" in line:  # imports and comments are not calls
                # Skip the remaining work for this item.
                continue
            # Iterate over pats.
            # Bind each item to (fn, pat) before processing it.
            for fn, pat in pats:
                # Check whether re.search(pat, line).
                if re.search(pat, line):
                    # Call out.append at this point.
                    out.append({"function": fn, "file": rel, "line": i, "excerpt": line.strip()[:200]})
                    # Stop the current loop here.
                    break
            # Check whether len(out) >= max_hits.
            if len(out) >= max_hits:  # enough sites to show a human; stop early
                # Return out to the caller.
                return out
    # Return out to the caller.
    return out


# Define reachability_called for source import scanning.
# Inputs include root, package, ecosystem.
def reachability_called(root: Path | str, package: str, ecosystem: str = "npm") -> list[dict]:
    # Document the contract for the surrounding module or callable.
    """For each reviewed rule of `package` with a call site: {vuln_ids, functions, why, sites}."""
    # Store an ordered collection in found.
    found = []
    # Iterate over vulnerable_functions(package, ecosystem).
    # Bind each item to rule before processing it.
    for rule in vulnerable_functions(package, ecosystem):
        # Store the result of call_sites in sites.
        sites = call_sites(root, package, list(rule.get("functions") or []), ecosystem)
        # Check whether sites.
        if sites:
            # Call found.append at this point.
            found.append({"vuln_ids": list(rule.get("vuln_ids") or []), "functions": list(rule["functions"]),
                          # Provide the mapping fields why, sites on this line.
                          "why": rule.get("why"), "sites": sites})
    # Return found to the caller.
    return found
