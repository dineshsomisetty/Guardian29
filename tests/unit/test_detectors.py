# Document the contract for the surrounding module or callable.
"""Dev2/Dev4 CP1 tool tests on small synthetic projects (no scanners, no network)."""

# Load json for detectors tests.
import json

# Import load_settings from guardian.core.config.
from guardian.core.config import load_settings
# Import build_graph from guardian.core.graph_build.
from guardian.core.graph_build import build_graph
# Import Finding, FindingCategory, Priority, Scope from guardian.core.models.
from guardian.core.models import Finding, FindingCategory, Priority, Scope
# Import initial_risk from guardian.core.scoring.
from guardian.core.scoring import initial_risk
# Import ci_pin, image_pin, lockfile, typosquat, unexpected_change from guardian.tools.detectors.
from guardian.tools.detectors import ci_pin, image_pin, lockfile, typosquat, unexpected_change
# Import check_name, damerau_levenshtein from guardian.tools.detectors.similarity.
from guardian.tools.detectors.similarity import check_name, damerau_levenshtein
# Import ToolContext from guardian.tools.registry.
from guardian.tools.registry import ToolContext

# Store a mapping keyed by the fields below in LOCK.
LOCK = {
    # Provide the mapping fields lockfileVersion on this line.
    "lockfileVersion": 3,
    # Provide the mapping fields packages on this line.
    "packages": {
        # Supply the next part of the expression started above.
        "": {"dependencies": {"express-jwt": "0.1.3", "ngy-cookie": "^6.0.0"}, "devDependencies": {"mocha": "1"}},
        # Supply the next part of the expression started above.
        "node_modules/express-jwt": {"version": "0.1.3", "resolved": "https://registry.npmjs.org/express-jwt/-/express-jwt-0.1.3.tgz",
                                     # Provide the mapping fields integrity, dependencies on this line.
                                     "integrity": "sha512-AAA", "dependencies": {"jsonwebtoken": "~0.1.0"}},
        # Supply the next part of the expression started above.
        "node_modules/express-jwt/node_modules/jsonwebtoken": {"version": "0.1.0", "integrity": "sha512-BBB"},
        # Supply the next part of the expression started above.
        "node_modules/ngy-cookie": {"version": "6.0.1", "integrity": "sha512-CCC"},
        # Supply the next part of the expression started above.
        "node_modules/mocha": {"version": "1.0.0", "dev": True},
        # Supply the next part of the expression started above.
        "node_modules/@scope/pkg": {"version": "2.0.0"},
    # Close the current expression or collection.
    },
# Close the current expression or collection.
}


# Define make_repo for detectors tests.
# Inputs include tmp_path.
def make_repo(tmp_path):
    # Store tmp_path / 'repo' in repo.
    repo = tmp_path / "repo"
    # Call (repo / '.github' / 'workflows').mkdir at this point.
    (repo / ".github" / "workflows").mkdir(parents=True)
    # Call (repo / 'ftp').mkdir at this point.
    (repo / "ftp").mkdir()
    # Call (repo / 'package.json').write_text at this point.
    (repo / "package.json").write_text(json.dumps({"dependencies": {"express-jwt": "0.1.3", "ngy-cookie": "^6.0.0"},
                                                   # Provide the mapping fields devDependencies on this line.
                                                   "devDependencies": {"mocha": "1"}}, indent=2))
    # Call (repo / 'package-lock.json').write_text at this point.
    (repo / "package-lock.json").write_text(json.dumps(LOCK))
    # Call (repo / '.npmrc').write_text at this point.
    (repo / ".npmrc").write_text("package-lock=false\n")
    # Call (repo / '.github/workflows/ci.yml').write_text at this point.
    (repo / ".github/workflows/ci.yml").write_text(
        # Supply the next part of the expression started above.
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 #v7\n"
        # Supply the next part of the expression started above.
        "      - uses: coverallsapp/github-action@v2\n      - uses: ./local-action\n")
    # Call (repo / 'Dockerfile').write_text at this point.
    (repo / "Dockerfile").write_text("FROM node:24 AS installer\nRUN x\nFROM installer\n"
                                     # Supply the next part of the expression started above.
                                     "FROM gcr.io/distroless/nodejs24-debian13\nFROM alpine@sha256:abc\nEXPOSE 3000\n")
    # Call (repo / 'ftp/package.json.bak').write_text at this point.
    (repo / "ftp/package.json.bak").write_text(json.dumps({"dependencies": {"express-jwt": "0.0.1", "epilogue-js": "~0.7",
                                                                            # Provide the mapping fields colors on this line.
                                                                            "colors": "~1.1"}}, indent=2))
    # Return repo to the caller.
    return repo


# Define ctx_for for detectors tests.
# Inputs include repo, tmp_path.
def ctx_for(repo, tmp_path):
    # Store tmp_path / 'run' in run_dir.
    run_dir = tmp_path / "run"
    # Call run_dir.mkdir at this point.
    run_dir.mkdir(exist_ok=True)
    # Return the result of ToolContext to the caller.
    return ToolContext(run_id="r", run_dir=run_dir, repo=repo, settings=load_settings(), work_dir=repo)


# Exercise the expected behavior for similarity.
def test_similarity():
    # Check that check_name('ngy-cookie').popular == 'ngx-cookie'.
    assert check_name("ngy-cookie").popular == "ngx-cookie"
    # Check that check_name('epilogue-js').popular == 'epilogue'.
    assert check_name("epilogue-js").popular == "epilogue"
    # Check that the expression on this line.
    assert check_name("ngx-cookie") is None and check_name("express") is None
    # Check that check_name('expresss').popular == 'express'.
    assert check_name("expresss").popular == "express"
    # Check that check_name('z86') is None.
    assert check_name("z86") is None  # too short
    # Check that damerau_levenshtein('ab', 'ba') == 1.
    assert damerau_levenshtein("ab", "ba") == 1


# Exercise the expected behavior for initial risk rule.
def test_initial_risk_rule():
    # Store the result of dict in base.
    base = dict(run_id="r", title="t", detector="d", evidence_ids=["ev"])
    # Check that the expression on this line.
    assert initial_risk(Finding(category=FindingCategory.CVE, cvss=9.8, **base)) is Priority.CRITICAL
    # Check that the expression on this line.
    assert initial_risk(Finding(category=FindingCategory.CVE, cvss=7.5, scope=Scope.DEV, **base)) is Priority.MEDIUM
    # Check that the expression on this line.
    assert initial_risk(Finding(category=FindingCategory.CVE, severity="High", **base)) is Priority.HIGH
    # Check that the expression on this line.
    assert initial_risk(Finding(category=FindingCategory.TYPOSQUAT, **base)) is Priority.HIGH
    # Check that the expression on this line.
    assert initial_risk(Finding(category=FindingCategory.UNPINNED_CI, **base)) is Priority.MEDIUM


# Exercise the expected behavior for graph paths origin integrity scope.
def test_graph_paths_origin_integrity_scope(tmp_path):
    # Store the result of ctx_for in ctx.
    ctx = ctx_for(make_repo(tmp_path), tmp_path)
    # Store build_graph(ctx).artifacts['graph'] in g.
    g = build_graph(ctx).artifacts["graph"]
    # Store the result of g.stats in st.
    st = g.stats()
    # Check that the expression on this line.
    assert st["components"] == 5 and st["direct"] == 3 and st["projects"] == ["root"]
    # Check that the expression on this line.
    assert g.paths_to("pkg:npm/jsonwebtoken@0.1.0") == [["root", "pkg:npm/express-jwt@0.1.3", "pkg:npm/jsonwebtoken@0.1.0"]]
    # Store g.g.nodes['pkg:npm/express-jwt@0.1.3'] in n.
    n = g.g.nodes["pkg:npm/express-jwt@0.1.3"]
    # Check that the expression on this line.
    assert n["origin"].startswith("https://registry.npmjs.org/") and n["integrity"] == "sha512-AAA"
    # Check that g.g.nodes['pkg:npm/mocha@1.0.0']['scope'] == 'dev'.
    assert g.g.nodes["pkg:npm/mocha@1.0.0"]["scope"] == "dev"
    # Check that 'pkg:npm/%40scope/pkg@2.0.0' in g.g.
    assert "pkg:npm/%40scope/pkg@2.0.0" in g.g


# Exercise the expected behavior for detectors find cp1 anomalies.
def test_detectors_find_cp1_anomalies(tmp_path):
    # Store the result of make_repo in repo.
    repo = make_repo(tmp_path)
    # Store the result of ctx_for in ctx.
    ctx = ctx_for(repo, tmp_path)
    # Store build_graph(ctx).artifacts['graph'] in ctx.graph.
    ctx.graph = build_graph(ctx).artifacts["graph"]

    # Store lockfile.detect(ctx).findings in lf.
    lf = lockfile.detect(ctx).findings
    # Check that the expression on this line.
    assert len(lf) == 1 and lf[0].file_path == ".npmrc" and lf[0].line == 1

    # Store typosquat.detect(ctx).findings in ts.
    ts = typosquat.detect(ctx).findings
    # Store a lookup built from the input records in names.
    names = {f.title.split("'")[1]: f for f in ts}
    # Check that set(names) == {'ngy-cookie', 'epilogue-js'}.
    assert set(names) == {"ngy-cookie", "epilogue-js"}
    # Check that the expression on this line.
    assert names["ngy-cookie"].component_purl == "pkg:npm/ngy-cookie@6.0.1" and names["ngy-cookie"].line == 4

    # Store ci_pin.detect(ctx).findings in ci.
    ci = ci_pin.detect(ctx).findings
    # Check that the expression on this line.
    assert [f.title for f in ci] == ["GitHub Action coverallsapp/github-action@v2 not pinned to a commit SHA"]
    # Check that ci[0].line == 5.
    assert ci[0].line == 5

    # Store image_pin.detect(ctx).findings in imgs.
    imgs = image_pin.detect(ctx).findings
    # Check that the expression on this line.
    assert [f.component_purl for f in imgs] == ["node:24", "gcr.io/distroless/nodejs24-debian13"]


# Exercise the expected behavior for mini diff.
def test_mini_diff(tmp_path):
    # Store the result of ctx_for in ctx.
    ctx = ctx_for(make_repo(tmp_path), tmp_path)
    # Store unexpected_change.mini_diff(ctx).artifacts['changes'] in ch.
    ch = unexpected_change.mini_diff(ctx).artifacts["changes"]
    # Check that ch['added'] == ['pkg:npm/mocha@1', 'pkg:npm/ngy-cookie@6.0.0'].
    assert ch["added"] == ["pkg:npm/mocha@1", "pkg:npm/ngy-cookie@6.0.0"]
    # Check that the expression on this line.
    assert ch["removed"] == ["pkg:npm/colors@1.1", "pkg:npm/epilogue-js@0.7"]
    # Check that the expression on this line.
    assert ch["changed"][0]["name"] == "express-jwt" and ch["evidence_ids"]


# Exercise the expected behavior for scanner env is offline safe.
def test_scanner_env_is_offline_safe(monkeypatch):
    # Document the contract for the surrounding module or callable.
    """G7.3: scanners never self-update; offline, Grype never refreshes its vulnerability DB."""
    # Import scanner_env from guardian.tools.binaries.
    from guardian.tools.binaries import scanner_env

    # Store the result of scanner_env in on.
    on = scanner_env({"PATH": "x"})
    # Check that the expression on this line.
    assert on["SYFT_CHECK_FOR_APP_UPDATE"] == on["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
    # Check that 'GRYPE_DB_AUTO_UPDATE' not in on.
    assert "GRYPE_DB_AUTO_UPDATE" not in on
    # Store the result of scanner_env in off.
    off = scanner_env({"PATH": "x", "GUARDIAN_OFFLINE": "1"})
    # Check that the expression on this line.
    assert off["GRYPE_DB_AUTO_UPDATE"] == "false" and off["GRYPE_DB_VALIDATE_AGE"] == "false"


# Exercise the expected behavior for osv scan is cached and offline safe.
def test_osv_scan_is_cached_and_offline_safe(tmp_path, settings, monkeypatch):
    # Document the contract for the surrounding module or callable.
    """G7.3/G7.4: online, OSV-Scanner output is cached by lockfile content; offline, the cache is reused and
    the binary is never started; offline without a cache the cross-check is skipped (Grype stays primary)."""
    # Import replace from dataclasses.
    from dataclasses import replace

    # Load pytest for detectors tests.
    import pytest

    # Import scanners from guardian.tools.
    from guardian.tools import scanners
    # Import ToolContext from guardian.tools.registry.
    from guardian.tools.registry import ToolContext

    # Call monkeypatch.setenv at this point.
    monkeypatch.setenv("GUARDIAN_INTEL_CACHE", str(tmp_path / "intel"))
    # Store tmp_path / 'app' in repo.
    repo = tmp_path / "app"
    # Call repo.mkdir at this point.
    repo.mkdir()
    # Call (repo / 'package.json').write_text at this point.
    (repo / "package.json").write_text('{"name": "app", "dependencies": {"a": "1.0.0"}}', encoding="utf-8")
    # Call (repo / 'package-lock.json').write_text at this point.
    (repo / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}', encoding="utf-8")
    # Store an ordered collection in calls.
    calls = []

    # Define Proc for detectors tests.
    # Group the related fields or methods under this type.
    class Proc:
        # Give stdout its starting value.
        # The initial value is '{"results": []}'.
        stdout = '{"results": []}'

    # Define fake_run for detectors tests.
    # Inputs include args.
    def fake_run(args, **kw):
        # Call calls.append at this point.
        calls.append(args)
        # Return the result of Proc to the caller.
        return Proc()

    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(scanners, "run", fake_run)
    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(scanners, "find", lambda name: name)

    # Define ctx for detectors tests.
    # Inputs include offline.
    def ctx(offline):
        # Store tmp_path / f'run_{offline}' in run_dir.
        run_dir = tmp_path / f"run_{offline}"
        # Call run_dir.mkdir at this point.
        run_dir.mkdir(exist_ok=True)
        # Return the result of ToolContext to the caller.
        return ToolContext(run_id="r", run_dir=run_dir, repo=repo, settings=replace(settings, offline=offline),
                           # Supply work_dir as named arguments to the surrounding call.
                           # These names connect the values to the receiving parameters.
                           work_dir=repo)

    # Call scanners.osv_scan at this point.
    scanners.osv_scan(ctx(False))
    # Check that len(calls) == 1.
    assert len(calls) == 1
    # Call scanners.osv_scan at this point.
    scanners.osv_scan(ctx(True))  # same lockfiles: served from the cache
    # Check that len(calls) == 1.
    assert len(calls) == 1
    # Call (repo / 'package-lock.json').write_text at this point.
    (repo / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {"x": {}}}', encoding="utf-8")
    # Enter the context managed by pytest.raises(RuntimeError, match='offline').
    with pytest.raises(RuntimeError, match="offline"):
        # Call scanners.osv_scan at this point.
        scanners.osv_scan(ctx(True))  # changed lockfile, no cache, offline: skipped, binary not started
    # Check that len(calls) == 1.
    assert len(calls) == 1


# Exercise the expected behavior for sbom only ecosystems get package nodes and empty graphs get a root.
def test_sbom_only_ecosystems_get_package_nodes_and_empty_graphs_get_a_root(tmp_path):
    # Document the contract for the surrounding module or callable.
    """Maven (and other ecosystems without a lockfile graph here) come from the SBOM; GitHub Actions purls are
    CI pseudo-nodes, not packages. A target with no packages still gets a root so graph.json is written."""
    # Load json for detectors tests.
    import json
    # Import SimpleNamespace from types.
    from types import SimpleNamespace

    # Import build_graph from guardian.core.graph_build.
    from guardian.core.graph_build import build_graph
    # Import build_graph_json from guardian.graph.workflow.
    from guardian.graph.workflow import build_graph_json

    # Store tmp_path / 'sbom.cdx.json' in sbom.
    sbom = tmp_path / "sbom.cdx.json"
    # Call sbom.write_text at this point.
    sbom.write_text(json.dumps({"components": [
        # Supply the next part of the expression started above.
        {"name": "xstream", "version": "1.4.5", "purl": "pkg:maven/com.thoughtworks.xstream/xstream@1.4.5"},
        # Supply the next part of the expression started above.
        {"name": "checkout", "version": "v4", "purl": "pkg:github/actions/checkout@v4"}]}), encoding="utf-8")
    # Store the result of SimpleNamespace in ctx.
    ctx = SimpleNamespace(work_dir=tmp_path, repo=tmp_path, sbom_path=sbom, run_id="r", artifacts={}, graph=None)
    # Store build_graph(ctx).artifacts['graph'] in g.
    g = build_graph(ctx).artifacts["graph"]
    # Check that the expression on this line.
    assert g.packages() == ["pkg:maven/com.thoughtworks.xstream/xstream@1.4.5"]
    # Store the result of SimpleNamespace in empty.
    empty = SimpleNamespace(graph=None, artifacts={"graph_json": {"nodes": [], "edges": [], "roots": []}})
    # Store the result of build_graph_json in data.
    data = build_graph_json(empty, [])
    # Check that the expression on this line.
    assert data["roots"] == ["root"] and any(n["id"] == "root" for n in data["nodes"])


# Exercise the expected behavior for established lookalikes are not typosquats but young ones are.
def test_established_lookalikes_are_not_typosquats_but_young_ones_are():
    # Document the contract for the surrounding module or callable.
    """query-string (13 years, 93 releases) looks like querystring but is not a typosquat; ngy-cookie (2 releases)
    and epilogue-js (9 years but 2 releases) stay flagged; no registry data keeps the flag."""
    # Import established from guardian.tools.detectors.typosquat.
    from guardian.tools.detectors.typosquat import established

    # Define meta for detectors tests.
    # Inputs include created, n.
    def meta(created, n):
        # Return a mapping keyed by the fields below to the caller.
        return {"time": {"created": created}, "version_list": [f"1.{i}.0" for i in range(n)]}

    # Check that the expression on this line.
    assert established(meta("2013-11-13T00:00:00Z", 93)) == {"age_years": established(meta("2013-11-13T00:00:00Z", 93))["age_years"], "stable_releases": 93}
    # Check that established(meta('2024-02-26T00:00:00Z', 2)) is None.
    assert established(meta("2024-02-26T00:00:00Z", 2)) is None
    # Check that established(meta('2017-08-15T00:00:00Z', 2)) is None.
    assert established(meta("2017-08-15T00:00:00Z", 2)) is None
    # Check that established(None) is None.
    assert established(None) is None


# Exercise the expected behavior for maven reachability uses java imports and never guesses.
def test_maven_reachability_uses_java_imports_and_never_guesses(tmp_path):
    # Document the contract for the surrounding module or callable.
    """A Maven package is found by its groupId in Java imports (production code only); an ecosystem without a
    scanner is 'unknown', never 'not imported' (which once turned a used xstream into a mitigate plan)."""
    # Import reachability from guardian.tools.
    from guardian.tools import reachability as r

    # Call r._INDEX.clear at this point.
    r._INDEX.clear()
    # Store tmp_path / 'src' / 'main' / 'java' / 'app' in src.
    src = tmp_path / "src" / "main" / "java" / "app"
    # Call src.mkdir at this point.
    src.mkdir(parents=True)
    # Call (src / 'Lesson.java').write_text at this point.
    (src / "Lesson.java").write_text("package app;\nimport com.thoughtworks.xstream.XStream;\n", encoding="utf-8")
    # Store tmp_path / 'src' / 'it' / 'java' in it.
    it = tmp_path / "src" / "it" / "java"
    # Call it.mkdir at this point.
    it.mkdir(parents=True)
    # Call (it / 'FlowIT.java').write_text at this point.
    (it / "FlowIT.java").write_text("import org.apache.commons.lang3.StringUtils;\n", encoding="utf-8")
    # Store the result of r.reachability_import in hit.
    hit = r.reachability_import(tmp_path, "com.thoughtworks.xstream/xstream", "maven")
    # Check that hit.tier == 'imported' and hit.hits[0]['line'] == 2.
    assert hit.tier == "imported" and hit.hits[0]["line"] == 2
    # Check that the expression on this line.
    assert r.reachability_import(tmp_path, "org.apache.commons/commons-lang3", "maven").tier == "not_imported"
    # Check that the expression on this line.
    assert r.reachability_import(tmp_path, "github.com/x/y", "golang").tier == "unknown"


# Exercise the expected behavior for osv purls match grype for every ecosystem.
def test_osv_purls_match_grype_for_every_ecosystem(tmp_path, settings, monkeypatch):
    # Document the contract for the surrounding module or callable.
    """OSV names Maven packages group:artifact; an npm-style purl kept them from merging with Grype's findings
    (WebGoat: 36 duplicate advisories) and made a used Java package look like an unimported npm one."""
    # Load json for detectors tests.
    import json as _json
    # Import replace from dataclasses.
    from dataclasses import replace

    # Import scanners from guardian.tools.
    from guardian.tools import scanners
    # Import ToolContext from guardian.tools.registry.
    from guardian.tools.registry import ToolContext

    # Call monkeypatch.setenv at this point.
    monkeypatch.setenv("GUARDIAN_INTEL_CACHE", str(tmp_path / "intel"))
    # Store tmp_path / 'app' in repo.
    repo = tmp_path / "app"
    # Call repo.mkdir at this point.
    repo.mkdir()
    # Call (repo / 'pom.xml').write_text at this point.
    (repo / "pom.xml").write_text("<project/>", encoding="utf-8")
    # Store an ordered collection in pkgs.
    pkgs = [("Maven", "com.thoughtworks.xstream:xstream", "1.4.5"), ("PyPI", "Django", "3.2.18"),
            # Supply the next part of the expression started above.
            ("npm", "lodash", "4.17.20"), ("Go", "github.com/x/y", "v1.0.0")]
    # Store a mapping keyed by the fields below in out.
    out = {"results": [{"packages": [{"package": {"name": n, "version": v, "ecosystem": e},
                                      # Provide the mapping fields vulnerabilities, groups on this line.
                                      "vulnerabilities": [{"id": f"GHSA-{i}"}], "groups": []}
                                     # Use this clause to iterate or filter the surrounding expression.
                                     # The collection includes the results of the completed expression.
                                     for i, (e, n, v) in enumerate(pkgs)]}]}

    # Define Proc for detectors tests.
    # Group the related fields or methods under this type.
    class Proc:
        # Store the result of _json.dumps in stdout.
        stdout = _json.dumps(out)

    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(scanners, "run", lambda args, **kw: Proc())
    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(scanners, "find", lambda name: name)
    # Store tmp_path / 'run' in run_dir.
    run_dir = tmp_path / "run"
    # Call run_dir.mkdir at this point.
    run_dir.mkdir()
    # Store the result of ToolContext in ctx.
    ctx = ToolContext(run_id="r", run_dir=run_dir, repo=repo, settings=replace(settings, offline=False), work_dir=repo)
    # Store the result of sorted in purls.
    purls = sorted(f.component_purl for f in scanners.osv_scan(ctx).findings)
    # Check that the expression on this line.
    assert purls == ["pkg:go/github.com/x/y@v1.0.0", "pkg:maven/com.thoughtworks.xstream/xstream@1.4.5",
                     # Supply the next part of the expression started above.
                     "pkg:npm/lodash@4.17.20", "pkg:pypi/django@3.2.18"]
