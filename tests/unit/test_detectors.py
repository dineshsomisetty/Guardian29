"""Dev2/Dev4 CP1 tool tests on small synthetic projects (no scanners, no network)."""

import json

from guardian.core.config import load_settings
from guardian.core.graph_build import build_graph
from guardian.core.models import Finding, FindingCategory, Priority, Scope
from guardian.core.scoring import initial_risk
from guardian.tools.detectors import ci_pin, image_pin, lockfile, typosquat, unexpected_change
from guardian.tools.detectors.similarity import check_name, damerau_levenshtein
from guardian.tools.registry import ToolContext

LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"express-jwt": "0.1.3", "ngy-cookie": "^6.0.0"}, "devDependencies": {"mocha": "1"}},
        "node_modules/express-jwt": {"version": "0.1.3", "resolved": "https://registry.npmjs.org/express-jwt/-/express-jwt-0.1.3.tgz",
                                     "integrity": "sha512-AAA", "dependencies": {"jsonwebtoken": "~0.1.0"}},
        "node_modules/express-jwt/node_modules/jsonwebtoken": {"version": "0.1.0", "integrity": "sha512-BBB"},
        "node_modules/ngy-cookie": {"version": "6.0.1", "integrity": "sha512-CCC"},
        "node_modules/mocha": {"version": "1.0.0", "dev": True},
        "node_modules/@scope/pkg": {"version": "2.0.0"},
    },
}


def make_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "ftp").mkdir()
    (repo / "package.json").write_text(json.dumps({"dependencies": {"express-jwt": "0.1.3", "ngy-cookie": "^6.0.0"},
                                                   "devDependencies": {"mocha": "1"}}, indent=2))
    (repo / "package-lock.json").write_text(json.dumps(LOCK))
    (repo / ".npmrc").write_text("package-lock=false\n")
    (repo / ".github/workflows/ci.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 #v7\n"
        "      - uses: coverallsapp/github-action@v2\n      - uses: ./local-action\n")
    (repo / "Dockerfile").write_text("FROM node:24 AS installer\nRUN x\nFROM installer\n"
                                     "FROM gcr.io/distroless/nodejs24-debian13\nFROM alpine@sha256:abc\nEXPOSE 3000\n")
    (repo / "ftp/package.json.bak").write_text(json.dumps({"dependencies": {"express-jwt": "0.0.1", "epilogue-js": "~0.7",
                                                                            "colors": "~1.1"}}, indent=2))
    return repo


def ctx_for(repo, tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    return ToolContext(run_id="r", run_dir=run_dir, repo=repo, settings=load_settings(), work_dir=repo)


def test_similarity():
    assert check_name("ngy-cookie").popular == "ngx-cookie"
    assert check_name("epilogue-js").popular == "epilogue"
    assert check_name("ngx-cookie") is None and check_name("express") is None
    assert check_name("expresss").popular == "express"
    assert check_name("z86") is None  # too short
    assert damerau_levenshtein("ab", "ba") == 1


def test_initial_risk_rule():
    base = dict(run_id="r", title="t", detector="d", evidence_ids=["ev"])
    assert initial_risk(Finding(category=FindingCategory.CVE, cvss=9.8, **base)) is Priority.CRITICAL
    assert initial_risk(Finding(category=FindingCategory.CVE, cvss=7.5, scope=Scope.DEV, **base)) is Priority.MEDIUM
    assert initial_risk(Finding(category=FindingCategory.CVE, severity="High", **base)) is Priority.HIGH
    assert initial_risk(Finding(category=FindingCategory.TYPOSQUAT, **base)) is Priority.HIGH
    assert initial_risk(Finding(category=FindingCategory.UNPINNED_CI, **base)) is Priority.MEDIUM


def test_graph_paths_origin_integrity_scope(tmp_path):
    ctx = ctx_for(make_repo(tmp_path), tmp_path)
    g = build_graph(ctx).artifacts["graph"]
    st = g.stats()
    assert st["components"] == 5 and st["direct"] == 3 and st["projects"] == ["root"]
    assert g.paths_to("pkg:npm/jsonwebtoken@0.1.0") == [["root", "pkg:npm/express-jwt@0.1.3", "pkg:npm/jsonwebtoken@0.1.0"]]
    n = g.g.nodes["pkg:npm/express-jwt@0.1.3"]
    assert n["origin"].startswith("https://registry.npmjs.org/") and n["integrity"] == "sha512-AAA"
    assert g.g.nodes["pkg:npm/mocha@1.0.0"]["scope"] == "dev"
    assert "pkg:npm/%40scope/pkg@2.0.0" in g.g


def test_detectors_find_cp1_anomalies(tmp_path):
    repo = make_repo(tmp_path)
    ctx = ctx_for(repo, tmp_path)
    ctx.graph = build_graph(ctx).artifacts["graph"]

    lf = lockfile.detect(ctx).findings
    assert len(lf) == 1 and lf[0].file_path == ".npmrc" and lf[0].line == 1

    ts = typosquat.detect(ctx).findings
    names = {f.title.split("'")[1]: f for f in ts}
    assert set(names) == {"ngy-cookie", "epilogue-js"}
    assert names["ngy-cookie"].component_purl == "pkg:npm/ngy-cookie@6.0.1" and names["ngy-cookie"].line == 4

    ci = ci_pin.detect(ctx).findings
    assert [f.title for f in ci] == ["GitHub Action coverallsapp/github-action@v2 not pinned to a commit SHA"]
    assert ci[0].line == 5

    imgs = image_pin.detect(ctx).findings
    assert [f.component_purl for f in imgs] == ["node:24", "gcr.io/distroless/nodejs24-debian13"]


def test_mini_diff(tmp_path):
    ctx = ctx_for(make_repo(tmp_path), tmp_path)
    ch = unexpected_change.mini_diff(ctx).artifacts["changes"]
    assert ch["added"] == ["pkg:npm/mocha@1", "pkg:npm/ngy-cookie@6.0.0"]
    assert ch["removed"] == ["pkg:npm/colors@1.1", "pkg:npm/epilogue-js@0.7"]
    assert ch["changed"][0]["name"] == "express-jwt" and ch["evidence_ids"]


def test_scanner_env_is_offline_safe(monkeypatch):
    """G7.3: scanners never self-update; offline, Grype never refreshes its vulnerability DB."""
    from guardian.tools.binaries import scanner_env

    on = scanner_env({"PATH": "x"})
    assert on["SYFT_CHECK_FOR_APP_UPDATE"] == on["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
    assert "GRYPE_DB_AUTO_UPDATE" not in on
    off = scanner_env({"PATH": "x", "GUARDIAN_OFFLINE": "1"})
    assert off["GRYPE_DB_AUTO_UPDATE"] == "false" and off["GRYPE_DB_VALIDATE_AGE"] == "false"


def test_osv_scan_is_cached_and_offline_safe(tmp_path, settings, monkeypatch):
    """G7.3/G7.4: online, OSV-Scanner output is cached by lockfile content; offline, the cache is reused and
    the binary is never started; offline without a cache the cross-check is skipped (Grype stays primary)."""
    from dataclasses import replace

    import pytest

    from guardian.tools import scanners
    from guardian.tools.registry import ToolContext

    monkeypatch.setenv("GUARDIAN_INTEL_CACHE", str(tmp_path / "intel"))
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "package.json").write_text('{"name": "app", "dependencies": {"a": "1.0.0"}}', encoding="utf-8")
    (repo / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}', encoding="utf-8")
    calls = []

    class Proc:
        stdout = '{"results": []}'

    def fake_run(args, **kw):
        calls.append(args)
        return Proc()

    monkeypatch.setattr(scanners, "run", fake_run)
    monkeypatch.setattr(scanners, "find", lambda name: name)

    def ctx(offline):
        run_dir = tmp_path / f"run_{offline}"
        run_dir.mkdir(exist_ok=True)
        return ToolContext(run_id="r", run_dir=run_dir, repo=repo, settings=replace(settings, offline=offline),
                           work_dir=repo)

    scanners.osv_scan(ctx(False))
    assert len(calls) == 1
    scanners.osv_scan(ctx(True))  # same lockfiles: served from the cache
    assert len(calls) == 1
    (repo / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {"x": {}}}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="offline"):
        scanners.osv_scan(ctx(True))  # changed lockfile, no cache, offline: skipped, binary not started
    assert len(calls) == 1


def test_sbom_only_ecosystems_get_package_nodes_and_empty_graphs_get_a_root(tmp_path):
    """Maven (and other ecosystems without a lockfile graph here) come from the SBOM; GitHub Actions purls are
    CI pseudo-nodes, not packages. A target with no packages still gets a root so graph.json is written."""
    import json
    from types import SimpleNamespace

    from guardian.core.graph_build import build_graph
    from guardian.graph.workflow import build_graph_json

    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps({"components": [
        {"name": "xstream", "version": "1.4.5", "purl": "pkg:maven/com.thoughtworks.xstream/xstream@1.4.5"},
        {"name": "checkout", "version": "v4", "purl": "pkg:github/actions/checkout@v4"}]}), encoding="utf-8")
    ctx = SimpleNamespace(work_dir=tmp_path, repo=tmp_path, sbom_path=sbom, run_id="r", artifacts={}, graph=None)
    g = build_graph(ctx).artifacts["graph"]
    assert g.packages() == ["pkg:maven/com.thoughtworks.xstream/xstream@1.4.5"]
    empty = SimpleNamespace(graph=None, artifacts={"graph_json": {"nodes": [], "edges": [], "roots": []}})
    data = build_graph_json(empty, [])
    assert data["roots"] == ["root"] and any(n["id"] == "root" for n in data["nodes"])


def test_established_lookalikes_are_not_typosquats_but_young_ones_are():
    """query-string (13 years, 93 releases) looks like querystring but is not a typosquat; ngy-cookie (2 releases)
    and epilogue-js (9 years but 2 releases) stay flagged; no registry data keeps the flag."""
    from guardian.tools.detectors.typosquat import established

    def meta(created, n):
        return {"time": {"created": created}, "version_list": [f"1.{i}.0" for i in range(n)]}

    assert established(meta("2013-11-13T00:00:00Z", 93)) == {"age_years": established(meta("2013-11-13T00:00:00Z", 93))["age_years"], "stable_releases": 93}
    assert established(meta("2024-02-26T00:00:00Z", 2)) is None
    assert established(meta("2017-08-15T00:00:00Z", 2)) is None
    assert established(None) is None


def test_maven_reachability_uses_java_imports_and_never_guesses(tmp_path):
    """A Maven package is found by its groupId in Java imports (production code only); an ecosystem without a
    scanner is 'unknown', never 'not imported' (which once turned a used xstream into a mitigate plan)."""
    from guardian.tools import reachability as r

    r._INDEX.clear()
    src = tmp_path / "src" / "main" / "java" / "app"
    src.mkdir(parents=True)
    (src / "Lesson.java").write_text("package app;\nimport com.thoughtworks.xstream.XStream;\n", encoding="utf-8")
    it = tmp_path / "src" / "it" / "java"
    it.mkdir(parents=True)
    (it / "FlowIT.java").write_text("import org.apache.commons.lang3.StringUtils;\n", encoding="utf-8")
    hit = r.reachability_import(tmp_path, "com.thoughtworks.xstream/xstream", "maven")
    assert hit.tier == "imported" and hit.hits[0]["line"] == 2
    assert r.reachability_import(tmp_path, "org.apache.commons/commons-lang3", "maven").tier == "not_imported"
    assert r.reachability_import(tmp_path, "github.com/x/y", "golang").tier == "unknown"


def test_osv_purls_match_grype_for_every_ecosystem(tmp_path, settings, monkeypatch):
    """OSV names Maven packages group:artifact; an npm-style purl kept them from merging with Grype's findings
    (WebGoat: 36 duplicate advisories) and made a used Java package look like an unimported npm one."""
    import json as _json
    from dataclasses import replace

    from guardian.tools import scanners
    from guardian.tools.registry import ToolContext

    monkeypatch.setenv("GUARDIAN_INTEL_CACHE", str(tmp_path / "intel"))
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "pom.xml").write_text("<project/>", encoding="utf-8")
    pkgs = [("Maven", "com.thoughtworks.xstream:xstream", "1.4.5"), ("PyPI", "Django", "3.2.18"),
            ("npm", "lodash", "4.17.20"), ("Go", "github.com/x/y", "v1.0.0")]
    out = {"results": [{"packages": [{"package": {"name": n, "version": v, "ecosystem": e},
                                      "vulnerabilities": [{"id": f"GHSA-{i}"}], "groups": []}
                                     for i, (e, n, v) in enumerate(pkgs)]}]}

    class Proc:
        stdout = _json.dumps(out)

    monkeypatch.setattr(scanners, "run", lambda args, **kw: Proc())
    monkeypatch.setattr(scanners, "find", lambda name: name)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = ToolContext(run_id="r", run_dir=run_dir, repo=repo, settings=replace(settings, offline=False), work_dir=repo)
    purls = sorted(f.component_purl for f in scanners.osv_scan(ctx).findings)
    assert purls == ["pkg:go/github.com/x/y@v1.0.0", "pkg:maven/com.thoughtworks.xstream/xstream@1.4.5",
                     "pkg:npm/lodash@4.17.20", "pkg:pypi/django@3.2.18"]
