import json
from pathlib import Path

from guardian.core.graph_build import add_findings, build_dependency_graph as build_graph, export_graph, paths_to

LOCK = {"packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"express": "^4", "@s/lib": "^1"},
         "devDependencies": {"mocha": "^1"}},
    "node_modules/express": {"version": "4.0.0", "resolved": "https://registry.npmjs.org/express/-/express-4.0.0.tgz",
                             "integrity": "sha512-E", "dependencies": {"qs": "^6"}},
    "node_modules/qs": {"version": "6.0.0", "resolved": "https://registry.npmjs.org/qs/-/qs-6.0.0.tgz",
                        "integrity": "sha512-Q"},
    "node_modules/@s/lib": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/@s/lib/-/lib-1.0.0.tgz",
                            "integrity": "sha512-L"},
    "node_modules/mocha": {"version": "1.0.0", "dev": True, "resolved": "https://x/mocha.tgz", "integrity": "sha512-M"},
}}


def comp(name, ver, path="/package-lock.json"):
    enc = name.replace("@", "%40", 1)
    purl = f"pkg:npm/{enc}@{ver}"
    return {"bom-ref": purl + "?package-id=zz", "type": "library", "name": name, "version": ver, "purl": purl,
            "properties": [{"name": "syft:location:0:path", "value": path}]}


def setup(tmp: Path, with_sbom_edges: bool):
    (tmp / "package-lock.json").write_text(json.dumps(LOCK))
    comps = [comp("app", "1.0.0"), comp("express", "4.0.0"), comp("qs", "6.0.0"), comp("@s/lib", "1.0.0"),
             comp("mocha", "1.0.0")]
    deps = [{"ref": comps[1]["bom-ref"], "dependsOn": [comps[2]["bom-ref"]]}] if with_sbom_edges else []
    sbom = tmp / "sbom.cdx.json"
    sbom.write_text(json.dumps({"components": comps, "dependencies": deps}))
    return sbom


def test_direct_scope_origin_integrity(tmp_path):
    G = build_graph(tmp_path, setup(tmp_path, True), projects={"root": "."})
    assert "pkg:npm/app@1.0.0" not in G  # the app itself is not a dependency
    ex = G.nodes["pkg:npm/express@4.0.0"]
    assert ex["direct"] and ex["scope"] == "prod" and ex["integrity"] == "sha512-E"
    assert ex["origin"].endswith("express-4.0.0.tgz")
    assert not G.nodes["pkg:npm/qs@6.0.0"]["direct"]
    assert G.nodes["pkg:npm/mocha@1.0.0"]["scope"] == "dev"
    assert "pkg:npm/%40s/lib@1.0.0" in G


def test_path_to_transitive(tmp_path):
    G = build_graph(tmp_path, setup(tmp_path, True), projects={"root": "."})
    assert paths_to(G, "pkg:npm/qs@6.0.0") == [["root", "pkg:npm/express@4.0.0", "pkg:npm/qs@6.0.0"]]
    assert paths_to(G, "pkg:npm/nope@1.0.0") == []


def test_lockfile_fallback_when_sbom_has_no_edges(tmp_path):
    G = build_graph(tmp_path, setup(tmp_path, False), projects={"root": "."})
    assert G.graph["edge_source"]["root"] == "package-lock.json"
    assert paths_to(G, "pkg:npm/qs@6.0.0")


def test_findings_and_pseudo_nodes_export(tmp_path):
    G = build_graph(tmp_path, setup(tmp_path, True), projects={"root": "."})
    add_findings(G, [
        {"finding_id": "fd_1", "category": "cve", "component_purl": "pkg:npm/qs@6.0.0", "initial_risk": "high"},
        {"finding_id": "fd_2", "category": "cve", "component_purl": "pkg:npm/qs@6.0.0", "initial_risk": "critical"},
        {"finding_id": "fd_3", "category": "unpinned_ci", "file_path": ".github/workflows/ci.yml",
         "initial_risk": "medium"},
        {"finding_id": "fd_4", "category": "lockfile", "file_path": ".npmrc", "initial_risk": "medium"},
    ])
    assert G.nodes["pkg:npm/qs@6.0.0"]["risk"] == "critical"
    out = tmp_path / "graph.json"
    facts = export_graph(G, out)
    data = json.loads(out.read_text())
    kinds = {n["kind"] for n in data["nodes"]}
    assert {"package", "project", "ci", "config"} <= kinds
    assert data["roots"] == ["root"] and facts["direct"] == 3
    assert {"source": "root", "target": "ci:.github/workflows/ci.yml", "type": "uses"} in data["edges"]
