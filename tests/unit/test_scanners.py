import json
from pathlib import Path

import networkx as nx

from guardian.core.models import new_id
from guardian.tools.scanners import parse_grype, to_models

FX = Path(__file__).resolve().parents[1] / "fixtures" / "juice-shop" / "grype_sample.json"


def graph_for(doc):
    G = nx.DiGraph(roots=["root"])
    G.add_node("root", kind="project")
    prev = "root"
    for m in doc["matches"]:
        p = m["artifact"]["purl"].split("?")[0]
        G.add_node(p, kind="package", scope="prod", project="root")
        G.add_edge("root", "pkg:npm/parent@1.0.0")
        G.add_edge("pkg:npm/parent@1.0.0", p)
    G.add_node("pkg:npm/parent@1.0.0", kind="package", scope="prod", project="root")
    return G


def test_parse_basic_fields_and_dedupe():
    doc = json.loads(FX.read_text())
    F, E = parse_grype(doc, graph_for(doc), "run_x")
    assert len(F) == len(E) == 3  # duplicate match merged
    jwt = next(f for f in F if "jsonwebtoken" in f["component_purl"])
    assert jwt["cvss"] == 9.8 and jwt["severity"] == "critical"
    assert jwt["vuln_id"].startswith("GHSA-") and "CVE-2015-9235" in jwt["aliases"]
    assert jwt["fixed_versions"] == ["4.2.2"] and jwt["affected_range"] == "<4.2.2 (semantic)"
    assert jwt["dependency_paths"][0][0] == "root" and jwt["dependency_paths"][0][-1] == jwt["component_purl"]


def test_every_finding_has_matching_evidence():
    doc = json.loads(FX.read_text())
    F, E = parse_grype(doc, graph_for(doc), "run_x")
    ev = {e["evidence_id"]: e for e in E}
    for f in F:
        assert f["evidence_ids"] and all(i in ev for i in f["evidence_ids"])
        e = ev[f["evidence_ids"][0]]
        assert e["facts"]["vuln_id"] == f["vuln_id"] and e["kind"] == "scanner_output"
        assert e["source_tool"].startswith("grype@")


def test_unfixed_has_no_fixed_versions_and_unknown_graph_ok():
    doc = json.loads(FX.read_text())
    F, _ = parse_grype(doc, None, "run_x")  # no graph: still produces findings, empty paths
    assert any(f["fixed_versions"] == [] for f in F) and all(f["dependency_paths"] == [] for f in F)


def test_new_id_format_and_unique():
    a, b = new_id("ev"), new_id("ev")
    assert a.startswith("ev_") and len(a) == 3 + 26 and a != b


def test_converts_to_pydantic_models():
    doc = json.loads(FX.read_text())
    F, E = parse_grype(doc, graph_for(doc), "run_x")
    fds, evs = to_models(F, E)
    assert fds[0].category.value == "cve" and fds[0].evidence_ids == [evs[0].evidence_id]
