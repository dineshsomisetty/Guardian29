import json
from types import SimpleNamespace

from guardian.adapters.pypi import normalize, parse_requirements, runtime_dependencies
from guardian.core.graph_build import DependencyGraph, build_pypi_graph, paths_to
from guardian.tools.detectors import lockfile

REQS = """# app
Django==4.2
requests==2.28.2
idna==3.4
urllib3==1.26.9  # pinned
crispy-bootstrap4==2022.1
PyYAML>=5.1
-r other.txt
"""
META = {
    "django": {"requires_dist": ["asgiref (<4,>=3.6.0)", "sqlparse (>=0.3.1)",
                                 "tzdata ; sys_platform == \"win32\"", "argon2-cffi (>=19.1.0) ; extra == 'argon2'"]},
    "requests": {"requires_dist": ["idna (<4,>=2.5)", "urllib3 (<1.27,>=1.21.1)", "charset-normalizer (<4,>=2)",
                                   "PySocks (!=1.5.7) ; extra == 'socks'"]},
    "crispy-bootstrap4": {"requires_dist": ["django (>=3.2)"]},
}


def comp(name, ver, path="/requirements.txt"):
    return {"type": "library", "name": name, "version": ver, "purl": f"pkg:pypi/{normalize(name)}@{ver}",
            "properties": [{"name": "syft:location:0:path", "value": path}]}


def setup(tmp_path):
    (tmp_path / "requirements.txt").write_text(REQS)
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(json.dumps({"components": [
        comp("Django", "4.2"), comp("requests", "2.28.2"), comp("idna", "3.4"), comp("urllib3", "1.26.9"),
        comp("crispy-bootstrap4", "2022.1"), comp("PyYAML", "5.1"), comp("flask", "1.0", "/labs/x/requirements.txt")]}))
    return sbom


def test_parse_requirements_lines_pins_and_skips():
    import pathlib
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "requirements.txt"
        p.write_text(REQS)
        r = {x.name: x for x in parse_requirements(p)}
    assert set(r) == {"django", "requests", "idna", "urllib3", "crispy-bootstrap4", "pyyaml"}
    assert r["django"].pinned_version == "4.2" and r["django"].line == 2
    assert r["pyyaml"].pinned_version is None and not r["django"].has_hash


def test_runtime_dependencies_drops_extras_and_other_platforms():
    assert runtime_dependencies(META["django"]) == ["asgiref", "sqlparse"]


def test_pypi_graph_edges_direct_and_unpinned(tmp_path):
    G = build_pypi_graph(tmp_path, setup(tmp_path), fetch=lambda n, v: META.get(n, {}))
    assert "pkg:pypi/flask@1.0" not in G  # other requirement files (labs) are out of scope
    assert not G.nodes["pkg:pypi/django@4.2"]["direct"]  # required by crispy-bootstrap4
    assert G.nodes["pkg:pypi/crispy-bootstrap4@2022.1"]["direct"] and G.nodes["pkg:pypi/requests@2.28.2"]["direct"]
    assert paths_to(G, "pkg:pypi/django@4.2") == [["root", "pkg:pypi/crispy-bootstrap4@2022.1", "pkg:pypi/django@4.2"]]
    assert G.graph["unpinned_requirements"] == ["asgiref", "charset-normalizer", "sqlparse"]
    assert G.nodes["pkg:pypi/idna@3.4"]["origin"] == "https://pypi.org/project/idna/3.4/"


def test_lockfile_detector_for_pip(tmp_path):
    G = build_pypi_graph(tmp_path, setup(tmp_path), fetch=lambda n, v: META.get(n, {}))
    out = lockfile.detect(SimpleNamespace(run_id="r", repo=tmp_path, work_dir=tmp_path, graph=DependencyGraph(G)))
    (fd,) = out.findings
    assert fd.category.value == "lockfile" and fd.file_path == "requirements.txt" and fd.line == 7
    facts = out.evidence[-1].facts
    assert facts["loose_specs"] == ["pyyaml"] and facts["without_hash"] == 6
    assert facts["runtime_deps_not_pinned"] == ["asgiref", "charset-normalizer", "sqlparse"]
