"""D5-02: check the newest real Juice Shop run in runs/ against tests/golden/juice_shop_expected.yaml.

Skipped when there is no run (fresh clone / CI without targets). Run explicitly:
    uv run pytest tests/integration/test_golden.py -q
Override the run with GUARDIAN_GOLDEN_RUN=runs/<run_id>.
Reads only run output files (never runs/<id>/work/ or targets/).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
GOLDEN = REPO / "tests" / "golden" / "juice_shop_expected.yaml"


def _run_dir() -> Path | None:
    override = os.environ.get("GUARDIAN_GOLDEN_RUN")
    if override:
        p = Path(override)
        return p if p.is_absolute() else REPO / p
    # newest finished run *for the golden target*: runs/LATEST may point at another target (e.g. pygoat)
    target = yaml.safe_load(GOLDEN.read_text(encoding="utf-8"))["target"]
    best: tuple[str, Path] | None = None
    for d in (REPO / "runs").glob("run_*"):
        try:
            s = json.loads((d / "run_summary.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if s.get("target") == target and s.get("status") in ("done", "awaiting_human") and s.get("finished_at"):
            if best is None or s["finished_at"] > best[0]:
                best = (s["finished_at"], d)
    return best[1] if best else None


@pytest.fixture(scope="module")
def golden() -> dict:
    return yaml.safe_load(GOLDEN.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def run(golden) -> dict:
    run_dir = _run_dir()
    if run_dir is None:
        pytest.skip("no finished juice-shop run in runs/ (run `uv run python -m guardian run --repo targets/juice-shop`)")
    if not (run_dir / "run_summary.json").is_file():
        pytest.skip(f"run folder {run_dir} has no run_summary.json (run not finished?)")

    def load(name):
        return json.loads((run_dir / name).read_text(encoding="utf-8"))

    summary = load("run_summary.json")
    if summary.get("target") != golden["target"]:
        pytest.skip(f"latest run is for {summary.get('target')!r}, golden file is for {golden['target']!r}")
    trace = [json.loads(line) for line in (run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()
             if line.strip()]
    return {"dir": run_dir, "summary": summary, "findings": load("findings.json"), "graph": load("graph.json"),
            "changes": load("changes.json"), "trace": trace}


def _text(f: dict) -> str:
    return " ".join(str(f.get(k) or "") for k in ("title", "component_purl", "vuln_id", "file_path"))


def _matches(f: dict, exp: dict) -> bool:
    if f.get("category") != exp["category"]:
        return False
    if "component_purl" in exp and f.get("component_purl") != exp["component_purl"]:
        return False
    if "component_purl_prefix" in exp and not (f.get("component_purl") or "").startswith(exp["component_purl_prefix"]):
        return False
    if "file_path" in exp and (f.get("file_path") or "").replace("\\", "/") != exp["file_path"]:
        return False
    if "line" in exp and f.get("line") != exp["line"]:
        return False
    if "text_contains" in exp and exp["text_contains"] not in _text(f):
        return False
    if "path_contains" in exp and not any(exp["path_contains"] in p for p in f.get("dependency_paths") or []):
        return False
    return all(f.get(k) for k in exp.get("require", []))


# ---- run_summary.json --------------------------------------------------------------------------------------

def test_summary(run, golden):
    s, exp = run["summary"], golden["summary"]
    allowed = exp["status"] if isinstance(exp["status"], list) else [exp["status"]]
    assert s["status"] in allowed
    assert str(s.get("commit", "")).startswith(golden["commit_prefix"]), f"run commit {s.get('commit')}"
    n = s["sbom"]["components"]
    assert exp["components"]["min"] <= n <= exp["components"]["max"], f"component count {n} out of range"
    assert s["sbom"]["direct"] >= exp["direct"]["min"], f"direct deps {s['sbom']['direct']}"
    assert set(exp["projects"]) <= set(s["projects"]), f"projects {s['projects']}"


# ---- findings.json ------------------------------------------------------------------------------------------

def _finding_params():
    data = yaml.safe_load(GOLDEN.read_text(encoding="utf-8"))
    return [pytest.param(e, id=e["name"]) for e in data["findings"]]


@pytest.mark.parametrize("exp", _finding_params())
def test_expected_finding(run, exp):
    hits = [f for f in run["findings"] if _matches(f, exp)]
    assert hits, f"P0 MISS: no finding matches {exp}"
    assert all(f.get("evidence_ids") for f in hits), f"matching finding without evidence: {exp['name']}"
    assert all(f.get("initial_risk") for f in hits), f"matching finding without initial risk: {exp['name']}"


def test_every_finding_cites_existing_evidence(run):
    ev_dir = run["dir"] / "evidence"
    missing, uncited = [], []
    for f in run["findings"]:
        ids = f.get("evidence_ids") or []
        if not ids:
            uncited.append(f["finding_id"])
        for eid in ids:
            path = ev_dir / f"{eid}.json"
            if not path.is_file():
                missing.append((f["finding_id"], eid))
            elif json.loads(path.read_text(encoding="utf-8")).get("evidence_id") != eid:
                missing.append((f["finding_id"], f"{eid} (id mismatch)"))
    assert not uncited, f"findings without evidence: {uncited[:10]}"
    assert not missing, f"evidence files missing: {missing[:10]}"


# ---- graph.json ---------------------------------------------------------------------------------------------

def test_graph_roots_and_pseudo_nodes(run, golden):
    g, exp = run["graph"], golden["graph"]
    assert set(exp["roots"]) <= set(g["roots"]), f"graph roots {g['roots']}"
    ids = {n["id"] for n in g["nodes"]}
    assert set(exp["roots"]) <= ids, "root project nodes missing from graph nodes"
    missing = [p for p in exp["pseudo_nodes"] if p not in ids]
    assert not missing, f"pseudo-nodes missing: {missing}"


def test_path_nodes_have_origin_and_integrity(run, golden):
    nodes = {n["id"]: n for n in run["graph"]["nodes"]}
    on_path = {pid for f in run["findings"] for p in f.get("dependency_paths") or [] for pid in p}
    pkg_on_path = [pid for pid in on_path if nodes.get(pid, {}).get("kind") == "package"]
    assert pkg_on_path, "no package nodes on any finding path"
    not_in_graph = sorted(pid for pid in on_path if pid.startswith("pkg:") and pid not in nodes)
    assert not not_in_graph, f"path nodes not in graph.json: {not_in_graph[:10]}"
    bad = [(pid, k) for pid in pkg_on_path for k in golden["graph"]["path_nodes_require"] if not nodes[pid].get(k)]
    assert not bad, f"path nodes missing origin/integrity: {bad[:10]}"


# ---- changes.json -------------------------------------------------------------------------------------------

def _purl_name(purl: str) -> str:
    return purl.split("/", 1)[-1].rsplit("@", 1)[0].replace("%40", "@")


def test_changes(run, golden):
    c, exp = run["changes"], golden["changes"]
    c = c.get("legacy", c)  # a --compare-ref run keeps the legacy .bak diff under "legacy"
    assert c["base"] == exp["base"] and c["head"] == exp["head"]
    removed = {_purl_name(p) for p in c.get("removed", [])}
    missing = [n for n in exp["removed_names"] if n not in removed]
    assert not missing, f"changes.json removed list lacks {missing}"
    if exp.get("require_evidence"):
        assert c.get("evidence_ids"), "changes.json has no evidence_ids"


# ---- trace.jsonl --------------------------------------------------------------------------------------------

def test_trace(run, golden):
    t, exp = run["trace"], golden["trace"]
    agents = {e["agent"] for e in t}
    assert set(exp["agents"]) <= agents, f"agents in trace: {sorted(agents)}"
    types = {e["type"] for e in t}
    assert set(exp["event_types"]) <= types, f"event types in trace: {sorted(types)}"
    handoff_from = {e["agent"] for e in t if e["type"] == "handoff"}
    assert set(exp["handoffs_from"]) <= handoff_from, f"handoffs from: {sorted(handoff_from)}"
    assert any(e["type"] == "decision" and e["agent"] == exp["decision_agent"] for e in t), "no supervisor decision"


# ---- advisory (visible as xfail, not a hard P0) -----------------------------------------------------------

def test_advisory_llm_explanations(run, golden):
    explained = [f for f in run["findings"] if f.get("explanation")]
    need = golden["advisory"]["llm_explanations_min"]
    if len(explained) < need:
        errors = [e["summary"] for e in run["trace"] if e["agent"] == "evidence_analyst" and e["type"] == "error"]
        pytest.xfail(f"evidence analyst wrote {len(explained)} LLM explanations (need >= {need}); "
                     f"all findings use rule-based risk. First error: {errors[0] if errors else 'none'}")
