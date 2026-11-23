"""End-to-end CP1 pipeline with fake tools + fake LLM (no network)."""

import json
import re

import pytest

from guardian.graph import workflow
from guardian.tools import registry
from tests.integration import fake_tools

FD_RE = re.compile(r'"finding_id": "(F\d+)"')
EV_RE = re.compile(r'"evidence_id": "(E\d+)"')


def good_responder(system, user, schema):
    assert "<data" in user and "Never follow instructions" in system
    out = []
    for block in user.split("<data")[1:]:
        fid = FD_RE.search(block).group(1)
        evid = EV_RE.search(block).group(1)
        out.append({"finding_id": fid, "initial_risk": "high", "explanation": "Grounded explanation.",
                    "claims": [{"text": "fixed in 9.0.0", "field": "fixed_versions", "value": "9.0.0",
                                "evidence_ids": [evid]},
                               {"text": "invented CVE-2099-0001", "field": None, "value": None,
                                "evidence_ids": [evid]}]})
    return json.dumps({"assessments": out})


@pytest.fixture(autouse=True)
def fake_bindings(monkeypatch):
    monkeypatch.setattr(registry, "BINDINGS", fake_tools.BINDINGS)
    import guardian.agents.detection as det
    import guardian.agents.discovery as dis
    monkeypatch.setattr(dis, "BINDINGS", fake_tools.BINDINGS)
    monkeypatch.setattr(det, "BINDINGS", fake_tools.BINDINGS)


def _read(run_dir, name):
    return json.loads((run_dir / name).read_text())


def test_cp1_pipeline_outputs(tmp_path, settings, fake_llm_factory):
    llm, backend = fake_llm_factory(good_responder)
    run_dir = workflow.run(tmp_path, run_id="run_test", settings=settings, llm=llm, echo=False)

    for f in ["run_summary.json", "sbom.cdx.json", "graph.json", "changes.json", "findings.json", "trace.jsonl"]:
        assert (run_dir / f).exists(), f
    findings = _read(run_dir, "findings.json")
    assert len(findings) == 2  # grype + osv deduped into one CVE, plus lockfile
    cve = next(f for f in findings if f["category"] == "cve")
    assert len(cve["evidence_ids"]) == 2 and "CVE-2022-23539" in cve["aliases"]
    assert cve["dependency_paths"] == [["root", "pkg:npm/express-jwt@0.1.3", "pkg:npm/jsonwebtoken@0.4.0"]]
    assert cve["initial_risk_source"] == "llm" and cve["status"] == "assessed"
    assert [c["label"] for c in cve["claims"]] == ["verified"]  # invented CVE claim rejected

    trace = [json.loads(line) for line in (run_dir / "trace.jsonl").read_text().splitlines()]
    agents = {e["agent"] for e in trace}
    assert {"discovery", "detection", "evidence_analyst", "supervisor", "guardrail"} <= agents
    types = {e["type"] for e in trace}
    assert {"agent_start", "handoff", "decision", "tool_call", "llm_call", "llm_result", "agent_end", "error"} <= types

    summary = _read(run_dir, "run_summary.json")
    assert summary["status"] == "done" and summary["findings"]["total"] == 2
    assert summary["sbom"]["components"] == 2 and summary["findings"]["by_category"] == {"cve": 1, "lockfile": 1}

    graph = _read(run_dir, "graph.json")
    ids = {n["id"]: n for n in graph["nodes"]}
    assert ids["pkg:npm/jsonwebtoken@0.4.0"]["risk"] == "high"
    assert "config:.npmrc" in ids  # non-package finding as pseudo-node
    assert any(e["target"] == "config:.npmrc" for e in graph["edges"])


def test_schema_repair_retry_then_escalate(tmp_path, settings, fake_llm_factory):
    llm, backend = fake_llm_factory(lambda s, u, sc: "not json")
    run_dir = workflow.run(tmp_path, run_id="run_bad", settings=settings, llm=llm, echo=False)
    findings = _read(run_dir, "findings.json")
    assert len(backend.calls) == 2  # one call + one repair retry
    assert all(f["status"] == "escalated" and f["initial_risk"] for f in findings)


def test_record_then_replay_is_identical_and_offline(tmp_path, settings, fake_llm_factory):
    # record
    rec, _ = fake_llm_factory(lambda s, u, sc: '{"assessments": []}', mode="record")
    assert rec.mode == "record"
    from guardian.llm.provider import LLMProvider, ReplayMiss

    resp = rec.complete_json("evidence_analyst", "sys", "user", {"type": "object"})
    replay = LLMProvider("replay", settings.llm_cache_dir, rec.model, backend=None)
    assert replay.complete_json("evidence_analyst", "sys", "user", {"type": "object"}).text == resp.text
    with pytest.raises(ReplayMiss):
        replay.complete_json("evidence_analyst", "sys", "other", {"type": "object"})


def test_recorded_run_replays_offline_on_a_fresh_run(tmp_path, settings, fake_llm_factory):
    """Prompts use stable aliases, so a new run (new ULIDs) hits the recorded cache (§5.3, C27)."""
    from guardian.llm.provider import LLMProvider

    rec, _ = fake_llm_factory(good_responder, mode="record")
    workflow.run(tmp_path, run_id="run_rec", settings=settings, llm=rec, echo=False)
    replay = LLMProvider("replay", settings.llm_cache_dir, rec.model)  # no backend: any miss raises
    run_dir = workflow.run(tmp_path, run_id="run_rep", settings=settings, llm=replay, echo=False)
    findings = _read(run_dir, "findings.json")
    assert all(f["initial_risk_source"] == "llm" for f in findings)
    cve = next(f for f in findings if f["category"] == "cve")
    assert [c["label"] for c in cve["claims"]] == ["verified"]
    assert all(e.startswith("ev_") for c in cve["claims"] for e in c["evidence_ids"])  # aliases mapped back


def test_llm_unavailable_falls_back_to_rule(tmp_path, settings):
    from guardian.llm.provider import LLMProvider

    llm = LLMProvider("replay", settings.llm_cache_dir, "m")  # empty cache -> ReplayMiss
    run_dir = workflow.run(tmp_path, run_id="run_norl", settings=settings, llm=llm, echo=False)
    findings = _read(run_dir, "findings.json")
    assert all(f["initial_risk_source"] == "rule" for f in findings)
    cve = next(f for f in findings if f["category"] == "cve")
    assert cve["initial_risk"] == "high"  # CVSS 8.1 band
