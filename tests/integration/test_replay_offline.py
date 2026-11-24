"""D1-13: a recorded run replays offline with identical LLM-derived results and no network or backend use."""

import json
import re
import socket

import pytest

from guardian.graph import workflow
from guardian.llm.provider import LLMProvider
from guardian.tools import registry
from tests.integration import fake_tools

FD_RE = re.compile(r'"finding_id": "(F\d+)"')
EV_RE = re.compile(r'"evidence_id": "(E\d+)"')


def responder(system, user, schema):
    out = []
    for block in user.split("<data")[1:]:
        fid, evid = FD_RE.search(block).group(1), EV_RE.search(block).group(1)
        out.append({"finding_id": fid, "initial_risk": "critical", "explanation": "Recorded explanation.",
                    "claims": [{"text": "fixed in 9.0.0", "field": "fixed_versions", "value": "9.0.0",
                                "evidence_ids": [evid]},
                               {"text": "invented CVE-2099-0001", "field": None, "value": None,
                                "evidence_ids": [evid]}]})
    return json.dumps({"assessments": out})


@pytest.fixture(autouse=True)
def fake_bindings(monkeypatch):
    import guardian.agents.detection as det
    import guardian.agents.discovery as dis

    for mod in (registry, dis, det):
        monkeypatch.setattr(mod, "BINDINGS", fake_tools.BINDINGS)


def _load(run_dir, name):
    return json.loads((run_dir / name).read_text(encoding="utf-8"))


def _by_title(run_dir) -> dict:
    """LLM-derived fields keyed by title (ids differ between runs)."""
    out = {}
    for f in _load(run_dir, "findings.json"):
        claims = [(c["text"], c["field"], c["value"], c["label"]) for c in f["claims"]]
        out[f["title"]] = {"initial_risk": f["initial_risk"], "source": f["initial_risk_source"],
                           "explanation": f["explanation"], "claims": claims, "status": f["status"]}
    return out


def test_replay_matches_recording_without_backend_or_network(tmp_path, settings, fake_llm_factory, monkeypatch):
    rec, backend = fake_llm_factory(responder, mode="record")
    rec_dir = workflow.run(tmp_path, run_id="run_rec", settings=settings, llm=rec, echo=False)
    assert backend.calls, "recording run must have used the fake LLM"
    recorded = _by_title(rec_dir)
    assert any(v["source"] == "llm" for v in recorded.values())

    attempts = []

    def no_network(*a, **k):
        attempts.append((a, k))
        raise AssertionError("network attempted during replay")

    def no_backend():
        raise AssertionError("LLM backend constructed during replay")

    monkeypatch.setattr("httpx.post", no_network)
    monkeypatch.setattr("httpx.get", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)

    replay = LLMProvider("replay", settings.llm_cache_dir, rec.model, backend_factory=no_backend)
    rep_dir = workflow.run(tmp_path, run_id="run_rep", settings=settings, llm=replay, echo=False)

    assert attempts == []
    assert _load(rep_dir, "run_summary.json")["status"] in {"done", "awaiting_human"}
    replayed = _by_title(rep_dir)
    assert replayed == recorded
    assert replayed  # not vacuously equal
    assert all(v["source"] == "llm" for v in replayed.values())


def test_replay_marks_llm_calls_as_cached(tmp_path, settings, fake_llm_factory):
    rec, _ = fake_llm_factory(responder, mode="record")
    workflow.run(tmp_path, run_id="run_rec", settings=settings, llm=rec, echo=False)
    replay = LLMProvider("replay", settings.llm_cache_dir, rec.model, backend_factory=lambda: pytest.fail("backend"))
    rep_dir = workflow.run(tmp_path, run_id="run_rep", settings=settings, llm=replay, echo=False)
    trace = [json.loads(line) for line in (rep_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    assert not [e for e in trace if e["type"] == "error" and "LLM" in e["summary"]]
    assert any(e["type"] == "llm_result" for e in trace)
