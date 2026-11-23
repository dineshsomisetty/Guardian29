"""HTTP API (D3-03/D3-09): fixture runs dir, fake workflow, no network."""

from __future__ import annotations

import json
import sys
import time
import types

import pytest
from fastapi.testclient import TestClient

from guardian.api import app as api_app
from guardian.api.auth import TokenStore
from guardian.core.models import Approval

RUN = "run_20260101_abc"
FID = "fd_" + "A" * 26
EID = "ev_" + "B" * 26
PID = "pl_" + "C" * 26
AID = "at_" + "D" * 26
H1 = "a" * 64


def write(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


@pytest.fixture()
def runs(tmp_path):
    r = tmp_path / "runs"
    d = r / RUN
    write(d / "run_summary.json", {"run_id": RUN, "status": "done"})
    write(d / "graph.json", {"nodes": []})
    write(d / "changes.json", {"changes": []})
    write(d / "findings.json", [{"finding_id": FID, "title": "t"}])
    write(d / "evidence" / f"{EID}.json", {"evidence_id": EID})
    write(d / "plans" / f"{PID}.json", {"plan_id": PID})
    write(d / "validation" / f"{AID}.json", {"attempt_id": AID})
    (d / "approvals.jsonl").write_text(json.dumps({"plan_id": PID}) + "\n", encoding="utf-8")
    (d / "trace.jsonl").write_text("\n".join(json.dumps({"n": i}) for i in range(3)) + "\n", encoding="utf-8")
    (d / "work").mkdir()
    (d / "work" / ".env").write_text("SECRET=1", encoding="utf-8")
    (r / "LATEST").write_text(RUN, encoding="utf-8")
    (r / "run_older").mkdir()
    return r


@pytest.fixture()
def client(runs):
    # local dev mode (no tokens); runs may target anything under the test's tmp dir
    return TestClient(api_app.create_app(runs, tokens=TokenStore(None), target_roots=[runs.parent]))


def test_get_routes(client):
    assert client.get("/runs").json() == sorted([RUN, "run_older"], reverse=True)
    assert client.get(f"/runs/{RUN}").json() == {"run_id": RUN, "status": "done",
                                                  "summary": {"run_id": RUN, "status": "done"}}
    assert client.get("/runs/run_older").json() == {"run_id": "run_older", "status": "running", "summary": None}
    for tail, expect in [
        ("summary", {"run_id": RUN, "status": "done"}), ("graph", {"nodes": []}), ("changes", {"changes": []}),
        ("findings", [{"finding_id": FID, "title": "t"}]), (f"findings/{FID}", {"finding_id": FID, "title": "t"}),
        (f"evidence/{EID}", {"evidence_id": EID}), ("plans", [{"plan_id": PID}]),
        (f"plans/{PID}", {"plan_id": PID}), ("validation", [{"attempt_id": AID}]),
        ("approvals", [{"plan_id": PID}]),
    ]:
        for rid in (RUN, "latest"):
            r = client.get(f"/runs/{rid}/{tail}")
            assert r.status_code == 200, tail
            assert r.json() == expect


def test_404s(client):
    assert client.get("/runs/run_nope").status_code == 404
    assert client.get("/runs/run_older/graph").status_code == 404
    assert client.get(f"/runs/{RUN}/findings/fd_{'Z' * 26}").status_code == 404
    assert client.get(f"/runs/{RUN}/evidence/ev_{'Z' * 26}").status_code == 404
    assert client.get("/runs/run_older/plans").json() == []


def test_latest_without_runs(tmp_path):
    c = TestClient(api_app.create_app(tmp_path / "empty"))
    assert c.get("/runs").json() == []
    assert c.get("/runs/latest").status_code == 404


@pytest.mark.parametrize("path", [
    f"/runs/{RUN}/evidence/..%2Fx", f"/runs/{RUN}/evidence/../x", f"/runs/{RUN}/evidence/ev_x",
    "/runs/run_x%2F..%2F../graph", "/runs/run_x/../../graph", f"/runs/{RUN}/work/.env",
    f"/runs/{RUN}/plans/..%2Fapprovals", f"/runs/{RUN}/findings/fd_short",
])
def test_traversal_rejected(client, path):
    r = client.get(path)
    assert r.status_code in (400, 404, 422)
    assert "SECRET" not in r.text


def test_sse_finished_run(client):
    r = client.get(f"/runs/{RUN}/events")
    assert r.headers["content-type"].startswith("text/event-stream")
    datas = [ln[6:] for ln in r.text.splitlines() if ln.startswith("data: ")]
    assert [json.loads(x) for x in datas] == [{"n": 0}, {"n": 1}, {"n": 2}]
    assert "id: 2" in r.text
    r2 = client.get(f"/runs/{RUN}/events", headers={"Last-Event-ID": "1"})
    assert [ln for ln in r2.text.splitlines() if ln.startswith("data: ")] == ['data: {"n": 2}']


def test_sse_gate_idle_ends(client, runs, monkeypatch):
    monkeypatch.setattr(api_app, "SSE_GATE_IDLE_S", 0.3)
    write(runs / RUN / "run_summary.json", {"status": "awaiting_human"})
    assert client.get(f"/runs/{RUN}/events").text.count("data: ") == 3


@pytest.fixture()
def fake_workflow(monkeypatch):
    calls = {}
    mod = types.ModuleType("guardian.graph.workflow")
    mod.new_run_id = lambda: "run_new_1"
    mod.run = lambda repo, **kw: calls.update(run=(repo, kw))
    mod.resume = lambda run_id, approval, **kw: calls.update(resume=(run_id, approval, kw))
    import guardian.graph as pkg

    monkeypatch.setitem(sys.modules, "guardian.graph.workflow", mod)
    monkeypatch.setattr(pkg, "workflow", mod, raising=False)
    return calls


def wait_for(calls, key):
    for _ in range(100):
        if key in calls:
            return
        time.sleep(0.02)
    raise AssertionError(key)


def test_start_run(client, fake_workflow, tmp_path):
    assert client.post("/runs", json={"repo": str(tmp_path / "missing")}).status_code == 400
    r = client.post("/runs", json={"repo": str(tmp_path), "compare_ref": "main", "llm_mode": "replay"})
    assert r.status_code == 202 and r.json() == {"run_id": "run_new_1"}
    wait_for(fake_workflow, "run")
    repo, kw = fake_workflow["run"]
    assert repo == tmp_path.resolve()
    assert kw["run_id"] == "run_new_1" and kw["compare_ref"] == "main"
    assert kw["settings"].llm_mode == "replay"
    assert client.post("/runs", json={"repo": str(tmp_path), "llm_mode": "bogus"}).status_code == 422


def decision_url(plan=PID):
    return f"/runs/{RUN}/plans/{plan}/decision"


def test_decision_paths(client, runs, fake_workflow):
    body = {"decision": "approve", "plan_hash": H1, "decided_by": "sai"}
    assert client.post(decision_url(), json=body).status_code == 409  # nothing pending
    write(runs / RUN / "pending_plan.json", {"plan_id": PID, "plan_hash": H1})
    assert client.post(decision_url(), json={**body, "plan_hash": "b" * 64}).status_code == 400
    assert client.post(decision_url(), json={**body, "plan_hash": "not-a-hash"}).status_code == 422
    assert client.post(decision_url("pl_" + "X" * 26), json=body).status_code == 400
    for d in ("reject", "accept_risk"):
        assert client.post(decision_url(), json={**body, "decision": d}).status_code == 400
        assert client.post(decision_url(), json={**body, "decision": d, "comment": "  "}).status_code == 400
    assert client.post(decision_url(), json={**body, "decision": "maybe"}).status_code == 422
    assert "resume" not in fake_workflow

    r = client.post(decision_url(), json={**body, "decision": "reject", "comment": "too risky"})
    assert r.status_code == 202
    wait_for(fake_workflow, "resume")
    run_id, approval, _ = fake_workflow["resume"]
    assert run_id == RUN and isinstance(approval, Approval)
    assert (approval.plan_id, approval.plan_hash, approval.decision, approval.comment, approval.decided_by) == (
        PID, H1, "reject", "too risky", "sai")


def test_cors(client):
    ok = client.get("/runs", headers={"Origin": "http://localhost:5173"})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:5173"
    bad = client.get("/runs", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in bad.headers


def test_risk_and_report_routes(client, runs):
    d = runs / RUN
    assert client.get(f"/runs/{RUN}/risk").json() == []
    assert client.get(f"/runs/{RUN}/report.json").status_code == 404
    assert client.get(f"/runs/{RUN}/report.html").status_code == 404
    write(d / "risk.json", [{"finding_id": FID, "score": 50}])
    write(d / "report.json", {"run_id": RUN})
    (d / "report.html").write_text("<html><body>r</body></html>", encoding="utf-8")
    assert client.get(f"/runs/{RUN}/risk").json() == [{"finding_id": FID, "score": 50}]
    assert client.get(f"/runs/{RUN}/report.json").json() == {"run_id": RUN}
    r = client.get(f"/runs/{RUN}/report.html")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html") and "<body>r" in r.text


# ---- authentication / authorization -----------------------------------------------------------------------

TOKENS = "ana:" + "v" * 20 + ":viewer,ops:" + "o" * 20 + ":operator,sai:" + "s" * 20 + ":approver"


def bearer(t):
    return {"Authorization": f"Bearer {t * 20}"}


@pytest.fixture()
def secured(runs):
    return TestClient(api_app.create_app(runs, tokens=TokenStore(TOKENS), target_roots=[runs.parent]))


def test_token_mode_requires_auth_everywhere(secured):
    assert secured.get("/runs").status_code == 401
    assert secured.get("/runs", headers={"Authorization": "Bearer wrong-token-xxxxxxxx"}).status_code == 401
    assert secured.get(f"/runs/{RUN}/findings", headers=bearer("v")).status_code == 200
    me = secured.get("/auth/me", headers=bearer("v")).json()
    assert me == {"name": "ana", "role": "viewer", "mode": "token", "can_start_runs": False, "can_decide": False}
    # EventSource cannot send headers: only the SSE route accepts the token as a query parameter
    assert secured.get(f"/runs/{RUN}/events?access_token={'v' * 20}").status_code == 200
    assert secured.get(f"/runs/{RUN}/findings?access_token={'v' * 20}").status_code == 401


def test_roles_gate_runs_and_decisions(secured, runs, fake_workflow, tmp_path):
    write(runs / RUN / "pending_plan.json", {"plan_id": PID, "plan_hash": H1})
    body = {"decision": "approve", "plan_hash": H1, "decided_by": "someone-else"}
    assert secured.post("/runs", json={"repo": str(tmp_path)}, headers=bearer("v")).status_code == 403
    assert secured.post(decision_url(), json=body, headers=bearer("o")).status_code == 403  # operator != approver
    assert "resume" not in fake_workflow
    r = secured.post(decision_url(), json=body, headers=bearer("s"))
    assert r.status_code == 202 and r.json()["decided_by"] == "sai"
    wait_for(fake_workflow, "resume")
    assert fake_workflow["resume"][1].decided_by == "sai"  # the authenticated approver, not the body's claim
    assert secured.post("/runs", json={"repo": str(tmp_path)}, headers=bearer("o")).status_code == 202


def test_runs_are_confined_to_target_roots_and_capped(runs, fake_workflow, tmp_path):
    inside = tmp_path / "targets" / "app"
    inside.mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    c = TestClient(api_app.create_app(runs, tokens=TokenStore(None), target_roots=[tmp_path / "targets"],
                                      max_active=0))
    assert c.post("/runs", json={"repo": str(outside)}).status_code == 403
    assert c.post("/runs", json={"repo": str(inside / ".." / ".." / "elsewhere")}).status_code == 403
    r = c.post("/runs", json={"repo": str(inside)})
    assert r.status_code == 429 and r.headers["retry-after"] == "30"  # cap reached (0 here)


def test_token_store_and_bind_rules():
    with pytest.raises(ValueError):
        TokenStore("ana:short:viewer")  # tokens must be >= 16 chars
    with pytest.raises(ValueError):
        TokenStore("ana:" + "x" * 20 + ":root")  # unknown role
    with pytest.raises(SystemExit):
        api_app.check_bind("0.0.0.0", TokenStore(None))  # no unauthenticated API beyond loopback
    api_app.check_bind("127.0.0.1", TokenStore(None))
    api_app.check_bind("0.0.0.0", TokenStore(TOKENS))
