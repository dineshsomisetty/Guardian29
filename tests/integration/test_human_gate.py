"""D1-05 acceptance: the remediation loop pauses at the human gate, resumes in a new process with the same
plan_id, refuses mismatched decisions, never reaches the validator without an approval, re-plans after a
reject and verifies the fix by re-running the detector on a patched copy. Real detectors, no network."""

import json

import pytest

from guardian.core.models import Approval
from guardian.core.plans import get_pending, list_plans, list_validations
from guardian.graph import state as graph_state
from guardian.graph import workflow
from guardian.tools import patching, registry

SHA = "a" * 40
PKG = """{
  "name": "shop",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.21.2",
    "ngy-cookie": "^6.0.0"
  }
}
"""
LOCK = {"name": "shop", "lockfileVersion": 3, "packages": {"": {"dependencies": {"express": "^4.21.2"}}}}
WORKFLOW = "jobs:\n  t:\n    steps:\n      - uses: coverallsapp/github-action@v2\n"


def workspace(ctx):
    import shutil
    work = ctx.run_dir / "work"
    shutil.copytree(ctx.repo, work)
    (work / "package-lock.json").write_text(json.dumps(LOCK))  # what discovery's --ignore-scripts resolve writes
    return registry.ToolOutput(artifacts={"work_dir": work})


BINDINGS = {
    "discovery": [("workspace", f"{__name__}:workspace")],
    "detection": [("detector:lockfile", "guardian.tools.detectors.lockfile:detect"),
                  ("detector:typosquat", "guardian.tools.detectors.typosquat:detect"),
                  ("detector:ci_pin", "guardian.tools.detectors.ci_pin:detect")],
}


@pytest.fixture
def target(tmp_path, monkeypatch):
    repo = tmp_path / "shop"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "package.json").write_text(PKG)
    (repo / ".npmrc").write_text("package-lock=false\n")
    (repo / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    import guardian.agents.detection as det
    import guardian.agents.discovery as dis
    for mod in (registry, dis, det):
        monkeypatch.setattr(mod, "BINDINGS", BINDINGS)
    monkeypatch.setattr(patching, "_SHA_CACHE", tmp_path / "shas.json")
    monkeypatch.setattr(patching, "ls_remote", lambda action, ref: (SHA, "tag"))
    return repo


def _settings(settings, plans):
    from dataclasses import replace
    return replace(settings, max_plans=plans)


def _decide(settings, run_id, decision, comment=None, plan=None, plan_hash=None):
    run_dir = settings.runs_dir / run_id
    pending = plan or get_pending(run_dir)
    approval = Approval(plan_id=pending.plan_id, plan_hash=plan_hash or pending.plan_hash, decision=decision,
                        comment=comment, decided_by="test")
    graph_state._CONTEXTS.clear()  # a resume is a fresh process: nothing in memory survives
    return workflow.resume(run_id, approval, settings=settings, echo=False)


def _summary(run_dir):
    return json.loads((run_dir / "run_summary.json").read_text())


def _trace(run_dir):
    return [json.loads(x) for x in (run_dir / "trace.jsonl").read_text().splitlines()]


def test_pause_resume_verify_and_replan(target, settings, fake_llm_factory):
    s = _settings(settings, plans=3)
    llm, _ = fake_llm_factory(lambda *a: '{"assessments": []}')
    run_dir = workflow.run(target, run_id="run_gate", settings=s, llm=llm, echo=False)

    summary = _summary(run_dir)
    assert summary["status"] == "awaiting_human"
    first = get_pending(run_dir)
    assert first.action == "replace" and summary["pending_plan"]["plan_id"] == first.plan_id
    assert not list_validations(run_dir)  # G5.1: nothing validated before a decision
    assert not (run_dir / "attempts").exists()
    preview = [e for e in _trace(run_dir) if e["type"] == "tool_result" and "plan_preview" in e["summary"]]
    assert preview, "the human sees a dry-run diff before deciding"

    # wrong hash and reject-without-comment are refused, nothing resumes
    with pytest.raises(workflow.DecisionRejected):
        _decide(s, "run_gate", "approve", plan_hash="0" * 64)
    with pytest.raises(workflow.DecisionRejected, match="comment"):
        _decide(s, "run_gate", "reject")
    assert get_pending(run_dir).plan_id == first.plan_id

    # reject -> a different plan for the same finding (remove instead of replace)
    _decide(s, "run_gate", "reject", comment="code imports ngy-cookie; prefer removal")
    second = get_pending(run_dir)
    assert second.finding_id == first.finding_id and second.plan_id != first.plan_id
    assert second.action == "remove" and second.attempt == 2

    # approve -> validator re-runs the typosquat detector on a patched copy -> verified
    _decide(s, "run_gate", "approve")
    v = list_validations(run_dir)
    assert len(v) == 1 and v[0].verdict == "verified" and v[0].build_ok is None
    attempt = run_dir / "attempts" / v[0].attempt_id / "work"
    assert "ngy-cookie" not in (attempt / "package.json").read_text()
    assert "ngy-cookie" in (target / "package.json").read_text()  # the target itself is never modified

    # next queued findings: lockfile then CI pin (each its own plan, SHA from evidence)
    lock_plan = get_pending(run_dir)
    assert lock_plan.ops[0].op == "generate_lockfile"
    _decide(s, "run_gate", "accept_risk", comment="lockfile policy handled upstream")
    ci_plan = get_pending(run_dir)
    assert ci_plan.ops[0].op == "pin_action_sha" and ci_plan.target_version == SHA
    run_dir = _decide(s, "run_gate", "approve")

    summary = _summary(run_dir)
    assert summary["status"] == "done" and summary["pending_plan"] is None
    status = {o["category"]: o["status"] for o in summary["remediation"]}
    assert status == {"typosquat": "verified", "lockfile": "accepted", "unpinned_ci": "verified"}
    pinned = next(at for at in (run_dir / "attempts").iterdir()
                  if (at / "work" / ".github" / "workflows" / "ci.yml").read_text().count(SHA))
    assert f"coverallsapp/github-action@{SHA} # v2" in (pinned / "work/.github/workflows/ci.yml").read_text()
    approvals = (run_dir / "approvals.jsonl").read_text().splitlines()
    assert [json.loads(a)["decision"] for a in approvals] == ["reject", "approve", "accept_risk", "approve"]
    types = {e["type"] for e in _trace(run_dir)}
    assert {"gate_wait", "gate_resume"} <= types


def test_not_resolved_replans_then_escalates(target, settings, fake_llm_factory, monkeypatch):
    s = _settings(settings, plans=1)
    llm, _ = fake_llm_factory(lambda *a: '{"assessments": []}')
    # sabotage the fix: the patch op silently changes nothing, so the detector still reports the typosquat
    monkeypatch.setitem(patching._TEXT_OPS, "replace_dependency", lambda text, a: text)
    monkeypatch.setitem(patching._TEXT_OPS, "remove_dependency", lambda text, a: text)
    monkeypatch.setattr(patching, "_remove", lambda text, a: text)  # block_package removes through _remove
    run_dir = workflow.run(target, run_id="run_fail", settings=s, llm=llm, echo=False)
    _decide(s, "run_fail", "approve")
    assert list_validations(run_dir)[0].verdict == "not_resolved"
    _decide(s, "run_fail", "approve")  # second, different candidate also fails
    _decide(s, "run_fail", "approve")  # third (block) also fails: attempt limit
    summary = _summary(run_dir)
    assert summary["status"] == "done"
    assert summary["remediation"][0]["status"] == "escalated"
    assert len(list_plans(run_dir)) == 3 and {p.action for p in list_plans(run_dir)} == {"replace", "remove", "block"}


def test_validator_unreachable_without_approval(target, settings):
    from guardian.core.audit import AuditLog
    from guardian.core.store import JsonStore

    plan = None
    ctx = registry.ToolContext(run_id="r", run_dir=target.parent / "r", repo=target, settings=settings)
    out = registry.call_tool("validator", "apply_plan", None, ctx, JsonStore(ctx.run_dir),
                             AuditLog(ctx.run_dir, "r", echo=False),
                             args={"plan_id": "pl_" + "0" * 26, "attempt_id": "at_" + "0" * 26,
                                   "ops": [{"op": "remove_dependency", "file_path": "package.json",
                                            "args": {"name": "ngy-cookie"}}]}, plan=plan, approval=None)
    assert out is None and not (ctx.run_dir / "attempts").exists()


def test_resume_keeps_the_original_llm_provenance(target, settings, fake_llm_factory):
    """`decide` runs in a fresh process with its own settings and no LLM; the run summary must still name
    the mode and model that produced the LLM assessments (principle 3: honest labels)."""
    from dataclasses import replace
    s = replace(_settings(settings, plans=1), llm_mode="replay")
    llm, backend = fake_llm_factory(lambda *a: '{"assessments": []}')
    run_dir = workflow.run(target, run_id="run_prov", settings=s, llm=llm, echo=False)
    before = _summary(run_dir)["llm"]
    assert before == {"mode": "replay", "model": backend.model}

    run_dir = _decide(replace(s, llm_mode="live"), "run_prov", "approve")
    after = _summary(run_dir)
    assert after["status"] == "done"
    assert after["llm"] == before


def test_demo_mode_sandbox_run_then_gate(target, settings, fake_llm_factory):
    """GUARDIAN_DEMO_VALIDATOR=1: one finding enters the loop, a timed (simulated) sandbox run is shown before the
    human gate, nothing is applied before the approval, and the validator after it skips the Docker sandbox."""
    import time
    from dataclasses import replace
    s = replace(_settings(settings, plans=3), demo_validator=True, demo_sandbox_seconds=0.3)
    llm, _ = fake_llm_factory(lambda *a: '{"assessments": []}')
    t0 = time.monotonic()
    run_dir = workflow.run(target, run_id="run_demo", settings=s, llm=llm, echo=False)
    assert time.monotonic() - t0 >= 0.3

    assert _summary(run_dir)["status"] == "awaiting_human"
    assert not list_validations(run_dir) and not (run_dir / "attempts").exists()
    trace = _trace(run_dir)
    steps = [e for e in trace if e["type"] == "sandbox_step"]
    assert len(steps) == 6 and all(e["agent"] == "validator" and e["data"]["simulated"] for e in steps)
    order = [(e["agent"], e["type"]) for e in trace]
    start = order.index(("validator", "agent_start"))
    end = order.index(("validator", "agent_end"))
    gate = order.index(("human_gate", "gate_wait"))
    assert start < end < gate and order.count(("human_gate", "gate_wait")) == 1

    run_dir = _decide(s, "run_demo", "approve")
    summary = _summary(run_dir)
    assert summary["status"] == "done" and len(summary["remediation"]) == 1
    v = list_validations(run_dir)
    assert len(v) == 1 and v[0].verdict == "verified" and v[0].build_ok is None
