"""Phase 1: investigator (D1-08), graph shape, G5.3, offline replay with the investigator, resume + approval binding.

Real detectors on a small target (typosquat `ngy-cookie` like Juice Shop's frontend), fake LLM, no network."""

import ast
import inspect
import json
import socket
from dataclasses import replace

import pytest

from guardian.agents import investigator
from guardian.agents.batch import batch_gate_node
from guardian.agents.human_gate import human_gate_node
from guardian.agents.remediation import HEURISTIC, HEURISTIC_ACTIONS, candidates
from guardian.core.audit import AuditLog
from guardian.core.models import Approval, Evidence, Finding, FindingCategory
from guardian.core.plans import get_pending, list_plans, list_validations
from guardian.core.store import JsonStore
from guardian.graph import state as graph_state
from guardian.graph import workflow
from guardian.graph.state import RunContext
from guardian.guardrails.budgets import Budget
from guardian.llm.provider import LLMProvider
from guardian.tools import registry
from guardian.tools.detectors import install_scripts
from guardian.tools.registry import ToolContext
from tests.integration.test_human_gate import _decide, _summary, _trace, target  # noqa: F401

NODES = {"discovery", "detection", "evidence_analyst", "investigator", "risk_analyst", "remediation",
         "human_gate", "record_decision", "validator", "reporter",
         "recommend", "batch_gate", "record_batch", "validate_batch"}  # + batch remediation nodes


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    """No registry traffic, ever: the intel cache is empty and httpx.get fails the test."""
    monkeypatch.setattr(install_scripts, "CACHE", tmp_path / "intel")
    monkeypatch.setattr("httpx.get", lambda *a, **k: pytest.fail("network used"))


@pytest.fixture
def s(settings):
    return replace(settings, offline=True, max_plans=0)


def _conclusion(finding: dict | Finding):
    claims = finding["claims"] if isinstance(finding, dict) else [c.model_dump(mode="json") for c in finding.claims]
    return [c for c in claims if c["text"].startswith("Conclusion:")]


def scripted(steps):
    """Fake LLM: investigator turns come from `steps` (the last one repeats); every other agent gets nothing."""
    state = {"i": 0}

    def respond(system, user, schema):
        if "Investigator" not in system:
            return '{"assessments": []}'
        step = steps[min(state["i"], len(steps) - 1)]
        state["i"] += 1
        return json.dumps(step)

    return respond


def tool_step(tool, **args):
    base = {"action": "call_tool", "tool": tool, "name": None, "version": None, "path": None, "line": None,
            "context": None, "conclusion": None, "claims": []}
    return {**base, **args}


CONCLUDE = {**tool_step(None), "action": "conclude",
            "conclusion": {"text": "ngy-cookie is one edit away from the popular ngx-cookie package",
                           "field": "similar_to", "value": "ngx-cookie", "evidence_ids": ["E1"]}}
HAPPY = [tool_step("registry_metadata", name="ngy-cookie"), tool_step("file_excerpt", path="package.json", line=5),
         CONCLUDE]


def _events(run_dir, **match):
    return [e for e in _trace(run_dir) if all(e.get(k) == v for k, v in match.items())]


# ---------------------------------------------------------------- (a) graph shape


def test_graph_has_exactly_the_contract_nodes():
    g = workflow.build_graph().get_graph()
    assert set(g.nodes) - {"__start__", "__end__"} == NODES
    edges = {(e.source, e.target) for e in g.edges}
    assert ("evidence_analyst", "investigator") in edges and ("investigator", "risk_analyst") in edges
    assert ("evidence_analyst", "risk_analyst") not in edges
    assert {e.source for e in g.edges if e.target == "validator"} == {"record_decision"}
    assert {e.source for e in g.edges if e.target == "validate_batch"} == {"record_batch", "recommend"}
    assert {e.source for e in g.edges if e.target == "reporter"} >= {"validate_batch", "recommend", "record_batch"}


@pytest.mark.parametrize("node", [human_gate_node, batch_gate_node])
def test_human_gate_contains_only_interrupt(node):
    fn = ast.parse(inspect.getsource(node)).body[0]
    body = [n for n in fn.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]  # no docstring
    assert len(body) == 1 and isinstance(body[0], ast.Return)
    calls = {n.func.id if isinstance(n.func, ast.Name) else n.func.attr
             for n in ast.walk(body[0]) if isinstance(n, ast.Call)}
    assert "interrupt" in calls and calls <= {"interrupt", "get"}


# ---------------------------------------------------------------- (b) investigator


def test_typosquat_gets_evidence_and_a_verified_conclusion(target, s, fake_llm_factory, tmp_path):  # noqa: F811
    llm, backend = fake_llm_factory(scripted(HAPPY))
    run_dir = workflow.run(target, run_id="run_inv", settings=s, llm=llm, echo=False)
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    squat = next(f for f in findings if f["category"] == "typosquat")
    (concl,) = _conclusion(squat)
    assert concl["label"] == "verified" and concl["value"] == "ngx-cookie"  # label set by grounding code
    store = JsonStore(run_dir)
    kinds = {store.get_evidence(e).kind for e in squat["evidence_ids"]}
    assert {"detector_result", "registry_metadata", "file_excerpt"} <= kinds
    assert all(store.get_evidence(e) for e in concl["evidence_ids"])
    trace = _events(run_dir, agent="investigator")
    types = [e["type"] for e in trace]
    assert types[0] == "agent_start" and types[-2:] == ["agent_end", "handoff"]
    assert {"llm_call", "tool_call", "tool_result", "decision"} <= set(types)
    assert [e["summary"] for e in trace if e["type"] == "tool_call"] == ["registry_metadata", "file_excerpt"]
    assert sum("Investigator" in c or "investigation" in c for c in backend.calls) == 3
    assert squat["claims"][-1]["text"].startswith("Conclusion:")


def test_conclusion_without_valid_citation_is_inferred_not_verified(target, s, fake_llm_factory):  # noqa: F811
    bad = {**CONCLUDE, "conclusion": {"text": "looks fine", "field": "similar_to", "value": "ngx-cookie",
                                      "evidence_ids": ["E99"]}}
    llm, _ = fake_llm_factory(scripted([bad]))
    run_dir = workflow.run(target, run_id="run_bad", settings=s, llm=llm, echo=False)
    squat = next(f for f in json.loads((run_dir / "findings.json").read_text()) if f["category"] == "typosquat")
    (concl,) = _conclusion(squat)
    assert concl["label"] == "inferred"
    assert any(e["data"].get("rule") == "G4.2" for e in _events(run_dir, type="guardrail"))


def test_eight_tool_call_cap_is_enforced_by_the_budget(target, s, fake_llm_factory):  # noqa: F811
    llm, _ = fake_llm_factory(scripted([tool_step("registry_metadata", name="ngy-cookie")]))  # never concludes
    run_dir = workflow.run(target, run_id="run_cap", settings=s, llm=llm, echo=False)
    calls = _events(run_dir, agent="investigator", type="tool_call")
    assert len(calls) == 8
    blocked = [e for e in _events(run_dir, type="guardrail") if e["data"].get("rule") == "G3.6"
               and e["data"].get("agent") == "investigator"]
    assert len(blocked) == 1  # the 9th call was refused by call_tool, not by a counter in the agent
    assert _summary(run_dir)["budget"]["tool_calls"]["investigator"] == 8
    squat = next(f for f in json.loads((run_dir / "findings.json").read_text()) if f["category"] == "typosquat")
    (concl,) = _conclusion(squat)
    assert concl["label"] in {"verified", "inferred"}


def test_tool_allowlist_and_typed_args(target, s, fake_llm_factory):  # noqa: F811
    steps = [tool_step("apply_plan"), tool_step("file_excerpt", path="package.json", line=0, context=500),
             tool_step("file_excerpt", path=".env", line=1), CONCLUDE]
    llm, _ = fake_llm_factory(scripted(steps))
    run_dir = workflow.run(target, run_id="run_allow", settings=s, llm=llm, echo=False)
    rules = [e["data"]["rule"] for e in _events(run_dir, type="guardrail")]
    assert "G3.1" in rules and "G3.2" in rules  # not on the investigator allowlist; line/context out of range


def test_no_llm_runs_the_fixed_plan_and_labels_inferred(target, s):  # noqa: F811
    rc_llm = LLMProvider("replay", s.llm_cache_dir, "fake-llm", backend_factory=lambda: pytest.fail("backend"))
    run_dir = workflow.run(target, run_id="run_det", settings=s, llm=rc_llm, echo=False)  # replay miss
    calls = [e["summary"] for e in _events(run_dir, agent="investigator", type="tool_call")]
    assert calls == ["registry_metadata", "file_excerpt"]
    squat = next(f for f in json.loads((run_dir / "findings.json").read_text()) if f["category"] == "typosquat")
    (concl,) = _conclusion(squat)
    assert concl["label"] == "inferred" and "ngy-cookie" in concl["text"]
    meta = next(e for e in JsonStore(run_dir).list_evidence() if e.kind == "registry_metadata")
    assert meta.facts["available"] is False  # offline + empty cache: said so, nothing invented


def test_no_heuristic_findings_is_a_single_decision_noop(tmp_path, s):
    run_dir = tmp_path / "run"
    audit = AuditLog(run_dir, "run_x", echo=False)
    store = JsonStore(run_dir)
    ev = Evidence(run_id="run_x", kind="scanner_output", source_tool="grype", facts={"vuln_id": "CVE-2022-1"})
    store.add_evidence(ev)
    cve = store.add_finding(Finding(run_id="run_x", category=FindingCategory.CVE, title="cve", detector="grype",
                                    evidence_ids=[ev.evidence_id]))
    tool_ctx = ToolContext(run_id="run_x", run_dir=run_dir, repo=tmp_path, settings=s, budget=Budget())
    graph_state.register(RunContext(tool_ctx=tool_ctx, store=store, audit=audit, llm=None))
    try:
        out = investigator.investigator_node({"run_id": "run_x", "finding_ids": [cve.finding_id]})
    finally:
        graph_state.unregister("run_x")
    assert out == {"status": "investigating"}
    events = [json.loads(x) for x in (run_dir / "trace.jsonl").read_text().splitlines()]
    assert [(e["agent"], e["type"]) for e in events] == [("investigator", "decision")]
    assert store.get_finding(cve.finding_id).claims == []


def test_investigator_tools_are_registered_for_investigator_only():
    assert registry.allowed_tools("investigator") == {"registry_metadata", "file_excerpt", "manifest_diff"}
    for agent in ("detection", "remediation", "validator", "discovery"):
        assert not registry.allowed_tools(agent) & {"registry_metadata", "file_excerpt", "manifest_diff"}


# ---------------------------------------------------------------- (c) G5.3


def _rc(tmp_path, settings):
    run_dir = tmp_path / "g53"
    tool_ctx = ToolContext(run_id="run_g", run_dir=run_dir, repo=tmp_path, settings=settings)
    return RunContext(tool_ctx=tool_ctx, store=JsonStore(run_dir), audit=AuditLog(run_dir, "run_g", echo=False),
                      llm=None)


@pytest.mark.parametrize("category", sorted(HEURISTIC, key=lambda c: c.value))
def test_heuristic_findings_only_get_replace_remove_block_escalate(tmp_path, settings, category):
    rc = _rc(tmp_path, settings)
    ev = Evidence(run_id="run_g", kind="detector_result", source_tool="detector:typosquat",
                  facts={"name": "ngy-cookie", "range": "^6.0.0", "similar_to": "ngx-cookie", "distance": 1,
                         "legacy_manifest": False}, file_path="package.json", line=5)
    rc.store.add_evidence(ev)
    f = Finding(run_id="run_g", category=category, title="heuristic", detector="d", file_path="package.json",
                evidence_ids=[ev.evidence_id])
    actions = {c.action for c in candidates(rc, f)}
    assert actions <= HEURISTIC_ACTIONS
    if category is FindingCategory.TYPOSQUAT:
        assert actions == {"replace", "remove", "block"}


def test_filter_is_what_restricts_heuristics(tmp_path, settings):
    """A non-heuristic category does get 'pin'; the same candidate would be dropped for a heuristic one."""
    rc = _rc(tmp_path, settings)
    ev = Evidence(run_id="run_g", kind="file_excerpt", source_tool="detector:lockfile",
                  facts={"setting": "package-lock=false"}, file_path=".npmrc", line=1)
    rc.store.add_evidence(ev)
    f = Finding(run_id="run_g", category=FindingCategory.LOCKFILE, title="lock", detector="d", file_path=".npmrc",
                evidence_ids=[ev.evidence_id])
    assert {c.action for c in candidates(rc, f)} == {"pin"}
    assert "pin" not in HEURISTIC_ACTIONS and FindingCategory.LOCKFILE not in HEURISTIC


def test_every_plan_for_a_heuristic_finding_uses_an_allowed_action(target, s, fake_llm_factory):  # noqa: F811
    s3 = replace(s, max_plans=3)
    llm, _ = fake_llm_factory(scripted(HAPPY))
    run_dir = workflow.run(target, run_id="run_g53", settings=s3, llm=llm, echo=False)
    _decide(s3, "run_g53", "reject", comment="prefer removal")
    plans = list_plans(run_dir)
    squat = next(f for f in JsonStore(run_dir).list_findings() if f.category is FindingCategory.TYPOSQUAT)
    mine = [p for p in plans if p.finding_id == squat.finding_id]
    assert {p.action for p in mine} == {"replace", "remove"}


# ---------------------------------------------------------------- (d) offline replay incl. investigator


def test_replay_offline_full_run_makes_zero_network_calls(target, s, fake_llm_factory, monkeypatch):  # noqa: F811
    rec, backend = fake_llm_factory(scripted(HAPPY), mode="record")
    rec_dir = workflow.run(target, run_id="run_rec", settings=s, llm=rec, echo=False)
    assert len(_events(rec_dir, agent="investigator", type="llm_call")) == 3

    attempts = []

    def no_network(*a, **k):
        attempts.append((a, k))
        raise AssertionError("network attempted during offline replay")

    monkeypatch.setattr("httpx.post", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    replay = LLMProvider("replay", s.llm_cache_dir, rec.model, backend_factory=lambda: pytest.fail("backend"))
    rep_dir = workflow.run(target, run_id="run_rep", settings=s, llm=replay, echo=False)

    assert attempts == []
    assert not _events(rep_dir, type="error")
    assert len(_events(rep_dir, agent="investigator", type="tool_call")) == 2

    def conclusions(d):
        return [(f["title"], c["text"], c["label"]) for f in json.loads((d / "findings.json").read_text())
                for c in _conclusion(f)]

    assert conclusions(rep_dir) == conclusions(rec_dir) != []


# ---------------------------------------------------------------- (e) resume keeps plan_id, approval binding


def test_resume_keeps_plan_id_and_validator_needs_a_bound_approval(target, s, fake_llm_factory, monkeypatch):  # noqa: F811
    s1 = replace(s, max_plans=1)
    llm, _ = fake_llm_factory(scripted(HAPPY))
    run_dir = workflow.run(target, run_id="run_res", settings=s1, llm=llm, echo=False)
    pending = get_pending(run_dir)
    assert _summary(run_dir)["status"] == "awaiting_human"

    def approval(**kw):
        base = {"plan_id": pending.plan_id, "plan_hash": pending.plan_hash, "decision": "approve",
                "decided_by": "t"}
        return Approval(**{**base, **kw})

    graph_state._CONTEXTS.clear()
    for bad in (approval(plan_hash="0" * 64), approval(plan_id="pl_other"), approval(decision="reject")):
        with pytest.raises(workflow.DecisionRejected):
            workflow.resume("run_res", bad, settings=s1, echo=False)
    # nothing reached the validator and the pending plan is untouched
    assert not list_validations(run_dir) and not (run_dir / "attempts").exists()
    assert not (run_dir / "approvals.jsonl").exists()
    assert get_pending(run_dir).plan_id == pending.plan_id
    assert not [e for e in _trace(run_dir) if e["agent"] == "validator"]

    _decide(s1, "run_res", "approve")
    (v,) = list_validations(run_dir)
    assert v.plan_id == pending.plan_id  # Command(resume=...) re-entered the same plan, no new one was built
    assert [p.plan_id for p in list_plans(run_dir)] == [pending.plan_id]
    (line,) = (run_dir / "approvals.jsonl").read_text().splitlines()
    assert json.loads(line)["plan_hash"] == pending.plan_hash
    assert _summary(run_dir)["status"] == "done"
