"""G3 tool guardrails enforced by registry.call_tool (D1-04): allowlist, typed args, approval, forbidden, budget."""

import json

import pytest

from guardian.core.audit import AuditLog
from guardian.core.models import Approval, PatchOp, RemediationPlan, new_id
from guardian.core.store import JsonStore
from guardian.guardrails.approval import plan_hash
from guardian.guardrails.budgets import AgentLimit, Budget
from guardian.tools import registry
from guardian.tools.registry import FORBIDDEN_WORDS, ToolContext, call_tool

FAKE_LOCKFILE = "tests.integration.fake_tools:lockfile"


@pytest.fixture
def env(tmp_path, settings):
    run_dir = tmp_path / "run"
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{\n  "dependencies": {\n    "left-pad": "1.0.0"\n  }\n}\n')
    audit = AuditLog(run_dir, "run_t", echo=False)
    store = JsonStore(run_dir)
    ctx = ToolContext(run_id="run_t", run_dir=run_dir, repo=repo, settings=settings)
    return ctx, store, audit


def _guardrail_events(ctx):
    lines = (ctx.run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()
    return [e for e in map(json.loads, lines) if e["type"] == "guardrail"]


def _plan() -> RemediationPlan:
    plan = RemediationPlan(
        plan_id=new_id("pl"), plan_hash="", finding_id="fd_1", attempt=1, action="upgrade",
        ops=[PatchOp(op="set_dependency_version", file_path="package.json",
                     args={"name": "left-pad", "version": "1.3.0"})],
        expected_risk_reduction="removes CVE", rollback="git revert", evidence_ids=["ev_1"])
    plan.plan_hash = plan_hash(plan)
    return plan


def _apply_args(plan: RemediationPlan) -> dict:
    return {"plan_id": plan.plan_id, "attempt_id": new_id("at"),
            "ops": [op.model_dump() for op in plan.ops]}


def _approval(plan, decision="approve", **kw) -> Approval:
    base = {"plan_id": plan.plan_id, "plan_hash": plan.plan_hash, "decision": decision, "decided_by": "tester",
            "comment": "ok"}
    return Approval(**{**base, **kw})


def _assert_blocked(ctx, rule, tool):
    events = _guardrail_events(ctx)
    assert len(events) == 1
    assert events[0]["agent"] == "guardrail"
    assert events[0]["data"]["rule"] == rule and events[0]["data"]["tool"] == tool


def test_g3_1_tool_outside_agent_allowlist_is_blocked(env):
    ctx, store, audit = env
    plan = _plan()
    out = call_tool("detection", "apply_plan", None, ctx, store, audit, args=_apply_args(plan), plan=plan,
                    approval=_approval(plan))
    assert out is None
    _assert_blocked(ctx, "G3.1", "apply_plan")
    assert not (ctx.run_dir / "attempts").exists()  # nothing ran


def test_g3_1_unknown_agent_has_no_tools(env):
    ctx, store, audit = env
    assert call_tool("nobody", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit) is None
    _assert_blocked(ctx, "G3.1", "detector:lockfile")


def test_g3_1_allowlist_matches_specs():
    assert "apply_plan" in registry.allowed_tools("validator")
    assert "apply_plan" not in registry.allowed_tools("remediation")
    assert {"resolve_action_sha", "plan_preview"} <= registry.allowed_tools("remediation")
    assert "detector:lockfile" in registry.allowed_tools("validator")


@pytest.mark.parametrize("args", [
    {"action": "../x", "ref": "v1"},
    {"action": "actions/checkout", "ref": "v1; rm -rf /"},
    {"action": "actions/checkout", "ref": "a..b"},
    {"action": "actions/checkout"},
])
def test_g3_2_bad_args_are_blocked(env, args):
    ctx, store, audit = env
    assert call_tool("remediation", "resolve_action_sha", None, ctx, store, audit, args=args) is None
    _assert_blocked(ctx, "G3.2", "resolve_action_sha")
    assert not store.list_evidence()


def test_g3_2_tool_without_args_model_rejects_args(env):
    ctx, store, audit = env
    assert call_tool("detection", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit, args={"x": 1}) is None
    _assert_blocked(ctx, "G3.2", "detector:lockfile")


def test_g3_2_bad_plan_id_is_blocked(env):
    ctx, store, audit = env
    plan = _plan()
    args = {**_apply_args(plan), "plan_id": "pl_short"}
    assert call_tool("validator", "apply_plan", None, ctx, store, audit, args=args, plan=plan,
                     approval=_approval(plan)) is None
    _assert_blocked(ctx, "G3.2", "apply_plan")


def test_g3_3_apply_plan_without_approval_is_blocked(env):
    ctx, store, audit = env
    plan = _plan()
    assert call_tool("validator", "apply_plan", None, ctx, store, audit, args=_apply_args(plan)) is None
    assert call_tool("validator", "apply_plan", None, ctx, store, audit, args=_apply_args(plan), plan=plan) is None
    events = _guardrail_events(ctx)
    assert [e["data"]["rule"] for e in events] == ["G3.3", "G3.3"]
    assert not (ctx.run_dir / "attempts").exists()


def test_g3_3_reject_decision_is_blocked(env):
    ctx, store, audit = env
    plan = _plan()
    out = call_tool("validator", "apply_plan", None, ctx, store, audit, args=_apply_args(plan), plan=plan,
                    approval=_approval(plan, "reject"))
    assert out is None
    _assert_blocked(ctx, "G3.3", "apply_plan")
    assert not (ctx.run_dir / "attempts").exists()


def test_g3_3_wrong_plan_hash_is_blocked(env):
    ctx, store, audit = env
    plan = _plan()
    out = call_tool("validator", "apply_plan", None, ctx, store, audit, args=_apply_args(plan), plan=plan,
                    approval=_approval(plan, plan_hash="0" * 64))
    assert out is None
    _assert_blocked(ctx, "G3.3", "apply_plan")


def test_g3_3_plan_edited_after_approval_is_blocked(env):
    ctx, store, audit = env
    plan = _plan()
    approval = _approval(plan)
    plan.ops[0].args["version"] = "9.9.9"  # edited after the human saw it; stored hash is now stale
    out = call_tool("validator", "apply_plan", None, ctx, store, audit, args=_apply_args(plan), plan=plan,
                    approval=approval)
    assert out is None
    _assert_blocked(ctx, "G3.3", "apply_plan")


def test_g3_3_matching_approve_runs_the_write_tool(env):
    ctx, store, audit = env
    plan = _plan()
    args = _apply_args(plan)
    out = call_tool("validator", "apply_plan", None, ctx, store, audit, args=args, plan=plan,
                    approval=_approval(plan))
    assert out is not None
    assert _guardrail_events(ctx) == []
    work = ctx.run_dir / "attempts" / args["attempt_id"] / "work"
    assert '"left-pad": "1.3.0"' in (work / "package.json").read_text()
    assert '"left-pad": "1.0.0"' in (ctx.repo / "package.json").read_text()  # target untouched
    assert any(e.kind == "patch_diff" for e in store.list_evidence())


def test_g3_4_forbidden_tool_names_are_blocked(env):
    ctx, store, audit = env
    for name in ("git_push", "npm_publish", "merge_pr", "deploy_prod"):
        assert call_tool("remediation", name, FAKE_LOCKFILE, ctx, store, audit) is None
    rules = [e["data"]["rule"] for e in _guardrail_events(ctx)]
    assert rules == ["G3.4"] * 4


def test_g3_4_no_registered_tool_is_forbidden():
    names = set(registry.tool_specs())
    names |= {n for b in registry.BINDINGS.values() for n, _ in b}
    names |= {n for extra in registry.EXTRA_ALLOW.values() for n in extra}
    assert names
    assert not [n for n in names if any(w in n.lower() for w in FORBIDDEN_WORDS)]


def test_g3_6_tool_call_budget_blocks_the_next_call(env):
    ctx, store, audit = env
    ctx.budget = Budget(limits={"detection": AgentLimit(tool_calls=2, seconds=60)})
    first = call_tool("detection", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit)
    second = call_tool("detection", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit)
    third = call_tool("detection", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit)
    assert first is not None and second is not None and third is None
    _assert_blocked(ctx, "G3.6", "detector:lockfile")
    assert ctx.budget.snapshot()["tool_calls"] == {"detection": 2}


def test_g3_6_budget_is_per_agent(env):
    ctx, store, audit = env
    ctx.budget = Budget(limits={"detection": AgentLimit(1, 60), "validator": AgentLimit(1, 60)})
    assert call_tool("detection", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit) is not None
    assert call_tool("validator", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit) is not None
    assert call_tool("detection", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit) is None


def test_g3_6_wall_clock_budget_blocks(env):
    ctx, store, audit = env
    ctx.budget = Budget(limits={"detection": AgentLimit(5, 10)})
    ctx.budget.started["detection"] = -10_000.0  # started long ago on the monotonic clock
    assert call_tool("detection", "detector:lockfile", FAKE_LOCKFILE, ctx, store, audit) is None
    _assert_blocked(ctx, "G3.6", "detector:lockfile")


def test_llm_token_budget_accounting():
    b = Budget(max_llm_tokens=100)
    b.charge_tokens(60)
    b.charge_tokens(-5)  # negative charges are ignored
    assert b.tokens_left() == 40
    b.charge_tokens(500)
    assert b.tokens_left() == 0
