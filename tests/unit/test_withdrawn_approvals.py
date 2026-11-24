"""Withdrawn approvals: approvals.jsonl stays the audit record; readers that act on or report decisions skip withdrawn ones.

Owner: Dev1. Covers core.plans.read_approvals, batch._recorded_approvals, local_pr._approval and the API list.
"""
from __future__ import annotations

import json

from guardian.agents.batch import _recorded_approvals
from guardian.core.plans import read_approvals
from guardian.tools.local_pr import _approval


def _write(run_dir, approvals, withdrawn):
    (run_dir / "approvals.jsonl").write_text("".join(json.dumps(a) + "\n" for a in approvals), encoding="utf-8")
    if withdrawn:
        (run_dir / "approvals.withdrawn.jsonl").write_text(
            "".join(json.dumps({"withdrawn": True, "plan_id": a["plan_id"], "plan_hash": a["plan_hash"],
                                "original_ts": a["ts"]}) + "\n" for a in withdrawn), encoding="utf-8")


def _a(plan, decision="approve", ts="2026-01-01T00:00:00Z", h="h1"):
    return {"plan_id": plan, "plan_hash": h, "decision": decision, "comment": None, "reason_type": None,
            "decided_by": "reviewer", "ts": ts}


def test_withdrawn_decisions_are_skipped_but_kept_on_request(tmp_path):
    a1, a2 = _a("pl_1"), _a("pl_2", ts="2026-01-01T00:00:01Z")
    _write(tmp_path, [a1, a2], [a1])
    assert [r["plan_id"] for r in read_approvals(tmp_path)] == ["pl_2"]
    full = read_approvals(tmp_path, include_withdrawn=True)
    assert [r["plan_id"] for r in full] == ["pl_1", "pl_2"] and full[0]["withdrawn"] and "withdrawn" not in full[1]
    assert "pl_1" in (tmp_path / "approvals.jsonl").read_text(encoding="utf-8")  # the audit file is untouched


def test_a_fresh_decision_after_withdrawal_counts(tmp_path):
    old, new = _a("pl_1"), _a("pl_1", ts="2026-01-02T00:00:00Z")
    _write(tmp_path, [old, new], [old])
    assert [r["ts"] for r in read_approvals(tmp_path)] == [new["ts"]]


def test_a_withdrawn_approval_cannot_validate_or_end_up_in_a_pr(tmp_path):
    a = _a("pl_1")
    _write(tmp_path, [a], [a])
    assert _recorded_approvals(tmp_path) == {}
    assert _approval(tmp_path, "pl_1") is None


def test_without_a_sidecar_nothing_changes(tmp_path):
    _write(tmp_path, [_a("pl_1")], [])
    assert _recorded_approvals(tmp_path).keys() == {"pl_1"}
    assert _approval(tmp_path, "pl_1") is not None


# --- withdrawn rejections: no memory of the rejected fix, no spent attempt, no "previous" ---------------------------
def _write_plan_validation(run_dir, plan_id):
    (run_dir / "validation").mkdir(exist_ok=True)
    (run_dir / "validation" / f"at_x.{plan_id}.json").write_text(json.dumps({"plan_id": plan_id}), encoding="utf-8")


def test_withdrawn_rejection_voids_its_plan_and_the_alternatives_built_on_it(tmp_path):
    from guardian.core.plans import voided_plan_ids
    rej, ok = _a("pl_1", "reject", "2026-01-01T00:00:00Z"), _a("pl_3", "approve", "2026-01-01T00:00:02Z")
    _write(tmp_path, [rej, ok], [rej])
    # pl_2 was proposed after the withdrawn rejection: the sidecar line says so
    with (tmp_path / "approvals.withdrawn.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"withdrawn": True, "plan_id": "pl_1", "plan_hash": "h1", "original_ts": rej["ts"],
                             "voids_plans": ["pl_2", "pl_3"]}) + "\n")
    assert voided_plan_ids(tmp_path) == {"pl_1", "pl_2"}  # pl_3 has a live decision, so it stays real history


def test_validated_plan_is_never_voided_and_without_sidecar_nothing_is(tmp_path):
    from guardian.core.plans import voided_plan_ids
    rej = _a("pl_1", "reject")
    _write(tmp_path, [rej], [])
    assert voided_plan_ids(tmp_path) == set()
    _write(tmp_path, [rej], [rej])
    assert voided_plan_ids(tmp_path) == {"pl_1"}
    _write_plan_validation(tmp_path, "pl_1")
    assert voided_plan_ids(tmp_path) == set()


def test_a_fresh_rejection_after_withdrawal_counts_again(tmp_path):
    from guardian.core.plans import voided_plan_ids
    old, new = _a("pl_1", "reject"), _a("pl_1", "reject", ts="2026-01-02T00:00:00Z")
    _write(tmp_path, [old, new], [old])
    assert voided_plan_ids(tmp_path) == set()


def test_previous_of_a_withdrawn_rejection_is_ignored(tmp_path):
    from guardian.agents.batch import _live_previous
    from guardian.core.recs import Previous, Recommendation
    rej = _a("pl_1", "reject")
    _write(tmp_path, [rej], [rej])
    mk = lambda pid, out: Recommendation(rec_id="rc", round=1, finding_ids=["f"], primary_finding_id="f", kind="fix",
                                        plan_id="pl_9", outcome="awaiting_decision",
                                        previous=Previous(plan_id=pid, outcome=out, detail="too new"))
    assert _live_previous(tmp_path, mk("pl_1", "rejected")) is None
    assert _live_previous(tmp_path, mk("pl_1", "failed")) is not None  # a failed validation is real
    assert _live_previous(tmp_path, mk("pl_2", "rejected")) is not None
    assert _live_previous(tmp_path, None) is None


def test_prepare_does_not_count_voided_plans_as_tried_or_spent(tmp_path, monkeypatch):
    import types
    from guardian.agents import batch
    plans = [types.SimpleNamespace(finding_id="f", plan_id=f"pl_{i}", attempt=i, ops=[f"op{i}"], action="upgrade")
             for i in (1, 2, 3)]
    monkeypatch.setattr(batch, "list_plans", lambda d: plans)
    monkeypatch.setattr(batch, "ops_key", lambda ops: tuple(ops))
    monkeypatch.setattr(batch, "candidates", lambda rc, m: [])
    rej = _a("pl_1", "reject")
    _write(tmp_path, [rej], [rej])
    with (tmp_path / "approvals.withdrawn.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"withdrawn": True, "plan_id": "pl_9", "plan_hash": "x", "original_ts": "z",
                             "voids_plans": ["pl_3"]}) + "\n")
    rc = types.SimpleNamespace(tool_ctx=types.SimpleNamespace(run_dir=tmp_path, budget=None))
    member = types.SimpleNamespace(finding_id="f", component_purl="p")
    prep = batch._prepare(rc, [member], None)
    assert prep.attempt == 3 and prep.tried == {("op2",)}  # pl_1 and pl_3 are voided; only pl_2 is spent
