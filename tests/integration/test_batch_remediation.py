"""Batch remediation: a recommendation for every finding, validation only after every decision, one combined
validation (with isolation when it fails), rejected / failed fixes back next round, the report once at the end.
Real detectors, the fake LLM and the fake sandbox runner from the existing rigs; no Docker, no network."""

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from langgraph.types import Command

from guardian.agents import batch
from guardian.core.models import Approval, FindingCategory
from guardian.core.plans import get_pending_batch, list_plans, list_validations
from guardian.graph import state as graph_state
from guardian.graph import workflow
from guardian.tools import sandbox
from tests.integration.test_human_gate import target  # noqa: F401
from tests.integration.test_sandbox_validator import rig  # noqa: F401
from tests.unit.test_sandbox import FakeDocker


@pytest.fixture
def s(settings):
    return replace(settings, max_plans=3, remediation_mode="batch")


def _start(target, s, fake_llm_factory, run_id):  # noqa: F811
    llm, _ = fake_llm_factory(lambda *a: '{"assessments": []}')
    return workflow.run(target, run_id=run_id, settings=s, llm=llm, echo=False)


def _json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _recs(run_dir):
    return _json(run_dir / "recommendations.json")


def _trace(run_dir):
    return [json.loads(x) for x in (run_dir / "trace.jsonl").read_text().splitlines()]


def _category(run_dir, rec):
    findings = {f["finding_id"]: f["category"] for f in _json(run_dir / "findings.json")}
    return findings[rec["primary_finding_id"]]


def _approvals(run_dir, overrides=None, default="approve"):
    """One decision per pending fix; `overrides` maps a finding category to (decision, comment)."""
    overrides = overrides or {}
    batch_ = get_pending_batch(run_dir)
    by_plan = {r["plan_id"]: r for r in _recs(run_dir)["items"] if r["plan_id"]}
    out = []
    for item in batch_["items"]:
        decision, comment, *rt = overrides.get(_category(run_dir, by_plan[item["plan_id"]]), (default, None))
        out.append(Approval(plan_id=item["plan_id"], plan_hash=item["plan_hash"], decision=decision,
                            comment=comment, reason_type=rt[0] if rt else None, decided_by="test"))
    return batch_["batch_id"], out


def _decide(settings, run_id, overrides=None, default="approve"):
    run_dir = settings.runs_dir / run_id
    batch_id, approvals = _approvals(run_dir, overrides, default)
    graph_state._CONTEXTS.clear()  # a resume is a fresh process
    return workflow.resume_batch(run_id, batch_id, approvals, settings=settings, echo=False)


def _reporter_runs(run_dir):
    return [e for e in _trace(run_dir) if e["agent"] == "reporter" and e["type"] == "agent_start"]


# ---------------------------------------------------------------- recommendations


def test_every_finding_gets_a_recommendation_or_no_alternative(target, s, fake_llm_factory, monkeypatch):  # noqa: F811
    real = batch.candidates
    monkeypatch.setattr(batch, "candidates",
                        lambda rc, f: [] if f.category is FindingCategory.UNPINNED_CI else real(rc, f))
    run_dir = _start(target, s, fake_llm_factory, "run_rec")
    summary = _json(run_dir / "run_summary.json")
    assert summary["status"] == "awaiting_human" and summary["pending_plan"] is None
    recs = _recs(run_dir)
    assert recs["status"] == "awaiting_decisions" and recs["round"] == 1
    assert summary["pending_batch"] == {"batch_id": recs["batch_id"], "round": 1, "count": 2}

    all_findings = {f["finding_id"] for f in _json(run_dir / "findings.json")}
    assert {fid for r in recs["items"] for fid in r["finding_ids"]} == all_findings  # nothing is left out
    kinds = {_category(run_dir, r): r for r in recs["items"]}
    assert set(kinds) == {"typosquat", "lockfile", "unpinned_ci"}
    assert kinds["typosquat"]["kind"] == "fix" and kinds["typosquat"]["plan_hash"]
    assert [a["action"] for a in kinds["typosquat"]["alternatives"]] == ["remove", "block"]  # untried, display only
    none = kinds["unpinned_ci"]
    assert none["kind"] == "no_alternative" and none["outcome"] == "no_alternative" and none["plan_id"] is None
    assert none["reason"].startswith("No alternatives")
    scores = [r["score"] for r in recs["items"]]
    assert scores == sorted(scores, reverse=True)  # highest risk first
    # only the fixes wait for a decision; nothing was validated or applied
    pending = get_pending_batch(run_dir)
    assert {i["plan_id"] for i in pending["items"]} == {r["plan_id"] for r in recs["items"] if r["kind"] == "fix"}
    assert len(list_plans(run_dir)) == 2 and not list_validations(run_dir) and not (run_dir / "attempts").exists()
    msgs = [e["summary"] for e in _trace(run_dir) if e["type"] == "decision"]
    assert any("Round 1: 2 recommendation(s) with a fix, 1 with no alternative" in m for m in msgs)
    assert not _reporter_runs(run_dir)  # the report waits for the last round


def test_cves_on_one_package_share_one_recommendation():
    from guardian.core.models import Finding

    def cve(vuln, purl, title):
        return Finding(run_id="r", category=FindingCategory.CVE, title=title, detector="scanner", vuln_id=vuln,
                       component_purl=purl, evidence_ids=["ev_" + "A" * 26])

    a, b = cve("CVE-1", "pkg:npm/lodash@4.0.0", "a"), cve("CVE-2", "pkg:npm/lodash@4.0.0", "b")
    c = cve("CVE-3", "pkg:npm/other@1.0.0", "c")
    groups = batch.group_findings([a, b, c], {a.finding_id: 5, b.finding_id: 9, c.finding_id: 7})
    assert [[f.vuln_id for f in g] for g in groups] == [["CVE-2", "CVE-1"], ["CVE-3"]]  # members + groups by score
    unfixable = cve("CVE-4", "pkg:npm/nofix@1.0.0", "d")
    assert "no fixed version" in batch.no_alternative_reason(unfixable)


# ---------------------------------------------------------------- nothing validates before every decision


def test_validation_waits_for_every_fix_to_be_decided(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_all")
    batch_id, approvals = _approvals(run_dir)
    assert len(approvals) == 3

    def refused(bid, decisions, match):
        graph_state._CONTEXTS.clear()
        with pytest.raises(workflow.DecisionRejected, match=match):
            workflow.resume_batch("run_all", bid, decisions, settings=s, echo=False)

    refused(batch_id, approvals[:2], "no decision yet")  # partial set
    refused(batch_id, [], "no decision yet")
    extra = Approval(plan_id="pl_" + "X" * 26, plan_hash="a" * 64, decision="approve", decided_by="t")
    refused(batch_id, [*approvals, extra], "not in this batch")
    refused(batch_id, [*approvals, approvals[0]], "more than one decision")
    refused("bt_" + "X" * 26, approvals, "pending batch is")
    refused(batch_id, [approvals[0].model_copy(update={"plan_hash": "0" * 64}), *approvals[1:]], "G5.1")
    refused(batch_id, [approvals[0].model_copy(update={"decision": "reject"}), *approvals[1:]], "G5.2")
    refused(batch_id, [approvals[0].model_copy(update={"decision": "accept_risk", "comment": "  "}),
                       *approvals[1:]], "G5.2")
    assert not list_validations(run_dir) and not (run_dir / "attempts").exists()
    assert get_pending_batch(run_dir)["batch_id"] == batch_id and not (run_dir / "approvals.jsonl").exists()

    # the graph does not trust its caller: a partial set pushed past the checks keeps the run waiting
    graph_state._CONTEXTS.clear()
    value = {"batch_id": batch_id, "decisions": [a.model_dump(mode="json") for a in approvals[:2]]}
    workflow._resume("run_all", s, None, False, Command(resume=value), "bypass attempt")
    assert _json(run_dir / "run_summary.json")["status"] == "awaiting_human"
    assert not list_validations(run_dir) and not (run_dir / "approvals.jsonl").exists()
    assert [e for e in _trace(run_dir) if e["type"] == "guardrail" and "no decision yet" in e["summary"]]
    assert _recs(run_dir)["items"][0]["decision"] is None


# ---------------------------------------------------------------- combined validation


def test_combined_validation_all_verified_report_once(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_ok")
    run_dir = _decide(s, "run_ok")
    summary = _json(run_dir / "run_summary.json")
    assert summary["status"] == "done" and "pending_batch" not in summary
    v = list_validations(run_dir)
    assert len(v) == 3 and {x.verdict for x in v} == {"verified"}
    assert len({x.attempt_id for x in v}) == 1 and all(x.combined and x.round == 1 for x in v)  # one shared attempt
    assert len(list((run_dir / "attempts").iterdir())) == 1
    work = run_dir / "attempts" / v[0].attempt_id / "work"
    assert "ngy-cookie" not in (work / "package.json").read_text()  # the typosquat fix AND the CI pin are both in
    assert "# v2" in (work / ".github/workflows/ci.yml").read_text()
    assert "ngy-cookie" in (target / "package.json").read_text()  # the target is never modified
    pr = (run_dir / "attempts" / v[0].attempt_id / "PR.md").read_text()
    assert pr.count("# Also in this PR") == 2 and "Possible typosquat" in pr
    assert {r["outcome"] for r in _recs(run_dir)["items"]} == {"verified"}
    assert _recs(run_dir)["status"] == "done"
    assert len((run_dir / "approvals.jsonl").read_text().splitlines()) == 3
    assert len(_reporter_runs(run_dir)) == 1 and (run_dir / "report.json").is_file()  # report: once, at the end
    report = _json(run_dir / "report.json")
    assert len(report["actions"]) == 3 and all(a["validations"][0]["combined"] for a in report["actions"])
    msgs = [e["summary"] for e in _trace(run_dir) if e["type"] == "decision"]
    assert any("Applying 3 approved plans together" in m for m in msgs)
    assert any("Combined validation of 3 plans" in m and "all verified together" in m for m in msgs)


class Culprit(FakeDocker):
    """Tests fail whenever the patched copy has the `replace` fix applied (ngx-cookie in package.json)."""

    def __call__(self, argv, timeout):
        if len(argv) > 1 and argv[1] == "run" and "test:server" in argv[-1]:
            mount = next((a for a in argv if a.startswith("type=bind")), "")
            if "baseline" not in mount.replace("\\", "/"):
                src = Path(re.search(r"source=([^,]+)", mount).group(1))
                self.test_exit = 1 if "ngx-cookie" in (src / "package.json").read_text() else 0
        return super().__call__(argv, timeout)


def test_combined_failure_isolates_the_culprit_and_only_it_returns(target, s, fake_llm_factory, rig):  # noqa: F811
    sandbox.set_runner(Culprit(test_exit=0))
    run_dir = _start(target, s, fake_llm_factory, "run_iso")
    run_dir = _decide(s, "run_iso")
    plans = {p.plan_id: p for p in list_plans(run_dir)}
    v = list_validations(run_dir)
    combined = [x for x in v if x.combined]
    assert len(combined) == 3 and {x.verdict for x in combined} == {"failed_tests"}
    assert len({x.attempt_id for x in combined}) == 1
    alone = {plans[x.plan_id].action + ":" + x.plan_id: x for x in v if not x.combined}
    assert len(alone) == 3 and len({x.attempt_id for x in alone.values()} | {combined[0].attempt_id}) == 4  # own attempts
    by_action = {plans[x.plan_id].action: x for x in alone.values()}
    assert by_action["replace"].verdict == "failed_tests"  # the culprit
    assert by_action["pin"].verdict == "verified"
    honest = [e for x in alone.values() if x.verdict == "verified"
              for e in [next(ev for ev in map(lambda i: _evidence(run_dir, i), x.log_evidence_ids)
                             if ev["source_tool"] == "validator")]]
    assert honest and all("combination is NOT verified" in " ".join(e["facts"]["known_limitations"]) for e in honest)
    msgs = [e["summary"] for e in _trace(run_dir) if e["type"] == "decision"]
    assert any("validating each plan alone" in m for m in msgs) and any(m.startswith("Isolation: 1 plan") for m in msgs)

    # round 2: only the culprit comes back, with its next alternative (remove), and it knows why
    summary = _json(run_dir / "run_summary.json")
    assert summary["status"] == "awaiting_human" and summary["pending_batch"]["count"] == 1
    recs = _recs(run_dir)
    assert recs["round"] == 2
    items = {_category(run_dir, r): r for r in recs["items"]}
    assert items["lockfile"]["outcome"] == "verified" and items["unpinned_ci"]["outcome"] == "verified"
    typo = items["typosquat"]
    assert typo["outcome"] == "awaiting_decision" and typo["round"] == 2 and typo["attempt"] == 2
    assert typo["previous"]["outcome"] == "failed" and "tests" in typo["previous"]["detail"]
    assert next(p for p in plans.values() if p.plan_id == typo["previous"]["plan_id"]).action == "replace"
    assert [i["plan_id"] for i in get_pending_batch(run_dir)["items"]] == [typo["plan_id"]]
    assert next(p for p in list_plans(run_dir) if p.plan_id == typo["plan_id"]).action == "remove"
    assert not _reporter_runs(run_dir)

    run_dir = _decide(s, "run_iso")  # the new alternative passes
    assert {r["outcome"] for r in _recs(run_dir)["items"]} == {"verified"}
    assert _json(run_dir / "run_summary.json")["status"] == "done" and len(_reporter_runs(run_dir)) == 1


def _evidence(run_dir, evidence_id):
    return _json(run_dir / "evidence" / f"{evidence_id}.json")


# ---------------------------------------------------------------- reject / accept_risk / attempt limit


def test_reject_comes_back_next_round_with_the_next_alternative(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_rej")
    run_dir = _decide(s, "run_rej", {"typosquat": ("reject", "code imports ngy-cookie; prefer removal")})
    v = list_validations(run_dir)
    assert len(v) == 2 and {x.verdict for x in v} == {"verified"}  # the approved ones validated together
    recs = _recs(run_dir)
    assert recs["round"] == 2 and recs["status"] == "awaiting_decisions"
    typo = next(r for r in recs["items"] if _category(run_dir, r) == "typosquat")
    assert typo["outcome"] == "awaiting_decision" and typo["decision"] is None
    assert typo["previous"] == {"plan_id": typo["previous"]["plan_id"], "outcome": "rejected",
                                "detail": "code imports ngy-cookie; prefer removal", "reason_type": None}
    assert next(p for p in list_plans(run_dir) if p.plan_id == typo["plan_id"]).action == "remove"
    assert [a["action"] for a in typo["alternatives"]] == ["block"]
    assert [i["rec_id"] for i in get_pending_batch(run_dir)["items"]] == [typo["rec_id"]]  # verified ones are done
    assert not _reporter_runs(run_dir)
    run_dir = _decide(s, "run_rej")
    assert {r["outcome"] for r in _recs(run_dir)["items"]} == {"verified"} and len(_reporter_runs(run_dir)) == 1
    decisions = [json.loads(x)["decision"] for x in (run_dir / "approvals.jsonl").read_text().splitlines()]
    assert sorted(decisions) == ["approve", "approve", "approve", "reject"]


def test_accept_risk_is_final_and_report_is_sorted_by_score(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_acc")
    run_dir = _decide(s, "run_acc", default="accept_risk",
                      overrides={c: ("accept_risk", f"accepted: {c}") for c in ("typosquat", "lockfile", "unpinned_ci")})
    recs = _recs(run_dir)
    assert recs["round"] == 1 and recs["status"] == "done"  # nothing was re-proposed
    assert {r["outcome"] for r in recs["items"]} == {"accepted"} and len(list_plans(run_dir)) == 3
    assert not list_validations(run_dir) and not (run_dir / "attempts").exists()
    assert {x["status"] for x in _json(run_dir / "findings.json")} == {"accepted"}
    assert _json(run_dir / "run_summary.json")["status"] == "done" and len(_reporter_runs(run_dir)) == 1
    remaining = _json(run_dir / "report.json")["remaining_risk"]
    assert len(remaining) == 3 and [r["score"] for r in remaining] == sorted((r["score"] for r in remaining), reverse=True)
    assert remaining[0]["score"] > remaining[-1]["score"]


def test_attempt_limit_needs_a_person(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_lim")
    run_dir = _decide(s, "run_lim", {"typosquat": ("reject", "no 1")})
    run_dir = _decide(s, "run_lim", {"typosquat": ("reject", "no 2")})
    typo = next(r for r in _recs(run_dir)["items"] if _category(run_dir, r) == "typosquat")
    assert typo["attempt"] == 3 and typo["round"] == 3  # third and last attempt
    run_dir = _decide(s, "run_lim", {"typosquat": ("reject", "no 3")})
    recs = _recs(run_dir)
    typo = next(r for r in recs["items"] if _category(run_dir, r) == "typosquat")
    assert typo["outcome"] == "needs_person" and "Attempt limit" in typo["reason"]
    assert [p.action for p in sorted((p for p in list_plans(run_dir) if p.finding_id == typo["primary_finding_id"]),
                                     key=lambda p: p.attempt)] == ["replace", "remove", "block"]  # never a 4th
    summary = _json(run_dir / "run_summary.json")
    assert summary["status"] == "done" and recs["status"] == "done" and len(_reporter_runs(run_dir)) == 1
    finding = next(f for f in _json(run_dir / "findings.json") if f["finding_id"] == typo["primary_finding_id"])
    assert finding["status"] == "escalated"
    remaining = _json(run_dir / "report.json")["remaining_risk"]
    assert [r["finding_id"] for r in remaining] == [typo["primary_finding_id"]] and "Attempt limit" in remaining[0]["note"]


def test_max_plans_zero_still_means_no_remediation(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, replace(s, max_plans=0), fake_llm_factory, "run_none")
    assert _json(run_dir / "run_summary.json")["status"] == "done"
    assert not (run_dir / "recommendations.json").exists() and not list_plans(run_dir)


def test_cli_plans_and_decide_batch(target, s, fake_llm_factory, monkeypatch, capsys, tmp_path):  # noqa: F811
    from guardian import cli

    run_dir = _start(target, s, fake_llm_factory, "run_cli")
    monkeypatch.setenv("GUARDIAN_RUNS_DIR", str(s.runs_dir))
    assert cli.main(["plans", "--run", "run_cli"]) == 0
    out = capsys.readouterr().out
    batch_id = get_pending_batch(run_dir)["batch_id"]
    assert f"Batch {batch_id}" in out and "3 fix(es) need a decision" in out and out.count("plan_hash") >= 3
    assert "alternative: remove ngy-cookie from the manifest" in out

    rows = [{"plan_id": i["plan_id"], "plan_hash": i["plan_hash"], "decision": "approve"}
            for i in get_pending_batch(run_dir)["items"]]
    partial = tmp_path / "partial.json"
    partial.write_text(json.dumps(rows[:1]))
    graph_state._CONTEXTS.clear()
    assert cli.main(["decide-batch", "--run", "run_cli", "--batch", batch_id, "--file", str(partial)]) == 2
    assert "no decision yet" in capsys.readouterr().err
    assert cli.main(["decide-batch", "--run", "run_cli", "--batch", batch_id]) == 2  # neither flag
    assert not list_validations(run_dir)

    graph_state._CONTEXTS.clear()
    assert cli.main(["decide-batch", "--run", "run_cli", "--batch", batch_id, "--approve-all", "--by", "me"]) == 0
    assert _json(run_dir / "run_summary.json")["status"] == "done"
    assert {x.verdict for x in list_validations(run_dir)} == {"verified"}


def test_round_two_applies_earlier_verified_fixes_underneath(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_carry")
    run_dir = _decide(s, "run_carry", {"typosquat": ("reject", "prefer removal")})
    round1 = {x.plan_id: x for x in list_validations(run_dir)}
    assert len(round1) == 2
    run_dir = _decide(s, "run_carry")  # round 2: only the typosquat is new
    v2 = [x for x in list_validations(run_dir) if x.round == 2]
    assert len(v2) == 3 and all(x.combined for x in v2) and len({x.attempt_id for x in v2}) == 1  # the whole set
    assert {x.plan_id for x in v2} >= set(round1)  # the round-1 plans are re-validated in the same attempt
    assert {x.verdict for x in v2} == {"verified"}
    work = run_dir / "attempts" / v2[0].attempt_id / "work"
    assert "ngy-cookie" not in (work / "package.json").read_text()
    assert "# v2" in (work / ".github/workflows/ci.yml").read_text()  # round-1 CI pin is underneath
    pr = (run_dir / "attempts" / v2[0].attempt_id / "PR.md").read_text()
    assert pr.count("# Also in this PR") == 2  # the final branch holds every verified plan
    assert {r["outcome"] for r in _recs(run_dir)["items"]} == {"verified"}
    assert len((run_dir / "approvals.jsonl").read_text().splitlines()) == 4  # carried plans reuse their approvals


class Interaction(FakeDocker):
    """Tests fail only when BOTH the typosquat removal and the CI pin are present; each passes alone."""

    def __call__(self, argv, timeout):
        if len(argv) > 1 and argv[1] == "run" and "test:server" in argv[-1]:
            mount = next((a for a in argv if a.startswith("type=bind")), "")
            if "baseline" not in mount.replace("\\", "/"):
                src = Path(re.search(r"source=([^,]+)", mount).group(1))
                both = ("ngy-cookie" not in (src / "package.json").read_text()
                        and "# v2" in (src / ".github/workflows/ci.yml").read_text())
                self.test_exit = 1 if both else 0
        return super().__call__(argv, timeout)


def test_unresolved_interaction_with_earlier_fix_sends_back_only_the_new_one(  # noqa: F811
        target, s, fake_llm_factory, rig):  # noqa: F811
    sandbox.set_runner(Interaction(test_exit=0))
    run_dir = _start(target, s, fake_llm_factory, "run_inter")
    run_dir = _decide(s, "run_inter", {"typosquat": ("reject", "prefer removal")})  # round 1 passes (no removal yet)
    assert {x.verdict for x in list_validations(run_dir)} == {"verified"}
    run_dir = _decide(s, "run_inter")  # round 2: remove + earlier CI pin fail together
    v2 = [x for x in list_validations(run_dir) if x.round == 2]
    assert {x.verdict for x in v2 if x.combined} == {"failed_tests"} and len([x for x in v2 if x.combined]) == 3
    recs = _recs(run_dir)
    items = {_category(run_dir, r): r for r in recs["items"]}
    assert items["unpinned_ci"]["outcome"] == "verified" and items["lockfile"]["outcome"] == "verified"
    typo = items["typosquat"]
    assert typo["outcome"] == "awaiting_decision" and typo["round"] == 3
    assert "interaction not resolved" in typo["previous"]["detail"]
    assert [i["rec_id"] for i in get_pending_batch(run_dir)["items"]] == [typo["rec_id"]]
    msgs = [e["summary"] for e in _trace(run_dir) if e["type"] == "decision"]
    assert any("interaction NOT resolved" in m for m in msgs)
    alone = [x for x in v2 if not x.combined and x.verdict == "verified"]
    assert len(alone) == 3


# ---------------------------------------------------------------- one dependency, one recommendation


def _cve(vuln, purl, paths=(), fixed=("9.0.0",), rng="<9.0.0", score_title="t"):
    from guardian.core.models import Finding

    return Finding(run_id="r", category=FindingCategory.CVE, title=f"{vuln} {score_title}", detector="scanner",
                   vuln_id=vuln, component_purl=purl, dependency_paths=[list(p) for p in paths],
                   fixed_versions=list(fixed), affected_range=rng, evidence_ids=["ev_" + "A" * 26])


def _upgrade(name, version):
    from guardian.agents.remediation import Candidate
    from guardian.core.models import PatchOp

    return Candidate("upgrade", [PatchOp(op="set_dependency_version", file_path="package.json",
                                         args={"name": name, "version": f"^{version}"})], version, [], "scanner")


class _Audit:
    def __init__(self):
        self.events = []

    def emit(self, agent, type, summary, **kw):
        self.events.append(summary)


def test_recommendations_editing_one_dependency_merge_into_one(monkeypatch):
    from types import SimpleNamespace

    findings = [_cve("A", "pkg:npm/express-jwt@0.1.3"), _cve("B", "pkg:npm/jsonwebtoken@0.1.0"),
                _cve("C", "pkg:npm/moment@2.0.0"), _cve("D", "pkg:npm/other@1.0.0")]
    rc = SimpleNamespace(audit=_Audit(), store=SimpleNamespace(list_findings=lambda: findings))
    scores = {findings[0].finding_id: 50, findings[1].finding_id: 90, findings[2].finding_id: 70,
              findings[3].finding_id: 10}
    preps = [batch.Prep(None, [findings[0]], 1, findings[0], [_upgrade("express-jwt", "6.0.0")]),
             batch.Prep(None, [findings[1]], 1, findings[1], [_upgrade("express-jwt", "7.7.8")]),
             batch.Prep(None, [findings[2]], 1, findings[2], [_upgrade("express-jwt", "8.5.1")]),
             batch.Prep(None, [findings[3]], 1, findings[3], [_upgrade("other", "2.0.0")])]
    still = {"8.5.1": ["jsonwebtoken GHSA-x"]}  # the highest still lets an affected child in
    monkeypatch.setattr(batch, "candidate_hits", lambda rc, c: still.get(c.target, []))
    out = batch.merge_preps(rc, preps, scores)
    assert len(out) == 2  # one for express-jwt, the unrelated one untouched
    merged = next(p for p in out if len(p.members) == 3)
    assert {m.vuln_id for m in merged.members} == {"A", "B", "C"}
    assert merged.primary.vuln_id == "B"  # highest score
    assert [c.target for c in merged.cands] == ["7.7.8", "6.0.0", "8.5.1"]  # allowed ones by version, then the rest
    assert any("Merged 3 recommendations that all edit express-jwt" in m for m in rc.audit.events)


def test_child_floor_flags_a_version_that_lets_an_affected_child_in(monkeypatch):
    from types import SimpleNamespace

    from guardian.agents import remediation as rem

    parent = "pkg:npm/express-jwt@0.1.3"
    child = _cve("GHSA-child", "pkg:npm/jsonwebtoken@0.1.0", paths=[["root", parent, "pkg:npm/jsonwebtoken@0.1.0"]],
                 fixed=("4.2.2",), rng="<9.0.0")
    rc = SimpleNamespace(store=SimpleNamespace(list_findings=lambda: [child]))
    monkeypatch.setattr(rem, "_lookup", lambda *a, **k: SimpleNamespace(facts={"child_ranges": {"6.0.0": "^8.0.0"}}))
    floor = rem.child_floor_hits(rc, parent, ["6.0.0", "8.5.1"])
    assert floor == {"6.0.0": ["jsonwebtoken GHSA-child"]}  # 6.0.0 allows jsonwebtoken 8.x, still affected


def test_two_plans_editing_one_dependency_never_share_a_run():
    from types import SimpleNamespace

    from guardian.agents.validator import Item, drop_conflicts

    def item(name, version):
        plan = SimpleNamespace(plan_id=f"pl_{name}{version}", target_version=version,
                               ops=_upgrade(name, version).ops)
        return Item(plan, None, [])

    low, high, other, earlier = item("express-jwt", "6.0.0"), item("express-jwt", "8.5.1"), item("lodash", "4.17.21"), \
        item("lodash", "4.0.0")
    kept, dropped = drop_conflicts([low, high, other], [])
    assert kept == [high, other] and [(d.plan.target_version, k.plan.target_version) for d, k in dropped] == [
        ("6.0.0", "8.5.1")]
    kept, dropped = drop_conflicts([earlier], [other])  # a plan verified in an earlier round always stays
    assert kept == [] and dropped[0][1] is other


def test_reject_reason_type_steers_or_rules_out_the_next_alternative(target, s, fake_llm_factory):  # noqa: F811
    """'Too big a change' on the typosquat replacement: remove and block are bigger changes, so nothing fits and
    the item says so instead of offering a bigger fix. 'Different kind of fix' would have moved on to remove."""
    run_dir = _start(target, s, fake_llm_factory, "run_rt")
    run_dir = _decide(s, "run_rt", {"typosquat": ("reject", "too much churn", "too_big")})
    typo = next(r for r in _recs(run_dir)["items"] if _category(run_dir, r) == "typosquat")
    assert typo["kind"] == "no_alternative" and typo["previous"]["reason_type"] == "too_big"
    assert "too big" in typo["reason"].lower() and "no smaller change" in typo["reason"]
    assert any("Rejected as 'The change is too big'" in e["summary"] for e in _trace(run_dir))

    run_dir = _start(target, s, fake_llm_factory, "run_rt2")
    run_dir = _decide(s, "run_rt2", {"typosquat": ("reject", "keep the package, try another way", "different_approach")})
    typo = next(r for r in _recs(run_dir)["items"] if _category(run_dir, r) == "typosquat")
    assert next(p for p in list_plans(run_dir) if p.plan_id == typo["plan_id"]).action == "remove"


def test_unknown_reason_type_is_refused_in_the_graph(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_rtx")
    with pytest.raises(workflow.DecisionRejected):
        _decide(s, "run_rtx", {"typosquat": ("reject", "why not", "because")})
    assert get_pending_batch(run_dir) is not None


# ---------------------------------------------------------------- one at a time (partial decisions)


def _decide_some(settings, run_id, picks, check_only=False):
    """Decide only the fixes of the given finding categories: {category: (decision, comment, reason_type)}."""
    run_dir = settings.runs_dir / run_id
    batch_ = get_pending_batch(run_dir)
    by_plan = {r["plan_id"]: r for r in _recs(run_dir)["items"] if r["plan_id"]}
    approvals = []
    for item in batch_["items"]:
        pick = picks.get(_category(run_dir, by_plan[item["plan_id"]]))
        if pick:
            decision, comment, rt = pick
            approvals.append(Approval(plan_id=item["plan_id"], plan_hash=item["plan_hash"], decision=decision,
                                      comment=comment, reason_type=rt, decided_by="test"))
    graph_state._CONTEXTS.clear()
    return workflow.resume_batch(run_id, batch_["batch_id"], approvals, settings=settings, echo=False,
                                 partial=True), approvals


def _plan_ids(run_dir):
    return {_category(run_dir, r): (r["plan_id"], r["plan_hash"]) for r in _recs(run_dir)["items"]}


def test_partial_approve_validates_only_that_one_and_the_rest_stay_pending(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_part")
    before = _plan_ids(run_dir)
    old_batch = get_pending_batch(run_dir)["batch_id"]
    run_dir, _ = _decide_some(s, "run_part", {"unpinned_ci": ("approve", None, None)})
    v = list_validations(run_dir)
    assert len(v) == 1 and v[0].verdict == "verified" and v[0].plan_id == before["unpinned_ci"][0]
    recs = _recs(run_dir)
    assert recs["step"] == 1 and recs["round"] == 1  # a partial step does not start a new round
    assert _plan_ids(run_dir) == before  # undecided items keep the same plan_id / hash
    outcomes = {_category(run_dir, r): r["outcome"] for r in recs["items"]}
    assert outcomes == {"unpinned_ci": "verified", "typosquat": "awaiting_decision", "lockfile": "awaiting_decision"}
    pending = get_pending_batch(run_dir)
    assert pending["batch_id"] != old_batch  # a NEW batch with every item still awaiting a decision
    assert {i["plan_id"] for i in pending["items"]} == {before["typosquat"][0], before["lockfile"][0]}
    assert _json(run_dir / "run_summary.json")["status"] == "awaiting_human" and not _reporter_runs(run_dir)
    msgs = [e for e in _trace(run_dir) if e["type"] == "decision" and "one at a time" in e["summary"]]
    assert msgs and msgs[0]["data"]["step"] == 1 and "2 still waiting" in msgs[0]["summary"]

    # the second step validates its fix with the first one underneath (same attempt copy holds both)
    run_dir, _ = _decide_some(s, "run_part", {"typosquat": ("approve", None, None)})
    v2 = [x for x in list_validations(run_dir) if x.attempt_id != v[0].attempt_id]
    assert len(v2) == 2 and all(x.combined for x in v2) and {x.verdict for x in v2} == {"verified"}
    work = run_dir / "attempts" / v2[0].attempt_id / "work"
    assert "# v2" in (work / ".github/workflows/ci.yml").read_text()
    assert "ngy-cookie" not in (work / "package.json").read_text()
    assert _recs(run_dir)["step"] == 2

    # finishing the last one ends the run with exactly one report
    run_dir, _ = _decide_some(s, "run_part", {"lockfile": ("accept_risk", "handled upstream", None)})
    assert _recs(run_dir)["step"] == 3 and _recs(run_dir)["status"] == "done"
    assert _json(run_dir / "run_summary.json")["status"] == "done" and len(_reporter_runs(run_dir)) == 1


def test_partial_reject_replans_only_that_item_and_keeps_a_gibberish_comment(target, s, fake_llm_factory):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_prej")
    before = _plan_ids(run_dir)
    run_dir, _ = _decide_some(s, "run_prej", {"typosquat": ("reject", "asdf qwer ;;; ???", "other")})
    recs = _recs(run_dir)
    assert recs["step"] == 1 and recs["round"] == 1 and not list_validations(run_dir)
    after = _plan_ids(run_dir)
    assert after["typosquat"][0] != before["typosquat"][0]  # only the rejected item was re-planned
    assert after["lockfile"] == before["lockfile"] and after["unpinned_ci"] == before["unpinned_ci"]
    typo = next(r for r in recs["items"] if _category(run_dir, r) == "typosquat")
    assert next(p for p in list_plans(run_dir) if p.plan_id == typo["plan_id"]).action == "remove"
    assert typo["previous"]["detail"] == "asdf qwer ;;; ???" and typo["previous"]["reason_type"] == "other"
    assert any("asdf qwer" in e["summary"] for e in _trace(run_dir) if e["type"] == "gate_resume")  # audit trail
    assert len(get_pending_batch(run_dir)["items"]) == 3  # new batch: two untouched + the re-proposal


def test_partial_submissions_are_refused_when_invalid_and_full_still_needs_every_item(  # noqa: F811
        target, s, fake_llm_factory):
    run_dir = _start(target, s, fake_llm_factory, "run_pbad")
    batch_id, approvals = _approvals(run_dir)
    first = approvals[0]

    def refused(decisions, match, partial=True):
        graph_state._CONTEXTS.clear()
        with pytest.raises(workflow.DecisionRejected, match=match):
            workflow.resume_batch("run_pbad", batch_id, decisions, settings=s, echo=False, partial=partial)

    refused([], "at least one decision")
    refused([first, first], "more than one decision")
    refused([first.model_copy(update={"plan_id": "pl_" + "X" * 26})], "not in this batch")
    refused([first.model_copy(update={"plan_hash": "0" * 64})], "G5.1")
    refused([first.model_copy(update={"decision": "reject", "comment": "", "reason_type": "other"})], "G5.2")
    refused([first.model_copy(update={"decision": "reject", "comment": "x", "reason_type": "nonsense"})], "reason type")
    refused([first], "no decision yet", partial=False)  # a full submission still requires every item
    assert not list_validations(run_dir) and get_pending_batch(run_dir)["batch_id"] == batch_id

    # and the graph re-checks: an invalid partial pushed past the entry points leaves the run waiting
    graph_state._CONTEXTS.clear()
    bad = first.model_copy(update={"plan_hash": "0" * 64})
    value = {"batch_id": batch_id, "partial": True, "decisions": [bad.model_dump(mode="json")]}
    workflow._resume("run_pbad", s, None, False, Command(resume=value), "bypass attempt")
    assert _json(run_dir / "run_summary.json")["status"] == "awaiting_human" and not list_validations(run_dir)


# ---------------------------------------------------------------- lockfile plan + manifest edits in one run


class StaleLock(FakeDocker):
    """`npm ci` analogue: tests fail when package.json declares ngx-cookie but the lockfile does not."""

    def __call__(self, argv, timeout):
        if len(argv) > 1 and argv[1] == "run" and "test:server" in argv[-1]:
            mount = next((a for a in argv if a.startswith("type=bind")), "")
            if "baseline" not in mount.replace("\\", "/"):
                src = Path(re.search(r"source=([^,]+)", mount).group(1))
                deps = json.loads((src / "package.json").read_text()).get("dependencies", {})
                lock = src / "package-lock.json"
                locked = (json.loads(lock.read_text()).get("packages", {}).get("", {}).get("dependencies", {})
                          if lock.exists() else {})
                self.test_exit = 1 if "ngx-cookie" in deps and "ngx-cookie" not in locked else 0
        return super().__call__(argv, timeout)


@pytest.fixture
def lock_rig(rig, monkeypatch):  # noqa: F811
    from guardian.tools import resolve
    from guardian.tools.registry import ToolOutput

    seen = {"lock_existed": []}

    def fake_resolve(ctx):  # what npm install --package-lock-only does when seeded: lock follows the manifest
        lock = ctx.work_dir / "package-lock.json"
        seen["lock_existed"].append(lock.exists())
        if not lock.exists():
            deps = json.loads((ctx.work_dir / "package.json").read_text()).get("dependencies", {})
            lock.write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": deps}}}))
        return ToolOutput()

    monkeypatch.setattr(resolve, "resolve_lockfiles", fake_resolve)
    sandbox.set_runner(StaleLock(test_exit=0))
    return seen


def test_lockfile_plan_is_regenerated_from_patched_manifests(target, s, fake_llm_factory, lock_rig):  # noqa: F811
    run_dir = _start(target, s, fake_llm_factory, "run_lock")
    run_dir = _decide(s, "run_lock")  # replace ngy-cookie -> ngx-cookie + generate_lockfile (+ CI pin) together
    v = list_validations(run_dir)
    assert len(v) == 3 and {x.verdict for x in v} == {"verified"} and all(x.combined for x in v)
    assert lock_rig["lock_existed"] == [False]  # the stale copy was dropped before resolving
    work = run_dir / "attempts" / v[0].attempt_id / "work"
    assert "ngx-cookie" in json.loads((work / "package-lock.json").read_text())["packages"][""]["dependencies"]
    assert any("would be stale" in e["summary"] for e in _trace(run_dir) if e["type"] == "decision")


def test_carried_lockfile_plan_is_regenerated_under_a_later_manifest_edit(  # noqa: F811
        target, s, fake_llm_factory, lock_rig):
    run_dir = _start(target, s, fake_llm_factory, "run_lock2")
    run_dir, _ = _decide_some(s, "run_lock2", {"lockfile": ("approve", None, None)})  # verified alone, lock as copied
    assert lock_rig["lock_existed"] == []
    run_dir, _ = _decide_some(s, "run_lock2", {"typosquat": ("approve", None, None)})  # replace, lockfile carried
    v = [x for x in list_validations(run_dir) if x.round == 1 and x.combined]
    assert len(v) == 2 and {x.verdict for x in v} == {"verified"}  # stale locks would have failed the build
    assert lock_rig["lock_existed"] == [False]
