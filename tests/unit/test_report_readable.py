"""The readable report: summary, verified fixes, decisions, open groups, score guide, method, appendix.

Builds a small synthetic batch run on disk (3 findings of one package fixed by one plan, a typosquat accepted as a
risk, a package with no fixed version, a lockfile finding left open) and checks the sections. Offline, no network.
"""

import json

import pytest

from guardian.core import scoring
from guardian.core.models import (
    Approval,
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    PatchOp,
    RemediationPlan,
    RiskAssessment,
    RiskFactors,
    Scope,
    ValidationResult,
)
from guardian.core.plans import append_approval, save_plan, save_risks, save_validation
from guardian.core.recs import Recommendation, save_recs
from guardian.core.scoring import compute, factor
from guardian.core.store import JsonStore
from guardian.reporting.build import build_report
from guardian.reporting.render import render_html, write_reports

RUN = "run_readable"


def _risk(f: Finding, s=1.0, e=0.5, r=1.0, p=1.0, x=1.0) -> RiskAssessment:
    factors = RiskFactors(S=factor(s, "cvss"), E=factor(e, "epss"), R=factor(r, "called"), P=factor(p, "prod"), X=factor(x, "network"))
    c = compute(factors)
    return RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band, confidence=c.confidence, factors=factors, summary="s")


def _plan(f: Finding, action: str, ops: list[PatchOp], target=None, hash_="h") -> RemediationPlan:
    return RemediationPlan(plan_id=f"pl_{f.finding_id[3:]}", plan_hash=hash_, finding_id=f.finding_id, attempt=1, action=action,
                           ops=ops, target_version=target, expected_risk_reduction="x", rollback="r", evidence_ids=["ev_1"])


@pytest.fixture
def run(tmp_path):
    d = tmp_path / RUN
    d.mkdir()
    store = JsonStore(d)
    ev = store.add_evidence(Evidence(run_id=RUN, kind="scanner_output", source_tool="grype@t"))

    def mk(title, purl=None, cat=FindingCategory.CVE, status=FindingStatus.OPEN, fixed=(), sev="High", path=None):
        f = Finding(run_id=RUN, category=cat, title=title, detector="grype@t", component_purl=purl, scope=Scope.PROD,
                    fixed_versions=list(fixed), severity=sev, evidence_ids=[ev.evidence_id], status=status, file_path=path)
        return store.add_finding(f)

    jwt = [mk(f"GHSA-{i} in jsonwebtoken@0.4.0", "pkg:npm/jsonwebtoken@0.4.0", fixed=["9.0.0"], status=FindingStatus.VERIFIED)
           for i in range(3)]
    typo = mk("Possible typosquat ngy-cookie", "pkg:npm/ngy-cookie@6.0.0", FindingCategory.TYPOSQUAT, FindingStatus.ACCEPTED, sev=None)
    nofix = mk("GHSA-zzz in notevil@1.0.0", "pkg:npm/notevil@1.0.0", fixed=[], sev="Critical")
    lock = mk("No lockfile", None, FindingCategory.LOCKFILE, sev=None, path=".npmrc")
    pol = mk("Policy missing_lockfile", None, FindingCategory.POLICY_VIOLATION, FindingStatus.ESCALATED, sev=None)
    risks = [_risk(jwt[0]), _risk(jwt[1], s=0.8), _risk(jwt[2], s=0.7), _risk(typo, s=0.9, r=0.5), _risk(nofix, s=1.0, e=0.9),
             _risk(lock, s=0.3, r=0.0, e=0.1, p=0.5, x=0.3), _risk(pol, s=0.3, r=0.0, e=0.1, p=0.5, x=0.3)]
    save_risks(d, risks)

    up = _plan(jwt[0], "upgrade", [PatchOp(op="set_dependency_version", file_path="package.json",
                                           args={"name": "jsonwebtoken", "version": "^9.0.0"})], "9.0.0", "h1")
    rep = _plan(typo, "replace", [PatchOp(op="replace_dependency", file_path="package.json",
                                          args={"name": "ngy-cookie", "new_name": "ngx-cookie"})], None, "h2")
    for p in (up, rep):
        save_plan(d, p)
    append_approval(d, Approval(plan_id=up.plan_id, plan_hash="h1", decision="approve", decided_by="alice"))
    append_approval(d, Approval(plan_id=rep.plan_id, plan_hash="h2", decision="accept_risk", decided_by="bob",
                                comment="Internal fork, accepted until Q3"))
    # attempt 1 failed the build, attempt 2 passed
    for at, ok, verdict in (("at_1", False, "failed_build"), ("at_2", True, "verified")):
        save_validation(d, ValidationResult(
            attempt_id=at, plan_id=up.plan_id, finding_id=jwt[0].finding_id, build_ok=ok, unit_tests={"passed": 9, "failed": 1, "total": 10},
            integration_tests={"passed": 4, "failed": 0, "total": 4}, target_finding_resolved=True, risk_before=95.0,
            risk_after=0.0, verdict=verdict, final_confidence="high", combined=True, round=1))
    (d / "attempts" / "at_2").mkdir(parents=True)
    (d / "attempts" / "at_2" / "PR.md").write_text("# Guardian fix\n\nBranch `guardian/fix-abc` @ `123` in the work copy.\n")
    (d / "sandbox_baseline.json").write_text(json.dumps({"unit_tests": {"passed": 9, "failed": 1, "total": 10},
                                                         "integration_tests": {"passed": 4, "failed": 0, "total": 4}}))

    def rec(fids, kind, outcome, plan=None, reason=None, score=50.0):
        return Recommendation(rec_id=f"rc_{fids[0].finding_id[3:]}", round=1, finding_ids=[x.finding_id for x in fids],
                              primary_finding_id=fids[0].finding_id, kind=kind, plan_id=plan.plan_id if plan else None,
                              reason=reason, outcome=outcome, score=score)
    save_recs(d, 1, "done", None, [
        rec(jwt, "fix", "verified", up), rec([typo], "fix", "accepted", rep),
        rec([nofix], "no_alternative", "no_alternative", reason="No alternatives: no fixed version of notevil has been published"),
        rec([pol], "no_alternative", "no_alternative", reason="No alternatives: it needs a person's decision")])
    trace = [{"type": "tool_call", "agent": "a", "summary": "grype", "data": {"tool": "grype"}},
             {"type": "tool_call", "agent": "a", "summary": "sandbox_validate", "data": {"tool": "sandbox_validate"}},
             {"type": "llm_call", "agent": "evidence_analyst", "summary": "x", "data": {"model": "m", "mode": "replay"}}]
    (d / "trace.jsonl").write_text("\n".join(json.dumps(e) for e in trace) + "\n")
    return d, jwt, typo, nofix, lock, pol


def test_summary_counts_and_verdict(run):
    d = run[0]
    rep = build_report(d, summary={"status": "done", "target": "shop", "llm": {"mode": "replay", "model": "m"},
                                   "finished_at": "2026-01-01T00:00:00+00:00"})
    c = rep.overview.counts
    assert (c.total, c.fixed, c.accepted, c.needs_person, c.open) == (7, 3, 1, 1, 2)
    assert c.fixed + c.accepted + c.open + c.needs_person == c.total
    assert sum(c.by_level.values()) == 7
    assert "3 issues now have a verified fix" in rep.overview.verdict and rep.overview.scanned_at.startswith("2026-01-01")
    assert any("replayed" in x for x in rep.overview.confidence_limits)  # AI replayed -> stated as a limit
    assert "fd_" not in rep.overview.verdict  # no internal ids in prose


def test_fix_in_plain_words_with_checks_and_location(run):
    fx = build_report(run[0], summary={}).fixes
    assert len(fx) == 1 and fx[0].finding_count == 3 and fx[0].title == "Upgrade jsonwebtoken from 0.4.0 to 9.0.0"
    text = " ".join(fx[0].checks)
    assert "no network" in text and "same as the unchanged project" in text and "Needed 2 attempts" in text
    assert fx[0].score_before == 95.0 and fx[0].score_after == 0.0
    assert fx[0].branch == "guardian/fix-abc" and fx[0].pr_markdown == "attempts/at_2/PR.md" and "Nothing was pushed" in fx[0].location
    assert len(fx[0].top_titles) == 3


def test_decisions_open_groups_and_attention(run):
    rep = build_report(run[0], summary={})
    assert [(x.decision, x.decided_by) for x in rep.decisions] == [("approve", "alice"), ("accept_risk", "bob")]
    assert rep.decisions[1].comment == "Internal fork, accepted until Q3" and rep.decisions[0].result == "Fix verified"
    groups = {g.package: g for g in rep.open_groups}
    assert set(groups) == {"notevil", "No lockfile (.npmrc)"}
    assert groups["notevil"].next_step.startswith("No fix available: no fixed version of notevil")
    assert [g.score for g in rep.open_groups] == sorted((g.score for g in rep.open_groups), reverse=True)
    kinds = {(a.kind, a.reason) for a in rep.attention}
    assert ("accepted", "Internal fork, accepted until Q3") in kinds
    assert any(a.kind == "needs_person" and a.title.startswith("Policy") for a in rep.attention)
    assert len(rep.appendix) == 7 and rep.appendix[0].score >= rep.appendix[-1].score


def test_score_guide_reads_weights_from_scoring(run, monkeypatch):
    monkeypatch.setitem(scoring.WEIGHTS, "S", 0.55)
    assert build_report(run[0], summary={}).score_guide.weights["S"] == 0.55
    monkeypatch.undo()
    g = build_report(run[0], summary={}).score_guide
    assert g.weights == scoring.WEIGHTS and g.bands["critical"] == "80 and above" and g.bands["low"] == "under 40"


def test_method_names_what_ran_and_what_was_not_checked(run):
    m = build_report(run[0], summary={"llm": {"mode": "replay", "model": "m"}}).method
    assert any("Grype" in x for x in m.ran) and any("sandbox" in x.lower() for x in m.ran)
    assert any("replayed" in x for x in m.ai) and m.ai_mode == "replay"
    assert any("not rebuilt" in x or "were not rebuilt" in x for x in m.not_checked)
    assert any("never built or tested" in x for x in m.not_checked) and len(m.guardrails) >= 6


def test_html_is_self_contained_with_anchors_and_old_fields_kept(run):
    j, h = write_reports(run[0], summary={"status": "done", "target": "shop"})
    doc = json.loads(j.read_text())
    assert set(doc) >= {"actions", "remaining_risk", "findings", "ranking"}  # backward compatible
    assert doc["ranking"][0] == max(doc["findings"], key=lambda e: e["risk"]["score"])["finding"]["finding_id"]
    html = h.read_text()
    for sec in ("summary", "fixes", "decisions", "open", "attention", "scores", "method", "appendix"):
        assert f'id="{sec}"' in html
    assert "<script" not in html and "http://" not in html and "https://" not in html
    assert html.index('id="summary"') < html.index('id="fixes"') < html.index('id="appendix"')
    assert "Internal fork, accepted until Q3" in html  # the decision's reason is shown
    assert "Technical details" in html and html.index("Technical details") > html.index('id="appendix"')


def test_sequential_run_without_recommendations_json(run):
    d = run[0]
    (d / "recommendations.json").unlink()
    rep = build_report(d, summary={})
    assert rep.overview.counts.total == 7 and len(rep.fixes) == 1
    assert render_html(rep).startswith("<!doctype html>")
