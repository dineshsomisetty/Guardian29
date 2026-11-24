# Document the contract for the surrounding module or callable.
"""The readable report: summary, verified fixes, decisions, open groups, score guide, method, appendix.

Builds a small synthetic batch run on disk (3 findings of one package fixed by one plan, a typosquat accepted as a
risk, a package with no fixed version, a lockfile finding left open) and checks the sections. Offline, no network.
"""

# Load json for report readable tests.
import json

# Load pytest for report readable tests.
import pytest

# Import scoring from guardian.core.
from guardian.core import scoring
# Import Approval, Evidence, Finding, FindingCategory, FindingStatus, PatchOp, RemediationPlan, RiskAssessment, RiskFactors, Scope, ValidationResult from guardian.core.models.
from guardian.core.models import (
    # Supply the next part of the expression started above.
    Approval,
    # Supply the next part of the expression started above.
    Evidence,
    # Supply the next part of the expression started above.
    Finding,
    # Supply the next part of the expression started above.
    FindingCategory,
    # Supply the next part of the expression started above.
    FindingStatus,
    # Supply the next part of the expression started above.
    PatchOp,
    # Supply the next part of the expression started above.
    RemediationPlan,
    # Supply the next part of the expression started above.
    RiskAssessment,
    # Supply the next part of the expression started above.
    RiskFactors,
    # Supply the next part of the expression started above.
    Scope,
    # Supply the next part of the expression started above.
    ValidationResult,
# Close the current expression or collection.
)
# Import append_approval, save_plan, save_risks, save_validation from guardian.core.plans.
from guardian.core.plans import append_approval, save_plan, save_risks, save_validation
# Import Recommendation, save_recs from guardian.core.recs.
from guardian.core.recs import Recommendation, save_recs
# Import compute, factor from guardian.core.scoring.
from guardian.core.scoring import compute, factor
# Import JsonStore from guardian.core.store.
from guardian.core.store import JsonStore
# Import build_report from guardian.reporting.build.
from guardian.reporting.build import build_report
# Import render_html, write_reports from guardian.reporting.render.
from guardian.reporting.render import render_html, write_reports

# Give RUN its starting value.
# The initial value is 'run_readable'.
RUN = "run_readable"


# Define _risk for report readable tests.
# Inputs include f, s, e, r, p, x.
def _risk(f: Finding, s=1.0, e=0.5, r=1.0, p=1.0, x=1.0) -> RiskAssessment:
    # Store the result of RiskFactors in factors.
    factors = RiskFactors(S=factor(s, "cvss"), E=factor(e, "epss"), R=factor(r, "called"), P=factor(p, "prod"), X=factor(x, "network"))
    # Store the result of compute in c.
    c = compute(factors)
    # Return the result of RiskAssessment to the caller.
    return RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band, confidence=c.confidence, factors=factors, summary="s")


# Define _plan for report readable tests.
# Inputs include f, action, ops, target, hash_.
def _plan(f: Finding, action: str, ops: list[PatchOp], target=None, hash_="h") -> RemediationPlan:
    # Return the result of RemediationPlan to the caller.
    return RemediationPlan(plan_id=f"pl_{f.finding_id[3:]}", plan_hash=hash_, finding_id=f.finding_id, attempt=1, action=action,
                           # Supply ops, target_version, expected_risk_reduction, rollback, evidence_ids as named arguments to the surrounding call.
                           # These names connect the values to the receiving parameters.
                           ops=ops, target_version=target, expected_risk_reduction="x", rollback="r", evidence_ids=["ev_1"])


# Apply the pytest.fixture decorator to the declaration below.
@pytest.fixture
# Define run for report readable tests.
# Inputs include tmp_path.
def run(tmp_path):
    # Store tmp_path / RUN in d.
    d = tmp_path / RUN
    # Call d.mkdir at this point.
    d.mkdir()
    # Store the result of JsonStore in store.
    store = JsonStore(d)
    # Store the result of store.add_evidence in ev.
    ev = store.add_evidence(Evidence(run_id=RUN, kind="scanner_output", source_tool="grype@t"))

    # Define mk for report readable tests.
    # Inputs include title, purl, cat, status, fixed, sev, path.
    def mk(title, purl=None, cat=FindingCategory.CVE, status=FindingStatus.OPEN, fixed=(), sev="High", path=None):
        # Store the result of Finding in f.
        f = Finding(run_id=RUN, category=cat, title=title, detector="grype@t", component_purl=purl, scope=Scope.PROD,
                    # Supply fixed_versions, severity, evidence_ids, status, file_path as named arguments to the surrounding call.
                    # These names connect the values to the receiving parameters.
                    fixed_versions=list(fixed), severity=sev, evidence_ids=[ev.evidence_id], status=status, file_path=path)
        # Return the result of store.add_finding to the caller.
        return store.add_finding(f)

    # Store values selected or transformed from the input in jwt.
    jwt = [mk(f"GHSA-{i} in jsonwebtoken@0.4.0", "pkg:npm/jsonwebtoken@0.4.0", fixed=["9.0.0"], status=FindingStatus.VERIFIED)
           # Use this clause to iterate or filter the surrounding expression.
           # The collection includes the results of the completed expression.
           for i in range(3)]
    # Store the result of mk in typo.
    typo = mk("Possible typosquat ngy-cookie", "pkg:npm/ngy-cookie@6.0.0", FindingCategory.TYPOSQUAT, FindingStatus.ACCEPTED, sev=None)
    # Store the result of mk in nofix.
    nofix = mk("GHSA-zzz in notevil@1.0.0", "pkg:npm/notevil@1.0.0", fixed=[], sev="Critical")
    # Store the result of mk in lock.
    lock = mk("No lockfile", None, FindingCategory.LOCKFILE, sev=None, path=".npmrc")
    # Store the result of mk in pol.
    pol = mk("Policy missing_lockfile", None, FindingCategory.POLICY_VIOLATION, FindingStatus.ESCALATED, sev=None)
    # Store an ordered collection in risks.
    risks = [_risk(jwt[0]), _risk(jwt[1], s=0.8), _risk(jwt[2], s=0.7), _risk(typo, s=0.9, r=0.5), _risk(nofix, s=1.0, e=0.9),
             # Supply the next part of the expression started above.
             _risk(lock, s=0.3, r=0.0, e=0.1, p=0.5, x=0.3), _risk(pol, s=0.3, r=0.0, e=0.1, p=0.5, x=0.3)]
    # Call save_risks at this point.
    save_risks(d, risks)

    # Store the result of _plan in up.
    up = _plan(jwt[0], "upgrade", [PatchOp(op="set_dependency_version", file_path="package.json",
                                           # Supply args as named arguments to the surrounding call.
                                           # These names connect the values to the receiving parameters.
                                           args={"name": "jsonwebtoken", "version": "^9.0.0"})], "9.0.0", "h1")
    # Store the result of _plan in rep.
    rep = _plan(typo, "replace", [PatchOp(op="replace_dependency", file_path="package.json",
                                          # Supply args as named arguments to the surrounding call.
                                          # These names connect the values to the receiving parameters.
                                          args={"name": "ngy-cookie", "new_name": "ngx-cookie"})], None, "h2")
    # Iterate over (up, rep).
    # Bind each item to p before processing it.
    for p in (up, rep):
        # Call save_plan at this point.
        save_plan(d, p)
    # Call append_approval at this point.
    append_approval(d, Approval(plan_id=up.plan_id, plan_hash="h1", decision="approve", decided_by="alice"))
    # Call append_approval at this point.
    append_approval(d, Approval(plan_id=rep.plan_id, plan_hash="h2", decision="accept_risk", decided_by="bob",
                                # Supply comment as named arguments to the surrounding call.
                                # These names connect the values to the receiving parameters.
                                comment="Internal fork, accepted until Q3"))
    # attempt 1 failed the build, attempt 2 passed
    # Iterate over (('at_1', False, 'failed_build'), ('at_2', True, 'verified')).
    # Bind each item to (at, ok, verdict) before processing it.
    for at, ok, verdict in (("at_1", False, "failed_build"), ("at_2", True, "verified")):
        # Call save_validation at this point.
        save_validation(d, ValidationResult(
            # Supply attempt_id, plan_id, finding_id, build_ok, unit_tests as named arguments to the surrounding call.
            # These names connect the values to the receiving parameters.
            attempt_id=at, plan_id=up.plan_id, finding_id=jwt[0].finding_id, build_ok=ok, unit_tests={"passed": 9, "failed": 1, "total": 10},
            # Supply integration_tests, target_finding_resolved, risk_before as named arguments to the surrounding call.
            # These names connect the values to the receiving parameters.
            integration_tests={"passed": 4, "failed": 0, "total": 4}, target_finding_resolved=True, risk_before=95.0,
            # Supply risk_after, verdict, final_confidence, combined, round as named arguments to the surrounding call.
            # These names connect the values to the receiving parameters.
            risk_after=0.0, verdict=verdict, final_confidence="high", combined=True, round=1))
    # Call (d / 'attempts' / 'at_2').mkdir at this point.
    (d / "attempts" / "at_2").mkdir(parents=True)
    # Call (d / 'attempts' / 'at_2' / 'PR.md').write_text at this point.
    (d / "attempts" / "at_2" / "PR.md").write_text("# Guardian fix\n\nBranch `guardian/fix-abc` @ `123` in the work copy.\n")
    # Call (d / 'sandbox_baseline.json').write_text at this point.
    (d / "sandbox_baseline.json").write_text(json.dumps({"unit_tests": {"passed": 9, "failed": 1, "total": 10},
                                                         # Provide the mapping fields integration_tests, failed, total on this line.
                                                         "integration_tests": {"passed": 4, "failed": 0, "total": 4}}))

    # Define rec for report readable tests.
    # Inputs include fids, kind, outcome, plan, reason, score.
    def rec(fids, kind, outcome, plan=None, reason=None, score=50.0):
        # Return the result of Recommendation to the caller.
        return Recommendation(rec_id=f"rc_{fids[0].finding_id[3:]}", round=1, finding_ids=[x.finding_id for x in fids],
                              # Supply primary_finding_id, kind, plan_id as named arguments to the surrounding call.
                              # These names connect the values to the receiving parameters.
                              primary_finding_id=fids[0].finding_id, kind=kind, plan_id=plan.plan_id if plan else None,
                              # Supply reason, outcome, score as named arguments to the surrounding call.
                              # These names connect the values to the receiving parameters.
                              reason=reason, outcome=outcome, score=score)
    # Call save_recs at this point.
    save_recs(d, 1, "done", None, [
        # Supply the next part of the expression started above.
        rec(jwt, "fix", "verified", up), rec([typo], "fix", "accepted", rep),
        # Supply the next part of the expression started above.
        rec([nofix], "no_alternative", "no_alternative", reason="No alternatives: no fixed version of notevil has been published"),
        # Supply the next part of the expression started above.
        rec([pol], "no_alternative", "no_alternative", reason="No alternatives: it needs a person's decision")])
    # Store an ordered collection in trace.
    trace = [{"type": "tool_call", "agent": "a", "summary": "grype", "data": {"tool": "grype"}},
             # Supply the next part of the expression started above.
             {"type": "tool_call", "agent": "a", "summary": "sandbox_validate", "data": {"tool": "sandbox_validate"}},
             # Supply the next part of the expression started above.
             {"type": "llm_call", "agent": "evidence_analyst", "summary": "x", "data": {"model": "m", "mode": "replay"}}]
    # Call (d / 'trace.jsonl').write_text at this point.
    (d / "trace.jsonl").write_text("\n".join(json.dumps(e) for e in trace) + "\n")
    # Return (d, jwt, typo, nofix, lock, pol) to the caller.
    return d, jwt, typo, nofix, lock, pol


# Exercise the expected behavior for summary counts and verdict.
def test_summary_counts_and_verdict(run):
    # Store run[0] in d.
    d = run[0]
    # Store the result of build_report in rep.
    rep = build_report(d, summary={"status": "done", "target": "shop", "llm": {"mode": "replay", "model": "m"},
                                   # Provide the mapping fields finished_at on this line.
                                   "finished_at": "2026-01-01T00:00:00+00:00"})
    # Store rep.overview.counts in c.
    c = rep.overview.counts
    # Check that the expression on this line.
    assert (c.total, c.fixed, c.accepted, c.needs_person, c.open) == (7, 3, 1, 1, 2)
    # Check that c.fixed + c.accepted + c.open + c.needs_person == c.total.
    assert c.fixed + c.accepted + c.open + c.needs_person == c.total
    # Check that sum(c.by_level.values()) == 7.
    assert sum(c.by_level.values()) == 7
    # Check that the expression on this line.
    assert "3 issues now have a verified fix" in rep.overview.verdict and rep.overview.scanned_at.startswith("2026-01-01")
    # Check that any(('replayed' in x for x in rep.overview.confidence_limits)).
    assert any("replayed" in x for x in rep.overview.confidence_limits)  # AI replayed -> stated as a limit
    # Check that 'fd_' not in rep.overview.verdict.
    assert "fd_" not in rep.overview.verdict  # no internal ids in prose


# Exercise the expected behavior for fix in plain words with checks and location.
def test_fix_in_plain_words_with_checks_and_location(run):
    # Store build_report(run[0], summary={}).fixes in fx.
    fx = build_report(run[0], summary={}).fixes
    # Check that the expression on this line.
    assert len(fx) == 1 and fx[0].finding_count == 3 and fx[0].title == "Upgrade jsonwebtoken from 0.4.0 to 9.0.0"
    # Store the result of ' '.join in text.
    text = " ".join(fx[0].checks)
    # Check that the expression on this line.
    assert "no network" in text and "same as the unchanged project" in text and "Needed 2 attempts" in text
    # Check that fx[0].score_before == 95.0 and fx[0].score_after == 0.0.
    assert fx[0].score_before == 95.0 and fx[0].score_after == 0.0
    # Check that the expression on this line.
    assert fx[0].branch == "guardian/fix-abc" and fx[0].pr_markdown == "attempts/at_2/PR.md" and "Nothing was pushed" in fx[0].location
    # Check that len(fx[0].top_titles) == 3.
    assert len(fx[0].top_titles) == 3


# Exercise the expected behavior for decisions open groups and attention.
def test_decisions_open_groups_and_attention(run):
    # Store the result of build_report in rep.
    rep = build_report(run[0], summary={})
    # Check that the expression on this line.
    assert [(x.decision, x.decided_by) for x in rep.decisions] == [("approve", "alice"), ("accept_risk", "bob")]
    # Check that the expression on this line.
    assert rep.decisions[1].comment == "Internal fork, accepted until Q3" and rep.decisions[0].result == "Fix verified"
    # Store a lookup built from the input records in groups.
    groups = {g.package: g for g in rep.open_groups}
    # Check that set(groups) == {'notevil', 'No lockfile (.npmrc)'}.
    assert set(groups) == {"notevil", "No lockfile (.npmrc)"}
    # Check that groups['notevil'].next_step.startswith(...).
    assert groups["notevil"].next_step.startswith("No fix available: no fixed version of notevil")
    # Check that the expression on this line.
    assert [g.score for g in rep.open_groups] == sorted((g.score for g in rep.open_groups), reverse=True)
    # Store values selected or transformed from the input in kinds.
    kinds = {(a.kind, a.reason) for a in rep.attention}
    # Check that ('accepted', 'Internal fork, accepted until Q3') in kinds.
    assert ("accepted", "Internal fork, accepted until Q3") in kinds
    # Check that any(...).
    assert any(a.kind == "needs_person" and a.title.startswith("Policy") for a in rep.attention)
    # Check that the expression on this line.
    assert len(rep.appendix) == 7 and rep.appendix[0].score >= rep.appendix[-1].score


# Exercise the expected behavior for score guide reads weights from scoring.
def test_score_guide_reads_weights_from_scoring(run, monkeypatch):
    # Call monkeypatch.setitem at this point.
    monkeypatch.setitem(scoring.WEIGHTS, "S", 0.55)
    # Check that the expression on this line.
    assert build_report(run[0], summary={}).score_guide.weights["S"] == 0.55
    # Call monkeypatch.undo at this point.
    monkeypatch.undo()
    # Store build_report(run[0], summary={}).score_guide in g.
    g = build_report(run[0], summary={}).score_guide
    # Check that the expression on this line.
    assert g.weights == scoring.WEIGHTS and g.bands["critical"] == "80 and above" and g.bands["low"] == "under 40"


# Exercise the expected behavior for method names what ran and what was not checked.
def test_method_names_what_ran_and_what_was_not_checked(run):
    # Store the expression on this line in m.
    m = build_report(run[0], summary={"llm": {"mode": "replay", "model": "m"}}).method
    # Check that the expression on this line.
    assert any("Grype" in x for x in m.ran) and any("sandbox" in x.lower() for x in m.ran)
    # Check that any(('replayed' in x for x in m.ai)) and m.ai_mode == 'replay'.
    assert any("replayed" in x for x in m.ai) and m.ai_mode == "replay"
    # Check that any(...).
    assert any("not rebuilt" in x or "were not rebuilt" in x for x in m.not_checked)
    # Check that the expression on this line.
    assert any("never built or tested" in x for x in m.not_checked) and len(m.guardrails) >= 6


# Exercise the expected behavior for html is self contained with anchors and old fields kept.
def test_html_is_self_contained_with_anchors_and_old_fields_kept(run):
    # Store the result of write_reports in (j, h).
    j, h = write_reports(run[0], summary={"status": "done", "target": "shop"})
    # Store the result of json.loads in doc.
    doc = json.loads(j.read_text())
    # Check that the expression on this line.
    assert set(doc) >= {"actions", "remaining_risk", "findings", "ranking"}  # backward compatible
    # Check that the expression on this line.
    assert doc["ranking"][0] == max(doc["findings"], key=lambda e: e["risk"]["score"])["finding"]["finding_id"]
    # Store the result of h.read_text in html.
    html = h.read_text()
    # Iterate over the expression on this line.
    # Bind each item to sec before processing it.
    for sec in ("summary", "fixes", "decisions", "open", "attention", "scores", "method", "appendix"):
        # Check that f'id="{sec}"' in html.
        assert f'id="{sec}"' in html
    # Check that the expression on this line.
    assert "<script" not in html and "http://" not in html and "https://" not in html
    # Check that the expression on this line.
    assert html.index('id="summary"') < html.index('id="fixes"') < html.index('id="appendix"')
    # Check that 'Internal fork, accepted until Q3' in html.
    assert "Internal fork, accepted until Q3" in html  # the decision's reason is shown
    # Check that the expression on this line.
    assert "Technical details" in html and html.index("Technical details") > html.index('id="appendix"')


# Exercise the expected behavior for sequential run without recommendations json.
def test_sequential_run_without_recommendations_json(run):
    # Store run[0] in d.
    d = run[0]
    # Call (d / 'recommendations.json').unlink at this point.
    (d / "recommendations.json").unlink()
    # Store the result of build_report in rep.
    rep = build_report(d, summary={})
    # Check that rep.overview.counts.total == 7 and len(rep.fixes) == 1.
    assert rep.overview.counts.total == 7 and len(rep.fixes) == 1
    # Check that render_html(rep).startswith('<!doctype html>').
    assert render_html(rep).startswith("<!doctype html>")
