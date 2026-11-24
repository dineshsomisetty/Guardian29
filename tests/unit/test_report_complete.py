# Document the contract for the surrounding module or callable.
"""The Guardian Report is complete for every kind of run (D4-06, plan 17): empty, undecided, rejected / accepted risk,
failed validation, SBOM diff, factor tables, grounding removals, redaction and a JSON round trip.

Small synthetic runs written to tmp_path; offline, no sandbox, no network.
"""

# Load json for report complete tests.
import json

# Import Approval, Claim, ClaimLabel, Evidence, Finding, FindingCategory, FindingStatus, PatchOp, RemediationPlan, RiskAssessment, RiskFactors, Scope, ValidationResult from guardian.core.models.
from guardian.core.models import (
    # Supply the next part of the expression started above.
    Approval,
    # Supply the next part of the expression started above.
    Claim,
    # Supply the next part of the expression started above.
    ClaimLabel,
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
# Import compute, factor from guardian.core.scoring.
from guardian.core.scoring import compute, factor
# Import JsonStore from guardian.core.store.
from guardian.core.store import JsonStore
# Import build_report from guardian.reporting.build.
from guardian.reporting.build import build_report
# Import render_html, write_reports from guardian.reporting.render.
from guardian.reporting.render import render_html, write_reports
# Import Report from guardian.reporting.schema.
from guardian.reporting.schema import Report

# Give SECRET its starting value.
# The initial value is 'AKIAABCDEFGHIJKLMNOP'.
SECRET = "AKIAABCDEFGHIJKLMNOP"


# Define _run for report complete tests.
# Inputs include tmp_path, name.
def _run(tmp_path, name="run_c"):
    # Store tmp_path / name in d.
    d = tmp_path / name
    # Call d.mkdir at this point.
    d.mkdir()
    # Return (d, JsonStore(d)) to the caller.
    return d, JsonStore(d)


# Define _finding for report complete tests.
# Inputs include store, run, title, purl, status, claims, excerpt.
def _finding(store, run, title="GHSA-x in lodash@4.0.0", purl="pkg:npm/lodash@4.0.0", status=FindingStatus.OPEN, claims=(),
             # Supply excerpt as named arguments to the surrounding call.
             # These names connect the values to the receiving parameters.
             excerpt="grype matched lodash"):
    # Store the result of store.add_evidence in ev.
    ev = store.add_evidence(Evidence(run_id=run, kind="scanner_output", source_tool="grype@t", excerpt=excerpt))
    # Store the result of Finding in f.
    f = Finding(run_id=run, category=FindingCategory.CVE, title=title, detector="grype@t", component_purl=purl, scope=Scope.PROD,
                # Supply severity, fixed_versions, evidence_ids, status, claims as named arguments to the surrounding call.
                # These names connect the values to the receiving parameters.
                severity="High", fixed_versions=["4.17.21"], evidence_ids=[ev.evidence_id], status=status, claims=list(claims),
                # Supply dependency_paths as named arguments to the surrounding call.
                # These names connect the values to the receiving parameters.
                dependency_paths=[["root", "pkg:npm/express@4.0.0", purl]])
    # Return (store.add_finding(f), ev) to the caller.
    return store.add_finding(f), ev


# Define _risk for report complete tests.
# Inputs include f, claims, prov.
def _risk(f, claims=(), prov=0.0):
    # Store the result of RiskFactors in fs.
    fs = RiskFactors(S=factor(0.8, "cvss", ["ev_1"]), E=factor(0.5, "epss", unknown=True), R=factor(1.0, "called", ["ev_1"]),
                     # Supply P, X, unknown, provenance_modifier as named arguments to the surrounding call.
                     # These names connect the values to the receiving parameters.
                     P=factor(1.0, "prod", ["ev_1"]), X=factor(0.5, "unknown", unknown=True), provenance_modifier=prov)
    # Store the result of compute in c.
    c = compute(fs)
    # Return the result of RiskAssessment to the caller.
    return RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band, confidence=c.confidence, factors=fs,
                          # Supply summary, claims as named arguments to the surrounding call.
                          # These names connect the values to the receiving parameters.
                          summary="Ranks high.", claims=list(claims))


# Define _plan for report complete tests.
# Inputs include f, hash_.
def _plan(f, hash_="h1"):
    # Return the result of RemediationPlan to the caller.
    return RemediationPlan(plan_id=f"pl_{f.finding_id[3:]}", plan_hash=hash_, finding_id=f.finding_id, attempt=1, action="upgrade",
                           # Supply ops, file_path as named arguments to the surrounding call.
                           # These names connect the values to the receiving parameters.
                           ops=[PatchOp(op="set_dependency_version", file_path="package.json",
                                        # Supply args as named arguments to the surrounding call.
                                        # These names connect the values to the receiving parameters.
                                        args={"name": "lodash", "version": "^4.17.21"})],
                           # Supply target_version, expected_risk_reduction, rollback, evidence_ids as named arguments to the surrounding call.
                           # These names connect the values to the receiving parameters.
                           target_version="4.17.21", expected_risk_reduction="x", rollback="r", evidence_ids=["ev_1"])


# Define _val for report complete tests.
# Inputs include f, plan, verdict, at, sbom_ev, new.
def _val(f, plan, verdict="verified", at="at_1", sbom_ev=None, new=()):
    # Return the result of ValidationResult to the caller.
    return ValidationResult(attempt_id=at, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=verdict != "failed_build",
                            # Supply unit_tests, integration_tests, target_finding_resolved as named arguments to the surrounding call.
                            # These names connect the values to the receiving parameters.
                            unit_tests={"passed": 5, "failed": 0, "total": 5}, integration_tests={}, target_finding_resolved=verdict == "verified",
                            # Supply new_findings, sbom_diff_evidence_id, risk_before as named arguments to the surrounding call.
                            # These names connect the values to the receiving parameters.
                            new_findings=list(new), sbom_diff_evidence_id=sbom_ev, risk_before=70.0,
                            # Supply risk_after, verdict, final_confidence as named arguments to the surrounding call.
                            # These names connect the values to the receiving parameters.
                            risk_after=0.0 if verdict == "verified" else 70.0, verdict=verdict, final_confidence="high")


# Exercise the expected behavior for empty run reports cleanly.
def test_empty_run_reports_cleanly(tmp_path):
    # Store the result of _run in (d, _).
    d, _ = _run(tmp_path)
    # Store the result of build_report in rep.
    rep = build_report(d, summary={"target": "empty-app"})
    # Check that the expression on this line.
    assert rep.overview.counts.total == 0 and rep.ranked == [] and rep.validations == [] and rep.final_confidence == "low"
    # Check that 'no supply-chain issues' in rep.overview.verdict.
    assert "no supply-chain issues" in rep.overview.verdict
    # Store the result of write_reports in (j, h).
    j, h = write_reports(d, summary={"target": "empty-app"})
    # Store the result of h.read_text in html.
    html = h.read_text(encoding="utf-8")
    # Check that the expression on this line.
    assert "No fix was built or tested" in html and "No findings." in html and "No person has decided" in html
    # Check that '<script' not in html and 'https://' not in html.
    assert "<script" not in html and "https://" not in html
    # Call Report.model_validate_json at this point.
    Report.model_validate_json(j.read_text(encoding="utf-8"))


# Exercise the expected behavior for no approvals yet is called out.
def test_no_approvals_yet_is_called_out(tmp_path):
    # Store the result of _run in (d, store).
    d, store = _run(tmp_path)
    # Store the result of _finding in (f, _).
    f, _ = _finding(store, "run_c")
    # Call save_risks at this point.
    save_risks(d, [_risk(f)])
    # Store the result of _plan in p.
    p = _plan(f)
    # Call save_plan at this point.
    save_plan(d, p)
    # Store the result of build_report in rep.
    rep = build_report(d, summary={})
    # Check that the expression on this line.
    assert rep.decisions == [] and rep.overview.counts.awaiting_decision == 1
    # Check that the expression on this line.
    assert "waits for a person" in rep.overview.verdict and any("Decision needed" in k for k in rep.overview.key_points)
    # Store rep.ranked[0] in r.
    r = rep.ranked[0]
    # Check that the expression on this line.
    assert r.decision == "Waiting for a person to decide" and r.action.startswith("Upgrade lodash")
    # Check that 'waiting; the report is rewritten' in render_html(rep).
    assert "waiting; the report is rewritten" in render_html(rep)


# Exercise the expected behavior for rejected and accepted risk carry who when hash.
def test_rejected_and_accepted_risk_carry_who_when_hash(tmp_path):
    # Store the result of _run in (d, store).
    d, store = _run(tmp_path)
    # Store the result of _finding in (a, _).
    a, _ = _finding(store, "run_c", "A in lodash@4.0.0", "pkg:npm/lodash@4.0.0")
    # Store the result of _finding in (b, _).
    b, _ = _finding(store, "run_c", "B in minimist@1.0.0", "pkg:npm/minimist@1.0.0", status=FindingStatus.ACCEPTED)
    # Call save_risks at this point.
    save_risks(d, [_risk(a), _risk(b)])
    # Store (_plan(a, 'ha'), _plan(b, 'hb')) in (pa, pb).
    pa, pb = _plan(a, "ha"), _plan(b, "hb")
    # Call save_plan at this point.
    save_plan(d, pa)
    # Call save_plan at this point.
    save_plan(d, pb)
    # Call append_approval at this point.
    append_approval(d, Approval(plan_id=pa.plan_id, plan_hash="ha", decision="reject", reason_type="too_big", decided_by="alice"))
    # Call append_approval at this point.
    append_approval(d, Approval(plan_id=pb.plan_id, plan_hash="OLD", decision="accept_risk", comment="vendored", decided_by="bob"))
    # Store the result of build_report in rep.
    rep = build_report(d, summary={})
    # Store a lookup built from the input records in by.
    by = {x.plan_id: x for x in rep.decisions}
    # Check that the expression on this line.
    assert by[pa.plan_id].plan_hash == "ha" and by[pa.plan_id].plan_hash_ok is True and by[pa.plan_id].reason_text == "too big a change"
    # Check that by[pb.plan_id].plan_hash_ok is False.
    assert by[pb.plan_id].plan_hash_ok is False  # the plan changed after the decision: shown, not hidden
    # Check that the expression on this line.
    assert rep.overview.counts.accepted == 1 and rep.overview.counts.fixed == 0 and rep.fixes == []  # accepted risk is not a fix
    # Check that any(...).
    assert any(a_.kind == "accepted" and a_.reason == "vendored" and a_.decided_by == "bob" for a_ in rep.attention)
    # Store the result of render_html in html.
    html = render_html(rep)
    # Check that the expression on this line.
    assert "plan changed since" in html and "matches the plan" in html and "Rejected" in html and "Risk accepted" in html
    # Check that the expression on this line(...).
    assert {x.finding_id: x.decision for x in rep.ranked}[a.finding_id].startswith("Rejected by alice")


# Exercise the expected behavior for failed validation and sbom diff and new findings.
def test_failed_validation_and_sbom_diff_and_new_findings(tmp_path):
    # Store the result of _run in (d, store).
    d, store = _run(tmp_path)
    # Store the result of _finding in (f, _).
    f, _ = _finding(store, "run_c")
    # Call save_risks at this point.
    save_risks(d, [_risk(f)])
    # Store the result of _plan in p.
    p = _plan(f)
    # Call save_plan at this point.
    save_plan(d, p)
    # Call append_approval at this point.
    append_approval(d, Approval(plan_id=p.plan_id, plan_hash="h1", decision="approve", decided_by="alice"))
    # Store the result of store.add_evidence in diff.
    diff = store.add_evidence(Evidence(run_id="run_c", kind="sbom_diff", source_tool="guardian:sbom_diff",
                                       # Supply facts as named arguments to the surrounding call.
                                       # These names connect the values to the receiving parameters.
                                       facts={"added": ["pkg:npm/new@1.0.0"], "removed": [], "components_before": 10, "components_after": 11,
                                              # Provide the mapping fields changed, from, to on this line.
                                              "changed": [{"name": "lodash", "from": "4.0.0", "to": "4.17.21"}]}))
    # Call save_validation at this point.
    save_validation(d, _val(f, p, "failed_build", "at_1"))
    # Call save_validation at this point.
    save_validation(d, _val(f, p, "verified", "at_2", diff.evidence_id, new=["vuln:GHSA-new"]))
    # Store the result of build_report in rep.
    rep = build_report(d, summary={})
    # Store a lookup built from the input records in v.
    v = {x.attempt_id: x for x in rep.validations}
    # Check that the expression on this line.
    assert v["at_1"].passed is False and v["at_1"].build == "failed" and v["at_1"].verdict_text == "Failed: the build failed"
    # Check that the expression on this line.
    assert v["at_2"].passed and v["at_2"].unit_tests == "5 of 5 pass" and v["at_2"].integration_tests == "not run"
    # Check that the expression on this line.
    assert v["at_2"].sbom_changed == ["lodash: 4.0.0 -> 4.17.21"] and v["at_2"].sbom_added == ["pkg:npm/new@1.0.0"]
    # Store rep.before_after in ba.
    ba = rep.before_after
    # Check that the expression on this line.
    assert ba.sbom_components == [10, 11] and ba.sbom_added == 1 and ba.sbom_changed == 1
    # Check that ba.new_findings == ['New known vulnerability GHSA-new'].
    assert ba.new_findings == ["New known vulnerability GHSA-new"]
    # Check that the expression on this line.
    assert sum(ba.levels_before.values()) == 1 and sum(ba.levels_after.values()) == 0 and ba.top_after == 0
    # Store the result of render_html in html.
    html = render_html(rep)
    # Check that the expression on this line.
    assert "Failed: the build failed" in html and "New known vulnerability GHSA-new" in html and "10" in html


# Exercise the expected behavior for factor table recomputes the score and states weights.
def test_factor_table_recomputes_the_score_and_states_weights(tmp_path):
    # Store the result of _run in (d, store).
    d, store = _run(tmp_path)
    # Store the result of _finding in (f, _).
    f, _ = _finding(store, "run_c")
    # Call save_risks at this point.
    save_risks(d, [_risk(f, prov=5.0)])
    # Store the result of build_report in rep.
    rep = build_report(d, summary={})
    # Store rep.ranked[0] in r.
    r = rep.ranked[0]
    # Check that the expression on this line.
    assert [x.key for x in r.factors] == ["S", "E", "R", "P", "X"] and r.provenance_points == 5.0
    # Check that r.score_matches is True and r.recomputed_score == r.score.
    assert r.score_matches is True and r.recomputed_score == r.score
    # Check that the expression on this line.
    assert round(sum(x.points for x in r.factors) + r.provenance_points, 2) == r.score
    # Check that {x.key for x in r.factors if x.assumed} == {'E', 'X'}.
    assert {x.key for x in r.factors if x.assumed} == {"E", "X"}
    # Store the result of render_html in html.
    html = render_html(rep)
    # Check that the expression on this line.
    assert "Guardian's own choice" in html and "Provenance modifier" in html and "recompute it yourself" in html
    # Check that r.paths == [['project', 'express@4.0.0', 'lodash@4.0.0']].
    assert r.paths == [["project", "express@4.0.0", "lodash@4.0.0"]]  # readable dependency chain, no purls


# Exercise the expected behavior for unsupported claims never appear and labels are kept.
def test_unsupported_claims_never_appear_and_labels_are_kept(tmp_path):
    # Store the result of _run in (d, store).
    d, store = _run(tmp_path)
    # Store the result of Claim in ok.
    ok = Claim(text="Fixed in 4.17.21.", field="fixed_version", value="4.17.21", evidence_ids=["ev_1"], label=ClaimLabel.VERIFIED)
    # Store the result of Claim in guess.
    guess = Claim(text="Probably used by the login page.", evidence_ids=[], label=ClaimLabel.INFERRED)
    # Store the result of Claim in bad.
    bad = Claim(text="Attackers are already exploiting this at your company.", evidence_ids=[], label=ClaimLabel.UNSUPPORTED)
    # Store the result of _finding in (f, _).
    f, _ = _finding(store, "run_c", claims=[ok, bad])
    # Call save_risks at this point.
    save_risks(d, [_risk(f, claims=[guess, bad])])
    # Store the result of build_report in rep.
    rep = build_report(d, summary={})
    # Store a lookup built from the input records in labels.
    labels = {c.text: c.label for c in rep.ranked[0].claims}
    # Check that the expression on this line.
    assert labels == {"Fixed in 4.17.21.": "verified", "Probably used by the login page.": "inferred"}
    # Store the result of write_reports in (j, h).
    j, h = write_reports(d, summary={})
    # Check that the expression on this line.
    assert "exploiting this at your company" not in j.read_text(encoding="utf-8") + h.read_text(encoding="utf-8")


# Exercise the expected behavior for guardrail events and audit trail are listed in words.
def test_guardrail_events_and_audit_trail_are_listed_in_words(tmp_path):
    # Store the result of _run in (d, store).
    d, store = _run(tmp_path)
    # Store the result of _finding in (f, _).
    f, _ = _finding(store, "run_c")
    # Call save_risks at this point.
    save_risks(d, [_risk(f)])
    # Store an ordered collection in trace.
    trace = [{"type": "guardrail", "agent": "evidence_analyst", "summary": "G4.6 claim removed: no evidence for 'x'", "ts": "2026-01-01T00:00:00"},
             # Supply the next part of the expression started above.
             {"type": "gate_wait", "agent": "human_gate", "summary": "Waiting for decisions on 1 fix(es)", "ts": "2026-01-01T00:01:00"},
             # Supply the next part of the expression started above.
             {"type": "gate_resume", "agent": "human_gate", "summary": "APPROVE by alice", "ts": "2026-01-01T00:02:00"},
             # Supply the next part of the expression started above.
             {"type": "tool_call", "agent": "x", "summary": "noise", "data": {"tool": "grype"}}]
    # Call (d / 'trace.jsonl').write_text at this point.
    (d / "trace.jsonl").write_text("\n".join(json.dumps({"run_id": "run_c", **e}) for e in trace), encoding="utf-8")
    # Store the result of build_report in rep.
    rep = build_report(d, summary={})
    # Check that the expression on this line.
    assert rep.guardrails_triggered[0].rule == "G4.6" and "removed because no evidence" in rep.guardrails_triggered[0].text
    # Check that the expression on this line.
    assert [a.kind for a in rep.audit_trail] == ["Safety rule", "Waiting for a person", "Person decided"]
    # Store the result of render_html in html.
    html = render_html(rep)
    # Check that the expression on this line.
    assert "G4.6" in html and "Show the audit trail (3 steps)" in html and "1 guardrail event" in html


# Exercise the expected behavior for secrets are masked everywhere.
def test_secrets_are_masked_everywhere(tmp_path):
    # Store the result of _run in (d, store).
    d, store = _run(tmp_path)
    # Store the result of _finding in (f, _).
    f, _ = _finding(store, "run_c", title=f"Leaked key {SECRET} in config", excerpt=f"aws_key = {SECRET}\npassword = hunter2hunter2")
    # Call save_risks at this point.
    save_risks(d, [_risk(f)])
    # Store the result of _plan in p.
    p = _plan(f)
    # Call save_plan at this point.
    save_plan(d, p)
    # Call append_approval at this point.
    append_approval(d, Approval(plan_id=p.plan_id, plan_hash="h1", decision="accept_risk", comment=f"key {SECRET} rotated", decided_by="bob"))
    # Store the result of write_reports in (j, h).
    j, h = write_reports(d, summary={})
    # Store j.read_text(encoding='utf-8') + h.read_text(encoding='utf-8') in text.
    text = j.read_text(encoding="utf-8") + h.read_text(encoding="utf-8")
    # Check that SECRET not in text and 'hunter2hunter2' not in text.
    assert SECRET not in text and "hunter2hunter2" not in text


# Exercise the expected behavior for json round trip validates against schema.
def test_json_round_trip_validates_against_schema(tmp_path):
    # Store the result of _run in (d, store).
    d, store = _run(tmp_path)
    # Store the result of _finding in (f, _).
    f, _ = _finding(store, "run_c")
    # Call save_risks at this point.
    save_risks(d, [_risk(f)])
    # Store the result of _plan in p.
    p = _plan(f)
    # Call save_plan at this point.
    save_plan(d, p)
    # Call append_approval at this point.
    append_approval(d, Approval(plan_id=p.plan_id, plan_hash="h1", decision="approve", decided_by="alice"))
    # Call save_validation at this point.
    save_validation(d, _val(f, p))
    # Store the result of write_reports in (j, _).
    j, _ = write_reports(d, summary={"target": "app"})
    # Store the result of Report.model_validate_json in rep.
    rep = Report.model_validate_json(j.read_text(encoding="utf-8"))
    # Store the result of json.loads in again.
    again = json.loads(rep.model_dump_json())
    # Check that again == json.loads(j.read_text(encoding='utf-8')).
    assert again == json.loads(j.read_text(encoding="utf-8"))
    # Iterate over the expression on this line.
    # Bind each item to key before processing it.
    for key in ("ranked", "validations", "before_after", "guardrails_triggered", "audit_trail", "decisions", "fixes", "overview"):
        # Check that key in again.
        assert key in again
    # Check that the expression on this line.
    assert again["decisions"][0]["plan_hash"] == "h1" and again["ranking"] == [f.finding_id]
    # an older report.json without the additive sections still loads
    # Store a lookup built from the input records in old.
    old = {k: v for k, v in again.items() if k in ("run_id", "generated_at", "findings", "ranking", "actions", "remaining_risk")}
    # Check that Report.model_validate(old).ranked == [].
    assert Report.model_validate(old).ranked == []
