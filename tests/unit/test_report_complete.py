"""The Guardian Report is complete for every kind of run (D4-06, plan 17): empty, undecided, rejected / accepted risk,
failed validation, SBOM diff, factor tables, grounding removals, redaction and a JSON round trip.

Small synthetic runs written to tmp_path; offline, no sandbox, no network.
"""

import json

from guardian.core.models import (
    Approval,
    Claim,
    ClaimLabel,
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
from guardian.core.scoring import compute, factor
from guardian.core.store import JsonStore
from guardian.reporting.build import build_report
from guardian.reporting.render import render_html, write_reports
from guardian.reporting.schema import Report

SECRET = "AKIAABCDEFGHIJKLMNOP"


def _run(tmp_path, name="run_c"):
    d = tmp_path / name
    d.mkdir()
    return d, JsonStore(d)


def _finding(store, run, title="GHSA-x in lodash@4.0.0", purl="pkg:npm/lodash@4.0.0", status=FindingStatus.OPEN, claims=(),
             excerpt="grype matched lodash"):
    ev = store.add_evidence(Evidence(run_id=run, kind="scanner_output", source_tool="grype@t", excerpt=excerpt))
    f = Finding(run_id=run, category=FindingCategory.CVE, title=title, detector="grype@t", component_purl=purl, scope=Scope.PROD,
                severity="High", fixed_versions=["4.17.21"], evidence_ids=[ev.evidence_id], status=status, claims=list(claims),
                dependency_paths=[["root", "pkg:npm/express@4.0.0", purl]])
    return store.add_finding(f), ev


def _risk(f, claims=(), prov=0.0):
    fs = RiskFactors(S=factor(0.8, "cvss", ["ev_1"]), E=factor(0.5, "epss", unknown=True), R=factor(1.0, "called", ["ev_1"]),
                     P=factor(1.0, "prod", ["ev_1"]), X=factor(0.5, "unknown", unknown=True), provenance_modifier=prov)
    c = compute(fs)
    return RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band, confidence=c.confidence, factors=fs,
                          summary="Ranks high.", claims=list(claims))


def _plan(f, hash_="h1"):
    return RemediationPlan(plan_id=f"pl_{f.finding_id[3:]}", plan_hash=hash_, finding_id=f.finding_id, attempt=1, action="upgrade",
                           ops=[PatchOp(op="set_dependency_version", file_path="package.json",
                                        args={"name": "lodash", "version": "^4.17.21"})],
                           target_version="4.17.21", expected_risk_reduction="x", rollback="r", evidence_ids=["ev_1"])


def _val(f, plan, verdict="verified", at="at_1", sbom_ev=None, new=()):
    return ValidationResult(attempt_id=at, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=verdict != "failed_build",
                            unit_tests={"passed": 5, "failed": 0, "total": 5}, integration_tests={}, target_finding_resolved=verdict == "verified",
                            new_findings=list(new), sbom_diff_evidence_id=sbom_ev, risk_before=70.0,
                            risk_after=0.0 if verdict == "verified" else 70.0, verdict=verdict, final_confidence="high")


def test_empty_run_reports_cleanly(tmp_path):
    d, _ = _run(tmp_path)
    rep = build_report(d, summary={"target": "empty-app"})
    assert rep.overview.counts.total == 0 and rep.ranked == [] and rep.validations == [] and rep.final_confidence == "low"
    assert "no supply-chain issues" in rep.overview.verdict
    j, h = write_reports(d, summary={"target": "empty-app"})
    html = h.read_text(encoding="utf-8")
    assert "No fix was built or tested" in html and "No findings." in html and "No person has decided" in html
    assert "<script" not in html and "https://" not in html
    Report.model_validate_json(j.read_text(encoding="utf-8"))


def test_no_approvals_yet_is_called_out(tmp_path):
    d, store = _run(tmp_path)
    f, _ = _finding(store, "run_c")
    save_risks(d, [_risk(f)])
    p = _plan(f)
    save_plan(d, p)
    rep = build_report(d, summary={})
    assert rep.decisions == [] and rep.overview.counts.awaiting_decision == 1
    assert "waits for a person" in rep.overview.verdict and any("Decision needed" in k for k in rep.overview.key_points)
    r = rep.ranked[0]
    assert r.decision == "Waiting for a person to decide" and r.action.startswith("Upgrade lodash")
    assert "waiting; the report is rewritten" in render_html(rep)


def test_rejected_and_accepted_risk_carry_who_when_hash(tmp_path):
    d, store = _run(tmp_path)
    a, _ = _finding(store, "run_c", "A in lodash@4.0.0", "pkg:npm/lodash@4.0.0")
    b, _ = _finding(store, "run_c", "B in minimist@1.0.0", "pkg:npm/minimist@1.0.0", status=FindingStatus.ACCEPTED)
    save_risks(d, [_risk(a), _risk(b)])
    pa, pb = _plan(a, "ha"), _plan(b, "hb")
    save_plan(d, pa)
    save_plan(d, pb)
    append_approval(d, Approval(plan_id=pa.plan_id, plan_hash="ha", decision="reject", reason_type="too_big", decided_by="alice"))
    append_approval(d, Approval(plan_id=pb.plan_id, plan_hash="OLD", decision="accept_risk", comment="vendored", decided_by="bob"))
    rep = build_report(d, summary={})
    by = {x.plan_id: x for x in rep.decisions}
    assert by[pa.plan_id].plan_hash == "ha" and by[pa.plan_id].plan_hash_ok is True and by[pa.plan_id].reason_text == "too big a change"
    assert by[pb.plan_id].plan_hash_ok is False  # the plan changed after the decision: shown, not hidden
    assert rep.overview.counts.accepted == 1 and rep.overview.counts.fixed == 0 and rep.fixes == []  # accepted risk is not a fix
    assert any(a_.kind == "accepted" and a_.reason == "vendored" and a_.decided_by == "bob" for a_ in rep.attention)
    html = render_html(rep)
    assert "plan changed since" in html and "matches the plan" in html and "Rejected" in html and "Risk accepted" in html
    assert {x.finding_id: x.decision for x in rep.ranked}[a.finding_id].startswith("Rejected by alice")


def test_failed_validation_and_sbom_diff_and_new_findings(tmp_path):
    d, store = _run(tmp_path)
    f, _ = _finding(store, "run_c")
    save_risks(d, [_risk(f)])
    p = _plan(f)
    save_plan(d, p)
    append_approval(d, Approval(plan_id=p.plan_id, plan_hash="h1", decision="approve", decided_by="alice"))
    diff = store.add_evidence(Evidence(run_id="run_c", kind="sbom_diff", source_tool="guardian:sbom_diff",
                                       facts={"added": ["pkg:npm/new@1.0.0"], "removed": [], "components_before": 10, "components_after": 11,
                                              "changed": [{"name": "lodash", "from": "4.0.0", "to": "4.17.21"}]}))
    save_validation(d, _val(f, p, "failed_build", "at_1"))
    save_validation(d, _val(f, p, "verified", "at_2", diff.evidence_id, new=["vuln:GHSA-new"]))
    rep = build_report(d, summary={})
    v = {x.attempt_id: x for x in rep.validations}
    assert v["at_1"].passed is False and v["at_1"].build == "failed" and v["at_1"].verdict_text == "Failed: the build failed"
    assert v["at_2"].passed and v["at_2"].unit_tests == "5 of 5 pass" and v["at_2"].integration_tests == "not run"
    assert v["at_2"].sbom_changed == ["lodash: 4.0.0 -> 4.17.21"] and v["at_2"].sbom_added == ["pkg:npm/new@1.0.0"]
    ba = rep.before_after
    assert ba.sbom_components == [10, 11] and ba.sbom_added == 1 and ba.sbom_changed == 1
    assert ba.new_findings == ["New known vulnerability GHSA-new"]
    assert sum(ba.levels_before.values()) == 1 and sum(ba.levels_after.values()) == 0 and ba.top_after == 0
    html = render_html(rep)
    assert "Failed: the build failed" in html and "New known vulnerability GHSA-new" in html and "10" in html


def test_factor_table_recomputes_the_score_and_states_weights(tmp_path):
    d, store = _run(tmp_path)
    f, _ = _finding(store, "run_c")
    save_risks(d, [_risk(f, prov=5.0)])
    rep = build_report(d, summary={})
    r = rep.ranked[0]
    assert [x.key for x in r.factors] == ["S", "E", "R", "P", "X"] and r.provenance_points == 5.0
    assert r.score_matches is True and r.recomputed_score == r.score
    assert round(sum(x.points for x in r.factors) + r.provenance_points, 2) == r.score
    assert {x.key for x in r.factors if x.assumed} == {"E", "X"}
    html = render_html(rep)
    assert "Guardian's own choice" in html and "Provenance modifier" in html and "recompute it yourself" in html
    assert r.paths == [["project", "express@4.0.0", "lodash@4.0.0"]]  # readable dependency chain, no purls


def test_unsupported_claims_never_appear_and_labels_are_kept(tmp_path):
    d, store = _run(tmp_path)
    ok = Claim(text="Fixed in 4.17.21.", field="fixed_version", value="4.17.21", evidence_ids=["ev_1"], label=ClaimLabel.VERIFIED)
    guess = Claim(text="Probably used by the login page.", evidence_ids=[], label=ClaimLabel.INFERRED)
    bad = Claim(text="Attackers are already exploiting this at your company.", evidence_ids=[], label=ClaimLabel.UNSUPPORTED)
    f, _ = _finding(store, "run_c", claims=[ok, bad])
    save_risks(d, [_risk(f, claims=[guess, bad])])
    rep = build_report(d, summary={})
    labels = {c.text: c.label for c in rep.ranked[0].claims}
    assert labels == {"Fixed in 4.17.21.": "verified", "Probably used by the login page.": "inferred"}
    j, h = write_reports(d, summary={})
    assert "exploiting this at your company" not in j.read_text(encoding="utf-8") + h.read_text(encoding="utf-8")


def test_guardrail_events_and_audit_trail_are_listed_in_words(tmp_path):
    d, store = _run(tmp_path)
    f, _ = _finding(store, "run_c")
    save_risks(d, [_risk(f)])
    trace = [{"type": "guardrail", "agent": "evidence_analyst", "summary": "G4.6 claim removed: no evidence for 'x'", "ts": "2026-01-01T00:00:00"},
             {"type": "gate_wait", "agent": "human_gate", "summary": "Waiting for decisions on 1 fix(es)", "ts": "2026-01-01T00:01:00"},
             {"type": "gate_resume", "agent": "human_gate", "summary": "APPROVE by alice", "ts": "2026-01-01T00:02:00"},
             {"type": "tool_call", "agent": "x", "summary": "noise", "data": {"tool": "grype"}}]
    (d / "trace.jsonl").write_text("\n".join(json.dumps({"run_id": "run_c", **e}) for e in trace), encoding="utf-8")
    rep = build_report(d, summary={})
    assert rep.guardrails_triggered[0].rule == "G4.6" and "removed because no evidence" in rep.guardrails_triggered[0].text
    assert [a.kind for a in rep.audit_trail] == ["Safety rule", "Waiting for a person", "Person decided"]
    html = render_html(rep)
    assert "G4.6" in html and "Show the audit trail (3 steps)" in html and "1 guardrail event" in html


def test_secrets_are_masked_everywhere(tmp_path):
    d, store = _run(tmp_path)
    f, _ = _finding(store, "run_c", title=f"Leaked key {SECRET} in config", excerpt=f"aws_key = {SECRET}\npassword = hunter2hunter2")
    save_risks(d, [_risk(f)])
    p = _plan(f)
    save_plan(d, p)
    append_approval(d, Approval(plan_id=p.plan_id, plan_hash="h1", decision="accept_risk", comment=f"key {SECRET} rotated", decided_by="bob"))
    j, h = write_reports(d, summary={})
    text = j.read_text(encoding="utf-8") + h.read_text(encoding="utf-8")
    assert SECRET not in text and "hunter2hunter2" not in text


def test_json_round_trip_validates_against_schema(tmp_path):
    d, store = _run(tmp_path)
    f, _ = _finding(store, "run_c")
    save_risks(d, [_risk(f)])
    p = _plan(f)
    save_plan(d, p)
    append_approval(d, Approval(plan_id=p.plan_id, plan_hash="h1", decision="approve", decided_by="alice"))
    save_validation(d, _val(f, p))
    j, _ = write_reports(d, summary={"target": "app"})
    rep = Report.model_validate_json(j.read_text(encoding="utf-8"))
    again = json.loads(rep.model_dump_json())
    assert again == json.loads(j.read_text(encoding="utf-8"))
    for key in ("ranked", "validations", "before_after", "guardrails_triggered", "audit_trail", "decisions", "fixes", "overview"):
        assert key in again
    assert again["decisions"][0]["plan_hash"] == "h1" and again["ranking"] == [f.finding_id]
    # an older report.json without the additive sections still loads
    old = {k: v for k, v in again.items() if k in ("run_id", "generated_at", "findings", "ranking", "actions", "remaining_risk")}
    assert Report.model_validate(old).ranked == []
