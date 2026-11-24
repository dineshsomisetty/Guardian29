"""D1-06/D1-07/D1-09: risk analyst, CVE remediation candidates, report. Offline, no network."""

import json
from dataclasses import replace

import pytest

from guardian.agents import remediation as rem
from guardian.agents import risk_analyst as ra
from guardian.core.audit import AuditLog
from guardian.core.models import (
    Approval,
    Evidence,
    Finding,
    FindingCategory,
    RemediationPlan,
    RiskFactors,
    Scope,
    ValidationResult,
)
from guardian.core.plans import list_plans, load_risks, save_validation
from guardian.core.scoring import compute, factor, simulate_after
from guardian.core.store import JsonStore
from guardian.graph.state import RunContext, register, unregister
from guardian.guardrails.budgets import Budget
from guardian.reporting.build import build_report
from guardian.reporting.render import render_html, write_reports
from guardian.tools.registry import ToolContext

PURL = "pkg:npm/jsonwebtoken@0.4.0"
RUN = "run_unit"


@pytest.fixture
def rc(tmp_path, settings, monkeypatch):
    monkeypatch.setenv("GUARDIAN_INTEL_CACHE", str(tmp_path / "intel"))
    repo = tmp_path / "shop"
    (repo / "routes").mkdir(parents=True)
    (repo / "package.json").write_text('{\n  "dependencies": {\n    "jsonwebtoken": "0.4.0"\n  }\n}\n')
    (repo / "routes" / "login.js").write_text("const jwt = require('jsonwebtoken')\n")
    (repo / "Dockerfile").write_text("FROM node:20\nEXPOSE 3000\n")
    run_dir = tmp_path / "runs" / RUN
    run_dir.mkdir(parents=True)
    s = replace(settings, offline=True, max_plans=2)
    ctx = ToolContext(run_id=RUN, run_dir=run_dir, repo=repo, settings=s, work_dir=repo, budget=Budget())
    rc = RunContext(tool_ctx=ctx, store=JsonStore(run_dir), audit=AuditLog(run_dir, RUN, echo=False), llm=None)
    register(rc)
    yield rc
    unregister(RUN)


def cve(rc, fixed=("9.0.0", "9.0.2"), paths=None):
    ev = Evidence(run_id=RUN, kind="scanner_output", source_tool="grype@t",
                  facts={"vuln_id": "GHSA-aaaa", "aliases": ["CVE-2022-23539"], "cvss": 8.1,
                         "fixed_versions": list(fixed)})
    rc.store.add_evidence(ev)
    f = Finding(run_id=RUN, category=FindingCategory.CVE, title="GHSA-aaaa in jsonwebtoken@0.4.0",
                detector="grype@t", component_purl=PURL, scope=Scope.PROD, project="root", vuln_id="GHSA-aaaa",
                aliases=["CVE-2022-23539"], cvss=8.1, fixed_versions=list(fixed), evidence_ids=[ev.evidence_id],
                dependency_paths=paths if paths is not None else [["root", PURL]], initial_risk="high")
    rc.store.add_finding(f)
    return f


def test_risk_score_equals_compute_and_factors_have_sources(rc):
    f = cve(rc)
    out = ra.risk_analyst_node({"run_id": RUN, "finding_ids": [f.finding_id]})
    a = load_risks(rc.tool_ctx.run_dir)[f.finding_id]
    assert a.score == compute(a.factors).score and a.band == compute(a.factors).band
    for k in "SERPX":
        fv = getattr(a.factors, k)
        assert fv.evidence_ids or fv.unknown, k
    assert a.factors.R.tier == "imported" and a.factors.X.tier == "network" and a.factors.P.tier == "prod"
    assert a.factors.E.unknown  # offline: no EPSS in cache -> unknown, lowers confidence
    assert a.summary.startswith("GHSA-aaaa") and out["plan_queue"] == [f.finding_id]  # CVE with a fix is plannable


def test_kev_override_and_not_applicable_weights():
    ids = ["ev_x"]
    low = RiskFactors(S=factor(0.0, "cvss", ids), E=factor(1.0, "kev", ids), R=factor(0.6, "imported", ids),
                      P=factor(1.0, "prod", ids), X=factor(0.5, "internal", ids))
    c = compute(low)
    assert c.override_applied == "kev_reachable_prod" and c.band.value == "high"
    ci = RiskFactors(S=factor(0.6, "unpinned_ci", ids), E=factor(0.5, "no_exploit_evidence", ids),
                     R=factor(0.0, "not_applicable", ids), P=factor(1.0, "prod", ids),
                     X=factor(0.5, "unknown", [], unknown=True))
    assert compute(ci).weights["S"] == 0.5 and compute(ci).confidence.value == "high"  # X never lowers confidence


def test_remediation_retry_picks_other_version_and_target_in_evidence(rc):
    f = cve(rc)
    ra.risk_analyst_node({"run_id": RUN, "finding_ids": [f.finding_id]})
    st = {"run_id": RUN, "plan_queue": [f.finding_id], "current": None, "attempt": 0}
    first = rem.remediation_node(st)
    p1 = list_plans(rc.tool_ctx.run_dir)[0]
    assert p1.action == "upgrade" and p1.target_version == "9.0.0" and first["route"] == "gate"
    assert p1.ops[0].args == {"name": "jsonwebtoken", "version": "^9.0.0"}
    assert "score" in p1.expected_risk_reduction and p1.plan_hash
    osv = [e for e in (rc.store.get_evidence(i) for i in p1.evidence_ids) if e.kind == "osv"]
    assert p1.target_version in osv[0].facts["candidates"]
    second = rem.remediation_node({**st, "current": first["current"], "attempt": 1,
                                   "last_validation": {"verdict": "failed_build"}})
    plans = list_plans(rc.tool_ctx.run_dir)
    assert len(plans) == 2 and second["route"] == "gate"
    p2 = next(p for p in plans if p.plan_id != p1.plan_id)
    assert p2.ops != p1.ops and p2.target_version == "9.0.2" and p2.attempt == 2
    third = rem.remediation_node({**st, "current": first["current"], "attempt": 2})  # nothing untried: escalate
    assert third["route"] == "next" and rc.store.get_finding(f.finding_id).status.value == "escalated"


def test_g45_blocks_target_absent_from_evidence(rc):
    f = cve(rc)
    cands = rem.cve_candidates(rc, f)
    assert cands and cands[0].target == "9.0.0"
    cands[0].target = "99.0.0"  # a version nobody looked up
    assert rem.build_plan(rc, f, cands[0], 1) is None
    assert "G4.5" in (rc.tool_ctx.run_dir / "trace.jsonl").read_text()


def test_transitive_without_known_parent_version_invents_nothing(rc):
    f = cve(rc, paths=[["root", PURL, "pkg:npm/jws@1.0.0"]])
    f.component_purl = "pkg:npm/jws@1.0.0"
    assert rem.cve_candidates(rc, f) == []  # offline, registry latest unknown: no invented target


def test_simulate_after_and_report(rc):
    f = cve(rc)
    ra.risk_analyst_node({"run_id": RUN, "finding_ids": [f.finding_id]})
    a = load_risks(rc.tool_ctx.run_dir)[f.finding_id]
    assert simulate_after(a, "upgrade")[0] == 0.0 and simulate_after(a, "escalate")[0] == a.score
    rem.remediation_node({"run_id": RUN, "plan_queue": [f.finding_id], "current": None, "attempt": 0})
    plan = list_plans(rc.tool_ctx.run_dir)[0]
    ev = Evidence(run_id=RUN, kind="build_log", source_tool="t", excerpt="x" * 5000)
    rc.store.add_evidence(ev)
    save_validation(rc.tool_ctx.run_dir, ValidationResult(
        attempt_id="at_" + "A" * 26, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=True,
        target_finding_resolved=True, risk_before=a.score, risk_after=0.0, verdict="verified",
        final_confidence="high", log_evidence_ids=[ev.evidence_id]))
    (rc.tool_ctx.run_dir / "approvals.jsonl").write_text(Approval(
        plan_id=plan.plan_id, plan_hash=plan.plan_hash, decision="approve", decided_by="t").model_dump_json() + "\n")
    j, h = write_reports(rc.tool_ctx.run_dir, summary={"status": "done", "target": "shop"})
    rep = json.loads(j.read_text())
    assert set(rep) >= {"run_id", "target", "commit", "generated_at", "summary", "inventory", "findings", "ranking",
                        "actions", "remaining_risk", "final_confidence", "guardrail_events", "audit"}
    assert rep["ranking"] == [f.finding_id] and rep["actions"][0]["approval"]["decision"] == "approve"
    assert rep["actions"][0]["validations"][0]["verdict"] == "verified" and rep["final_confidence"] == "high"
    assert rep["findings"][0]["risk"]["score"] == a.score
    html = h.read_text()
    assert "<script src" not in html and "http://" not in html and "GHSA-aaaa" in html
    assert render_html(build_report(rc.tool_ctx.run_dir, summary={})).startswith("<!doctype html>")


def test_pip_cves_with_a_fix_are_plannable():
    from guardian.agents.risk_analyst import cve_plannable
    from guardian.core.models import Finding, FindingCategory

    def cve(purl, fixed):
        return Finding(run_id="r", category=FindingCategory.CVE, title="t", detector="grype", component_purl=purl,
                       fixed_versions=fixed, evidence_ids=["ev_1"])

    assert cve_plannable(cve("pkg:pypi/django@3.2.18", ["3.2.19"]))
    assert cve_plannable(cve("pkg:npm/lodash@2.4.2", ["4.17.21"]))
    assert not cve_plannable(cve("pkg:pypi/django@3.2.18", []))
    assert not cve_plannable(cve("pkg:maven/org.x/y@1.0", ["1.1"]))


def test_transitive_fix_prefers_smallest_parent_major_that_provably_pulls_fixed_child(rc, monkeypatch):
    """jsonwebtoken@0.1.0 (fixed in 4.2.2) comes in through express-jwt@0.1.3. Older express-jwt majors whose
    jsonwebtoken range floor is >= 4.2.2 are proven fixes: attempt 1 is the smallest such jump, attempt 2 the
    next, and ~4.2.0 (floor 4.2.0 < 4.2.2) is never offered. Each target and range is cited evidence (G4.5)."""
    from guardian.tools.threat_intel import IntelClient

    (rc.tool_ctx.repo / "package.json").write_text('{\n  "dependencies": {\n    "express-jwt": "0.1.3"\n  }\n}\n')
    heads = {"8.5.1": {"jsonwebtoken": "^9.0.0"}, "6.1.2": {"jsonwebtoken": "^8.1.0"},
             "3.4.0": {"jsonwebtoken": "^5.0.0"}, "2.1.0": {"jsonwebtoken": "~4.2.0"}}
    monkeypatch.setattr(IntelClient, "registry_metadata",
                        lambda self, purl: {"latest": "8.5.1", "major_heads": heads} if "express-jwt" in purl else None)
    child = "pkg:npm/jsonwebtoken@0.1.0"
    f = cve(rc, fixed=("4.2.2",), paths=[["root", "pkg:npm/express-jwt@0.1.3", child]])
    f.component_purl = child
    cands = rem.cve_candidates(rc, f)
    assert [c.target for c in cands] == ["3.4.0", "6.1.2", "8.5.1"]
    assert cands[0].ops[0].args == {"name": "express-jwt", "version": "^3.4.0"}
    plan = rem.build_plan(rc, f, cands[0], 1)
    assert plan is not None and plan.target_version == "3.4.0"
    proof = next(c for c in plan.rationale if "depends on jsonwebtoken ^5.0.0" in c.text)
    assert proof.label.value == "verified"


# ---------------------------------------------------------------- selection by score, version checks (critique fixes)


def _f(purl, score_title, *, cat=FindingCategory.CVE, fixed=("1.0.0",), paths=None, rng=None, vid="GHSA-x"):
    return Finding(run_id=RUN, category=cat, title=score_title, detector="grype@t", component_purl=purl,
                   vuln_id=vid if cat is FindingCategory.CVE else None, fixed_versions=list(fixed),
                   affected_range=rng, dependency_paths=paths or ([["root", purl]] if purl else []),
                   file_path=".npmrc" if cat is FindingCategory.LOCKFILE else None, evidence_ids=["ev_t"])


def test_select_ranks_every_fixable_finding_by_score_one_per_package():
    """A Medium lockfile finding no longer takes a slot from Critical vulnerabilities; two advisories on one
    package version get one plan; on a score tie the direct dependency goes first."""
    lock = _f(None, "lockfile", cat=FindingCategory.LOCKFILE, fixed=())
    san1 = _f("pkg:npm/sanitize-html@1.4.2", "san 1", vid="GHSA-1")
    san2 = _f("pkg:npm/sanitize-html@1.4.2", "san 2", vid="GHSA-2")
    jwt_t = _f("pkg:npm/jsonwebtoken@0.1.0", "a jwt transitive",
               paths=[["root", "pkg:npm/express-jwt@0.1.3", "pkg:npm/jsonwebtoken@0.1.0"]])
    jwt_d = _f("pkg:npm/jsonwebtoken@0.4.0", "b jwt direct")
    scores = {lock.finding_id: 58, san1.finding_id: 87, san2.finding_id: 81, jwt_t.finding_id: 98,
              jwt_d.finding_id: 98}
    chosen = ra.select([lock, san1, san2, jwt_t, jwt_d], 3, scores)
    assert chosen == [jwt_d, jwt_t, san1]
    assert ra.select([lock, san1, san2], 3, scores) == [san1, lock]


def test_version_range_helpers():
    assert rem.in_range("5.3.3", "<=5.3.3") and not rem.in_range("6.1.2", "<=5.3.3")
    assert rem.in_range("8.19.0", ">=8.0.0,<8.21.0") and not rem.in_range("7.0.0", ">=8.0.0,<8.21.0")
    assert rem.in_range("1.0.0", None) is None and rem.in_range("1.0.0", "some text") is None
    assert rem.lowest_allowed("^8.1.0") == "8.1.0" and rem.lowest_allowed("*") is None


def test_direct_fix_skips_versions_another_advisory_still_affects(rc):
    f = cve(rc)  # candidates 9.0.0 and 9.0.2
    other = _f(PURL, "GHSA-bbbb in jsonwebtoken@0.4.0", rng="<9.0.1", vid="GHSA-bbbb")
    other.evidence_ids = f.evidence_ids
    rc.store.add_finding(other)
    assert [c.target for c in rem.cve_candidates(rc, f)] == ["9.0.2"]


def test_transitive_fix_skips_parents_that_leave_an_advisory_behind(rc, monkeypatch):
    """express-jwt 3.4.0 is itself affected (<=5.3.3) and 6.1.2 lets jsonwebtoken ^8.1.0 in, which another
    advisory covers (<=8.5.1): only 8.5.1 clears everything, so it is the one proposed."""
    from guardian.tools.threat_intel import IntelClient

    (rc.tool_ctx.repo / "package.json").write_text('{\n  "dependencies": {\n    "express-jwt": "0.1.3"\n  }\n}\n')
    heads = {"8.5.1": {"jsonwebtoken": "^9.0.0"}, "6.1.2": {"jsonwebtoken": "^8.1.0"},
             "3.4.0": {"jsonwebtoken": "^5.0.0"}}
    monkeypatch.setattr(IntelClient, "registry_metadata",
                        lambda self, purl: {"latest": "8.5.1", "major_heads": heads} if "express-jwt" in purl else None)
    child = "pkg:npm/jsonwebtoken@0.1.0"
    parent_paths = [["root", "pkg:npm/express-jwt@0.1.3", child]]
    f = cve(rc, fixed=("4.2.2",), paths=parent_paths)
    f.component_purl = child
    for g in (_f("pkg:npm/express-jwt@0.1.3", "express-jwt own", rng="<=5.3.3", vid="GHSA-6g6m"),
              _f(child, "jwt 8.x", rng="<=8.5.1", vid="GHSA-8cf7", paths=parent_paths)):
        g.evidence_ids = f.evidence_ids
        rc.store.add_finding(g)
    assert [c.target for c in rem.cve_candidates(rc, f)] == ["8.5.1"]


@pytest.mark.parametrize("name,expected", [
    ("GET basket should accept forged JWTs", True),
    ("login works without a valid token", True),
    ("rejects forged tokens", False),
    ("should not accept forged tokens", False),
    ("XSS payload is sanitized", False),
    ("scan of forged data deleted", False),
    ("GET all orders", False),
    # Juice Shop insecurity.unit.test.ts: the noun "sanitization" names the hole, it is not a protective verb
    ("can be bypassed by exploiting lack of recursive sanitization", True),
    ("cannot be bypassed by exploiting lack of recursive sanitization", False),
])
def test_tests_that_assert_an_attack_works(name, expected):
    from guardian.agents.validator import asserts_exploit

    assert asserts_exploit(name) is expected


def test_steer_follows_the_rejection_reason():
    def up(v):
        return rem.Candidate("upgrade", [], v, [], "t")

    rejected = RemediationPlan.model_construct(action="upgrade", target_version="8.5.1")
    cands = [up("8.6.0"), up("7.7.8"), up("6.0.0"), up("9.0.0")]
    assert [c.target for c in rem.steer(cands, rejected, "too_big")[0]] == ["6.0.0", "7.7.8"]
    assert [c.target for c in rem.steer(cands, rejected, "breaks_app")[0]] == ["7.7.8", "6.0.0", "9.0.0"]
    assert rem.steer(cands, rejected, "other")[0] == cands and rem.steer(cands, rejected, None)[0] == cands
    out, note = rem.steer(cands, rejected, "different_approach")
    assert out == [] and "no fix other than an upgrade" in note
    small, note = rem.steer([up("9.0.0")], rejected, "too_big")
    assert small == [] and "no smaller change" in note
