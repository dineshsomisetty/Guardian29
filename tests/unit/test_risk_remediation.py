# Document the contract for the surrounding module or callable.
"""D1-06/D1-07/D1-09: risk analyst, CVE remediation candidates, report. Offline, no network."""

# Load json for risk remediation tests.
import json
# Import replace from dataclasses.
from dataclasses import replace

# Load pytest for risk remediation tests.
import pytest

# Import remediation from guardian.agents.
from guardian.agents import remediation as rem
# Import risk_analyst from guardian.agents.
from guardian.agents import risk_analyst as ra
# Import AuditLog from guardian.core.audit.
from guardian.core.audit import AuditLog
# Import Approval, Evidence, Finding, FindingCategory, RemediationPlan, RiskFactors, Scope, ValidationResult from guardian.core.models.
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
    RemediationPlan,
    # Supply the next part of the expression started above.
    RiskFactors,
    # Supply the next part of the expression started above.
    Scope,
    # Supply the next part of the expression started above.
    ValidationResult,
# Close the current expression or collection.
)
# Import list_plans, load_risks, save_validation from guardian.core.plans.
from guardian.core.plans import list_plans, load_risks, save_validation
# Import compute, factor, simulate_after from guardian.core.scoring.
from guardian.core.scoring import compute, factor, simulate_after
# Import JsonStore from guardian.core.store.
from guardian.core.store import JsonStore
# Import RunContext, register, unregister from guardian.graph.state.
from guardian.graph.state import RunContext, register, unregister
# Import Budget from guardian.guardrails.budgets.
from guardian.guardrails.budgets import Budget
# Import build_report from guardian.reporting.build.
from guardian.reporting.build import build_report
# Import render_html, write_reports from guardian.reporting.render.
from guardian.reporting.render import render_html, write_reports
# Import ToolContext from guardian.tools.registry.
from guardian.tools.registry import ToolContext

# Give PURL its starting value.
# The initial value is 'pkg:npm/jsonwebtoken@0.4.0'.
PURL = "pkg:npm/jsonwebtoken@0.4.0"
# Give RUN its starting value.
# The initial value is 'run_unit'.
RUN = "run_unit"


# Apply the pytest.fixture decorator to the declaration below.
@pytest.fixture
# Define rc for risk remediation tests.
# Inputs include tmp_path, settings, monkeypatch.
def rc(tmp_path, settings, monkeypatch):
    # Call monkeypatch.setenv at this point.
    monkeypatch.setenv("GUARDIAN_INTEL_CACHE", str(tmp_path / "intel"))
    # Store tmp_path / 'shop' in repo.
    repo = tmp_path / "shop"
    # Call (repo / 'routes').mkdir at this point.
    (repo / "routes").mkdir(parents=True)
    # Call (repo / 'package.json').write_text at this point.
    (repo / "package.json").write_text('{\n  "dependencies": {\n    "jsonwebtoken": "0.4.0"\n  }\n}\n')
    # Call (repo / 'routes' / 'login.js').write_text at this point.
    (repo / "routes" / "login.js").write_text("const jwt = require('jsonwebtoken')\n")
    # Call (repo / 'Dockerfile').write_text at this point.
    (repo / "Dockerfile").write_text("FROM node:20\nEXPOSE 3000\n")
    # Store tmp_path / 'runs' / RUN in run_dir.
    run_dir = tmp_path / "runs" / RUN
    # Call run_dir.mkdir at this point.
    run_dir.mkdir(parents=True)
    # Store the result of replace in s.
    s = replace(settings, offline=True, max_plans=2)
    # Store the result of ToolContext in ctx.
    ctx = ToolContext(run_id=RUN, run_dir=run_dir, repo=repo, settings=s, work_dir=repo, budget=Budget())
    # Store the result of RunContext in rc.
    rc = RunContext(tool_ctx=ctx, store=JsonStore(run_dir), audit=AuditLog(run_dir, RUN, echo=False), llm=None)
    # Call register at this point.
    register(rc)
    # Continue the operation in this block.
    # This step contributes to risk remediation tests.
    yield rc
    # Call unregister at this point.
    unregister(RUN)


# Define cve for risk remediation tests.
# Inputs include rc, fixed, paths.
def cve(rc, fixed=("9.0.0", "9.0.2"), paths=None):
    # Store the result of Evidence in ev.
    ev = Evidence(run_id=RUN, kind="scanner_output", source_tool="grype@t",
                  # Supply facts as named arguments to the surrounding call.
                  # These names connect the values to the receiving parameters.
                  facts={"vuln_id": "GHSA-aaaa", "aliases": ["CVE-2022-23539"], "cvss": 8.1,
                         # Provide the mapping fields fixed_versions on this line.
                         "fixed_versions": list(fixed)})
    # Call rc.store.add_evidence at this point.
    rc.store.add_evidence(ev)
    # Store the result of Finding in f.
    f = Finding(run_id=RUN, category=FindingCategory.CVE, title="GHSA-aaaa in jsonwebtoken@0.4.0",
                # Supply detector, component_purl, scope, project, vuln_id as named arguments to the surrounding call.
                # These names connect the values to the receiving parameters.
                detector="grype@t", component_purl=PURL, scope=Scope.PROD, project="root", vuln_id="GHSA-aaaa",
                # Supply aliases, cvss, fixed_versions, evidence_ids as named arguments to the surrounding call.
                # These names connect the values to the receiving parameters.
                aliases=["CVE-2022-23539"], cvss=8.1, fixed_versions=list(fixed), evidence_ids=[ev.evidence_id],
                # Supply dependency_paths, initial_risk as named arguments to the surrounding call.
                # These names connect the values to the receiving parameters.
                dependency_paths=paths if paths is not None else [["root", PURL]], initial_risk="high")
    # Call rc.store.add_finding at this point.
    rc.store.add_finding(f)
    # Return f to the caller.
    return f


# Exercise the expected behavior for risk score equals compute and factors have sources.
def test_risk_score_equals_compute_and_factors_have_sources(rc):
    # Store the result of cve in f.
    f = cve(rc)
    # Store the result of ra.risk_analyst_node in out.
    out = ra.risk_analyst_node({"run_id": RUN, "finding_ids": [f.finding_id]})
    # Store load_risks(rc.tool_ctx.run_dir)[f.finding_id] in a.
    a = load_risks(rc.tool_ctx.run_dir)[f.finding_id]
    # Check that the expression on this line.
    assert a.score == compute(a.factors).score and a.band == compute(a.factors).band
    # Iterate over 'SERPX'.
    # Bind each item to k before processing it.
    for k in "SERPX":
        # Store the result of getattr in fv.
        fv = getattr(a.factors, k)
        # Check that fv.evidence_ids or fv.unknown.
        assert fv.evidence_ids or fv.unknown, k
    # Check that the expression on this line.
    assert a.factors.R.tier == "imported" and a.factors.X.tier == "network" and a.factors.P.tier == "prod"
    # Check that a.factors.E.unknown.
    assert a.factors.E.unknown  # offline: no EPSS in cache -> unknown, lowers confidence
    # Check that the expression on this line.
    assert a.summary.startswith("GHSA-aaaa") and out["plan_queue"] == [f.finding_id]  # CVE with a fix is plannable


# Exercise the expected behavior for kev override and not applicable weights.
def test_kev_override_and_not_applicable_weights():
    # Store an ordered collection in ids.
    ids = ["ev_x"]
    # Store the result of RiskFactors in low.
    low = RiskFactors(S=factor(0.0, "cvss", ids), E=factor(1.0, "kev", ids), R=factor(0.6, "imported", ids),
                      # Supply P, X as named arguments to the surrounding call.
                      # These names connect the values to the receiving parameters.
                      P=factor(1.0, "prod", ids), X=factor(0.5, "internal", ids))
    # Store the result of compute in c.
    c = compute(low)
    # Check that the expression on this line.
    assert c.override_applied == "kev_reachable_prod" and c.band.value == "high"
    # Store the result of RiskFactors in ci.
    ci = RiskFactors(S=factor(0.6, "unpinned_ci", ids), E=factor(0.5, "no_exploit_evidence", ids),
                     # Supply R, P as named arguments to the surrounding call.
                     # These names connect the values to the receiving parameters.
                     R=factor(0.0, "not_applicable", ids), P=factor(1.0, "prod", ids),
                     # Supply X, unknown as named arguments to the surrounding call.
                     # These names connect the values to the receiving parameters.
                     X=factor(0.5, "unknown", [], unknown=True))
    # Current weights: severity 0.40 receives reachability's 0.20 for CI findings.
    # Approximate comparison avoids the 0.6000000000000001 floating-point artifact.
    # Check that compute(ci).weights['S'] == pytest.approx(0.6).
    assert compute(ci).weights["S"] == pytest.approx(0.6)
    # Check that compute(ci).weights['R'] == 0.0.
    assert compute(ci).weights["R"] == 0.0
    # Check that compute(ci).confidence.value == 'high'.
    assert compute(ci).confidence.value == "high"  # X never lowers confidence


# Exercise the expected behavior for remediation retry picks other version and target in evidence.
def test_remediation_retry_picks_other_version_and_target_in_evidence(rc):
    # Store the result of cve in f.
    f = cve(rc)
    # Call ra.risk_analyst_node at this point.
    ra.risk_analyst_node({"run_id": RUN, "finding_ids": [f.finding_id]})
    # Store a mapping keyed by the fields below in st.
    st = {"run_id": RUN, "plan_queue": [f.finding_id], "current": None, "attempt": 0}
    # Store the result of rem.remediation_node in first.
    first = rem.remediation_node(st)
    # Store list_plans(rc.tool_ctx.run_dir)[0] in p1.
    p1 = list_plans(rc.tool_ctx.run_dir)[0]
    # Check that the expression on this line.
    assert p1.action == "upgrade" and p1.target_version == "9.0.0" and first["route"] == "gate"
    # Check that the expression on this line.
    assert p1.ops[0].args == {"name": "jsonwebtoken", "version": "^9.0.0"}
    # Check that 'score' in p1.expected_risk_reduction and p1.plan_hash.
    assert "score" in p1.expected_risk_reduction and p1.plan_hash
    # Store values selected or transformed from the input in osv.
    osv = [e for e in (rc.store.get_evidence(i) for i in p1.evidence_ids) if e.kind == "osv"]
    # Check that p1.target_version in osv[0].facts['candidates'].
    assert p1.target_version in osv[0].facts["candidates"]
    # Store the result of rem.remediation_node in second.
    second = rem.remediation_node({**st, "current": first["current"], "attempt": 1,
                                   # Provide the mapping fields last_validation on this line.
                                   "last_validation": {"verdict": "failed_build"}})
    # Store the result of list_plans in plans.
    plans = list_plans(rc.tool_ctx.run_dir)
    # Check that len(plans) == 2 and second['route'] == 'gate'.
    assert len(plans) == 2 and second["route"] == "gate"
    # Store the result of next in p2.
    p2 = next(p for p in plans if p.plan_id != p1.plan_id)
    # Check that the expression on this line.
    assert p2.ops != p1.ops and p2.target_version == "9.0.2" and p2.attempt == 2
    # Store the result of rem.remediation_node in third.
    third = rem.remediation_node({**st, "current": first["current"], "attempt": 2})  # nothing untried: escalate
    # Check that the expression on this line.
    assert third["route"] == "next" and rc.store.get_finding(f.finding_id).status.value == "escalated"


# Exercise the expected behavior for g45 blocks target absent from evidence.
def test_g45_blocks_target_absent_from_evidence(rc):
    # Store the result of cve in f.
    f = cve(rc)
    # Store the result of rem.cve_candidates in cands.
    cands = rem.cve_candidates(rc, f)
    # Check that cands and cands[0].target == '9.0.0'.
    assert cands and cands[0].target == "9.0.0"
    # Give cands[0].target its starting value.
    # The initial value is '99.0.0'.
    cands[0].target = "99.0.0"  # a version nobody looked up
    # Check that rem.build_plan(rc, f, cands[0], 1) is None.
    assert rem.build_plan(rc, f, cands[0], 1) is None
    # Check that 'G4.5' in (rc.tool_ctx.run_dir / 'trace.jsonl').read_text().
    assert "G4.5" in (rc.tool_ctx.run_dir / "trace.jsonl").read_text()


# Exercise the expected behavior for transitive without known parent version invents nothing.
def test_transitive_without_known_parent_version_invents_nothing(rc):
    # Store the result of cve in f.
    f = cve(rc, paths=[["root", PURL, "pkg:npm/jws@1.0.0"]])
    # Give f.component_purl its starting value.
    # The initial value is 'pkg:npm/jws@1.0.0'.
    f.component_purl = "pkg:npm/jws@1.0.0"
    # Check that rem.cve_candidates(rc, f) == [].
    assert rem.cve_candidates(rc, f) == []  # offline, registry latest unknown: no invented target


# Exercise the expected behavior for simulate after and report.
def test_simulate_after_and_report(rc):
    # Store the result of cve in f.
    f = cve(rc)
    # Call ra.risk_analyst_node at this point.
    ra.risk_analyst_node({"run_id": RUN, "finding_ids": [f.finding_id]})
    # Store load_risks(rc.tool_ctx.run_dir)[f.finding_id] in a.
    a = load_risks(rc.tool_ctx.run_dir)[f.finding_id]
    # Check that the expression on this line.
    assert simulate_after(a, "upgrade")[0] == 0.0 and simulate_after(a, "escalate")[0] == a.score
    # Call rem.remediation_node at this point.
    rem.remediation_node({"run_id": RUN, "plan_queue": [f.finding_id], "current": None, "attempt": 0})
    # Store list_plans(rc.tool_ctx.run_dir)[0] in plan.
    plan = list_plans(rc.tool_ctx.run_dir)[0]
    # Store the result of Evidence in ev.
    ev = Evidence(run_id=RUN, kind="build_log", source_tool="t", excerpt="x" * 5000)
    # Call rc.store.add_evidence at this point.
    rc.store.add_evidence(ev)
    # Call save_validation at this point.
    save_validation(rc.tool_ctx.run_dir, ValidationResult(
        # Supply attempt_id, plan_id, finding_id, build_ok as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        attempt_id="at_" + "A" * 26, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=True,
        # Supply target_finding_resolved, risk_before, risk_after, verdict as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        target_finding_resolved=True, risk_before=a.score, risk_after=0.0, verdict="verified",
        # Supply final_confidence, log_evidence_ids as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        final_confidence="high", log_evidence_ids=[ev.evidence_id]))
    # Call (rc.tool_ctx.run_dir / 'approvals.jsonl').write_text at this point.
    (rc.tool_ctx.run_dir / "approvals.jsonl").write_text(Approval(
        # Supply plan_id, plan_hash, decision, decided_by as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        plan_id=plan.plan_id, plan_hash=plan.plan_hash, decision="approve", decided_by="t").model_dump_json() + "\n")
    # Store the result of write_reports in (j, h).
    j, h = write_reports(rc.tool_ctx.run_dir, summary={"status": "done", "target": "shop"})
    # Store the result of json.loads in rep.
    rep = json.loads(j.read_text())
    # Check that the expression on this line.
    assert set(rep) >= {"run_id", "target", "commit", "generated_at", "summary", "inventory", "findings", "ranking",
                        # Supply the next part of the expression started above.
                        "actions", "remaining_risk", "final_confidence", "guardrail_events", "audit"}
    # Check that the expression on this line.
    assert rep["ranking"] == [f.finding_id] and rep["actions"][0]["approval"]["decision"] == "approve"
    # Check that the expression on this line.
    assert rep["actions"][0]["validations"][0]["verdict"] == "verified" and rep["final_confidence"] == "high"
    # Check that rep['findings'][0]['risk']['score'] == a.score.
    assert rep["findings"][0]["risk"]["score"] == a.score
    # Store the result of h.read_text in html.
    html = h.read_text()
    # Check that the expression on this line.
    assert "<script src" not in html and "http://" not in html and "GHSA-aaaa" in html
    # Check that the expression on this line(...).
    assert render_html(build_report(rc.tool_ctx.run_dir, summary={})).startswith("<!doctype html>")


# Exercise the expected behavior for pip cves with a fix are plannable.
def test_pip_cves_with_a_fix_are_plannable():
    # Import cve_plannable from guardian.agents.risk_analyst.
    from guardian.agents.risk_analyst import cve_plannable
    # Import Finding, FindingCategory from guardian.core.models.
    from guardian.core.models import Finding, FindingCategory

    # Define cve for risk remediation tests.
    # Inputs include purl, fixed.
    def cve(purl, fixed):
        # Return the result of Finding to the caller.
        return Finding(run_id="r", category=FindingCategory.CVE, title="t", detector="grype", component_purl=purl,
                       # Supply fixed_versions, evidence_ids as named arguments to the surrounding call.
                       # These names connect the values to the receiving parameters.
                       fixed_versions=fixed, evidence_ids=["ev_1"])

    # Check that cve_plannable(cve('pkg:pypi/django@3.2.18', ['3.2.19'])).
    assert cve_plannable(cve("pkg:pypi/django@3.2.18", ["3.2.19"]))
    # Check that cve_plannable(cve('pkg:npm/lodash@2.4.2', ['4.17.21'])).
    assert cve_plannable(cve("pkg:npm/lodash@2.4.2", ["4.17.21"]))
    # Check that not cve_plannable(cve('pkg:pypi/django@3.2.18', [])).
    assert not cve_plannable(cve("pkg:pypi/django@3.2.18", []))
    # Check that not cve_plannable(cve('pkg:maven/org.x/y@1.0', ['1.1'])).
    assert not cve_plannable(cve("pkg:maven/org.x/y@1.0", ["1.1"]))


# Exercise the expected behavior for transitive fix prefers smallest parent major that provably pulls fixed child.
def test_transitive_fix_prefers_smallest_parent_major_that_provably_pulls_fixed_child(rc, monkeypatch):
    # Document the contract for the surrounding module or callable.
    """jsonwebtoken@0.1.0 (fixed in 4.2.2) comes in through express-jwt@0.1.3. Older express-jwt majors whose
    jsonwebtoken range floor is >= 4.2.2 are proven fixes: attempt 1 is the smallest such jump, attempt 2 the
    next, and ~4.2.0 (floor 4.2.0 < 4.2.2) is never offered. Each target and range is cited evidence (G4.5)."""
    # Import IntelClient from guardian.tools.threat_intel.
    from guardian.tools.threat_intel import IntelClient

    # Call (rc.tool_ctx.repo / 'package.json').write_text at this point.
    (rc.tool_ctx.repo / "package.json").write_text('{\n  "dependencies": {\n    "express-jwt": "0.1.3"\n  }\n}\n')
    # Store a mapping keyed by the fields below in heads.
    heads = {"8.5.1": {"jsonwebtoken": "^9.0.0"}, "6.1.2": {"jsonwebtoken": "^8.1.0"},
             # Supply the next part of the expression started above.
             "3.4.0": {"jsonwebtoken": "^5.0.0"}, "2.1.0": {"jsonwebtoken": "~4.2.0"}}
    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(IntelClient, "registry_metadata",
                        # Supply the next part of the expression started above.
                        lambda self, purl: {"latest": "8.5.1", "major_heads": heads} if "express-jwt" in purl else None)
    # Give child its starting value.
    # The initial value is 'pkg:npm/jsonwebtoken@0.1.0'.
    child = "pkg:npm/jsonwebtoken@0.1.0"
    # Store the result of cve in f.
    f = cve(rc, fixed=("4.2.2",), paths=[["root", "pkg:npm/express-jwt@0.1.3", child]])
    # Store child in f.component_purl.
    f.component_purl = child
    # Store the result of rem.cve_candidates in cands.
    cands = rem.cve_candidates(rc, f)
    # Check that [c.target for c in cands] == ['3.4.0', '6.1.2', '8.5.1'].
    assert [c.target for c in cands] == ["3.4.0", "6.1.2", "8.5.1"]
    # Check that the expression on this line.
    assert cands[0].ops[0].args == {"name": "express-jwt", "version": "^3.4.0"}
    # Store the result of rem.build_plan in plan.
    plan = rem.build_plan(rc, f, cands[0], 1)
    # Check that plan is not None and plan.target_version == '3.4.0'.
    assert plan is not None and plan.target_version == "3.4.0"
    # Store the result of next in proof.
    proof = next(c for c in plan.rationale if "depends on jsonwebtoken ^5.0.0" in c.text)
    # Check that proof.label.value == 'verified'.
    assert proof.label.value == "verified"


# ---------------------------------------------------------------- selection by score, version checks (critique fixes)


# Define _f for risk remediation tests.
# Inputs include purl, score_title, cat, fixed, paths, rng, vid.
def _f(purl, score_title, *, cat=FindingCategory.CVE, fixed=("1.0.0",), paths=None, rng=None, vid="GHSA-x"):
    # Return the result of Finding to the caller.
    return Finding(run_id=RUN, category=cat, title=score_title, detector="grype@t", component_purl=purl,
                   # Supply vuln_id, fixed_versions as named arguments to the surrounding call.
                   # These names connect the values to the receiving parameters.
                   vuln_id=vid if cat is FindingCategory.CVE else None, fixed_versions=list(fixed),
                   # Supply affected_range, dependency_paths as named arguments to the surrounding call.
                   # These names connect the values to the receiving parameters.
                   affected_range=rng, dependency_paths=paths or ([["root", purl]] if purl else []),
                   # Supply file_path, evidence_ids as named arguments to the surrounding call.
                   # These names connect the values to the receiving parameters.
                   file_path=".npmrc" if cat is FindingCategory.LOCKFILE else None, evidence_ids=["ev_t"])


# Exercise the expected behavior for select ranks every fixable finding by score one per package.
def test_select_ranks_every_fixable_finding_by_score_one_per_package():
    # Document the contract for the surrounding module or callable.
    """A Medium lockfile finding no longer takes a slot from Critical vulnerabilities; two advisories on one
    package version get one plan; on a score tie the direct dependency goes first."""
    # Store the result of _f in lock.
    lock = _f(None, "lockfile", cat=FindingCategory.LOCKFILE, fixed=())
    # Store the result of _f in san1.
    san1 = _f("pkg:npm/sanitize-html@1.4.2", "san 1", vid="GHSA-1")
    # Store the result of _f in san2.
    san2 = _f("pkg:npm/sanitize-html@1.4.2", "san 2", vid="GHSA-2")
    # Store the result of _f in jwt_t.
    jwt_t = _f("pkg:npm/jsonwebtoken@0.1.0", "a jwt transitive",
               # Supply paths as named arguments to the surrounding call.
               # These names connect the values to the receiving parameters.
               paths=[["root", "pkg:npm/express-jwt@0.1.3", "pkg:npm/jsonwebtoken@0.1.0"]])
    # Store the result of _f in jwt_d.
    jwt_d = _f("pkg:npm/jsonwebtoken@0.4.0", "b jwt direct")
    # Store a mapping keyed by the fields below in scores.
    scores = {lock.finding_id: 58, san1.finding_id: 87, san2.finding_id: 81, jwt_t.finding_id: 98,
              # Supply the next part of the expression started above.
              jwt_d.finding_id: 98}
    # Store the result of ra.select in chosen.
    chosen = ra.select([lock, san1, san2, jwt_t, jwt_d], 3, scores)
    # Check that chosen == [jwt_d, jwt_t, san1].
    assert chosen == [jwt_d, jwt_t, san1]
    # Check that ra.select([lock, san1, san2], 3, scores) == [san1, lock].
    assert ra.select([lock, san1, san2], 3, scores) == [san1, lock]


# Exercise the expected behavior for version range helpers.
def test_version_range_helpers():
    # Check that the expression on this line.
    assert rem.in_range("5.3.3", "<=5.3.3") and not rem.in_range("6.1.2", "<=5.3.3")
    # Check that the expression on this line.
    assert rem.in_range("8.19.0", ">=8.0.0,<8.21.0") and not rem.in_range("7.0.0", ">=8.0.0,<8.21.0")
    # Check that the expression on this line.
    assert rem.in_range("1.0.0", None) is None and rem.in_range("1.0.0", "some text") is None
    # Check that the expression on this line.
    assert rem.lowest_allowed("^8.1.0") == "8.1.0" and rem.lowest_allowed("*") is None


# Exercise the expected behavior for direct fix skips versions another advisory still affects.
def test_direct_fix_skips_versions_another_advisory_still_affects(rc):
    # Store the result of cve in f.
    f = cve(rc)  # candidates 9.0.0 and 9.0.2
    # Store the result of _f in other.
    other = _f(PURL, "GHSA-bbbb in jsonwebtoken@0.4.0", rng="<9.0.1", vid="GHSA-bbbb")
    # Store f.evidence_ids in other.evidence_ids.
    other.evidence_ids = f.evidence_ids
    # Call rc.store.add_finding at this point.
    rc.store.add_finding(other)
    # Check that [c.target for c in rem.cve_candidates(rc, f)] == ['9.0.2'].
    assert [c.target for c in rem.cve_candidates(rc, f)] == ["9.0.2"]


# Exercise the expected behavior for transitive fix skips parents that leave an advisory behind.
def test_transitive_fix_skips_parents_that_leave_an_advisory_behind(rc, monkeypatch):
    # Document the contract for the surrounding module or callable.
    """express-jwt 3.4.0 is itself affected (<=5.3.3) and 6.1.2 lets jsonwebtoken ^8.1.0 in, which another
    advisory covers (<=8.5.1): only 8.5.1 clears everything, so it is the one proposed."""
    # Import IntelClient from guardian.tools.threat_intel.
    from guardian.tools.threat_intel import IntelClient

    # Call (rc.tool_ctx.repo / 'package.json').write_text at this point.
    (rc.tool_ctx.repo / "package.json").write_text('{\n  "dependencies": {\n    "express-jwt": "0.1.3"\n  }\n}\n')
    # Store a mapping keyed by the fields below in heads.
    heads = {"8.5.1": {"jsonwebtoken": "^9.0.0"}, "6.1.2": {"jsonwebtoken": "^8.1.0"},
             # Supply the next part of the expression started above.
             "3.4.0": {"jsonwebtoken": "^5.0.0"}}
    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(IntelClient, "registry_metadata",
                        # Supply the next part of the expression started above.
                        lambda self, purl: {"latest": "8.5.1", "major_heads": heads} if "express-jwt" in purl else None)
    # Give child its starting value.
    # The initial value is 'pkg:npm/jsonwebtoken@0.1.0'.
    child = "pkg:npm/jsonwebtoken@0.1.0"
    # Store an ordered collection in parent_paths.
    parent_paths = [["root", "pkg:npm/express-jwt@0.1.3", child]]
    # Store the result of cve in f.
    f = cve(rc, fixed=("4.2.2",), paths=parent_paths)
    # Store child in f.component_purl.
    f.component_purl = child
    # Iterate over the expression on this line.
    # Bind each item to g before processing it.
    for g in (_f("pkg:npm/express-jwt@0.1.3", "express-jwt own", rng="<=5.3.3", vid="GHSA-6g6m"),
              # Supply the next part of the expression started above.
              _f(child, "jwt 8.x", rng="<=8.5.1", vid="GHSA-8cf7", paths=parent_paths)):
        # Store f.evidence_ids in g.evidence_ids.
        g.evidence_ids = f.evidence_ids
        # Call rc.store.add_finding at this point.
        rc.store.add_finding(g)
    # Check that [c.target for c in rem.cve_candidates(rc, f)] == ['8.5.1'].
    assert [c.target for c in rem.cve_candidates(rc, f)] == ["8.5.1"]


# Apply the pytest.mark.parametrize decorator to the declaration below.
@pytest.mark.parametrize("name,expected", [
    # Supply the next part of the expression started above.
    ("GET basket should accept forged JWTs", True),
    # Supply the next part of the expression started above.
    ("login works without a valid token", True),
    # Supply the next part of the expression started above.
    ("rejects forged tokens", False),
    # Supply the next part of the expression started above.
    ("should not accept forged tokens", False),
    # Supply the next part of the expression started above.
    ("XSS payload is sanitized", False),
    # Supply the next part of the expression started above.
    ("scan of forged data deleted", False),
    # Supply the next part of the expression started above.
    ("GET all orders", False),
    # Juice Shop insecurity.unit.test.ts: the noun "sanitization" names the hole, it is not a protective verb
    # Supply the next part of the expression started above.
    ("can be bypassed by exploiting lack of recursive sanitization", True),
    # Supply the next part of the expression started above.
    ("cannot be bypassed by exploiting lack of recursive sanitization", False),
# Close the current expression or collection.
])
# Exercise the expected behavior for tests that assert an attack works.
def test_tests_that_assert_an_attack_works(name, expected):
    # Import asserts_exploit from guardian.agents.validator.
    from guardian.agents.validator import asserts_exploit

    # Check that asserts_exploit(name) is expected.
    assert asserts_exploit(name) is expected


# Exercise the expected behavior for steer follows the rejection reason.
def test_steer_follows_the_rejection_reason():
    # Define up for risk remediation tests.
    # Inputs include v.
    def up(v):
        # Return the result of rem.Candidate to the caller.
        return rem.Candidate("upgrade", [], v, [], "t")

    # Store the result of RemediationPlan.model_construct in rejected.
    rejected = RemediationPlan.model_construct(action="upgrade", target_version="8.5.1")
    # Store an ordered collection in cands.
    cands = [up("8.6.0"), up("7.7.8"), up("6.0.0"), up("9.0.0")]
    # Check that the expression on this line.
    assert [c.target for c in rem.steer(cands, rejected, "too_big")[0]] == ["6.0.0", "7.7.8"]
    # Check that the expression on this line.
    assert [c.target for c in rem.steer(cands, rejected, "breaks_app")[0]] == ["7.7.8", "6.0.0", "9.0.0"]
    # Check that the expression on this line.
    assert rem.steer(cands, rejected, "other")[0] == cands and rem.steer(cands, rejected, None)[0] == cands
    # Store the result of rem.steer in (out, note).
    out, note = rem.steer(cands, rejected, "different_approach")
    # Check that out == [] and 'no fix other than an upgrade' in note.
    assert out == [] and "no fix other than an upgrade" in note
    # Store the result of rem.steer in (small, note).
    small, note = rem.steer([up("9.0.0")], rejected, "too_big")
    # Check that small == [] and 'no smaller change' in note.
    assert small == [] and "no smaller change" in note
