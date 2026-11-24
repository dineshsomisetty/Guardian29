"""D2-08 validator wiring with a fake docker runner and a stubbed rescan (no Docker, no Syft)."""

import pytest

from guardian.core.plans import list_validations
from guardian.graph import workflow
from guardian.tools import sandbox
from guardian.tools.registry import ToolOutput
from tests.integration.test_human_gate import _decide, _settings, target  # noqa: F401
from tests.unit.test_sandbox import FakeDocker


@pytest.fixture
def rig(monkeypatch):
    from guardian.core.models import Evidence

    monkeypatch.setenv("GUARDIAN_SANDBOX", "docker")
    monkeypatch.setattr(sandbox, "_scripts", lambda w: {"build:server": "x", "test:server": "y"})
    state = {"vulns": []}

    def rescan(ctx):
        ev = Evidence(run_id=ctx.run_id, kind="sbom_diff", source_tool="t",
                      facts={"added": [], "removed": ["pkg:npm/ngy-cookie@6.0.0"], "changed": [],
                             "components_before": 2, "components_after": 1})
        return ToolOutput(evidence=[ev], artifacts={"sbom_diff": ev.facts, "new_vulns": state["vulns"]})

    monkeypatch.setattr(sandbox, "rescan_patched", rescan)
    fake = FakeDocker(test_exit=1)
    sandbox.set_runner(fake)
    yield fake, state
    sandbox.set_runner(None)


def test_failed_tests_then_replan_then_high(target, settings, fake_llm_factory, rig):  # noqa: F811
    fake, _ = rig
    s = _settings(settings, plans=3)
    llm, _b = fake_llm_factory(lambda *a: '{"assessments": []}')
    run_dir = workflow.run(target, run_id="run_sb", settings=s, llm=llm, echo=False)
    _decide(s, "run_sb", "approve")
    v = list_validations(run_dir)
    assert v[0].verdict == "failed_tests" and v[0].build_ok is True and v[0].unit_tests["failed"] == 1
    assert v[0].sbom_diff_evidence_id and v[0].artifact_rescanned
    fake.test_exit = 0  # the second candidate passes
    _decide(s, "run_sb", "approve")
    v = list_validations(run_dir)
    assert v[1].verdict == "verified" and v[1].final_confidence.value == "high"


def test_new_vuln_is_regressed(target, settings, fake_llm_factory, rig):  # noqa: F811
    fake, state = rig
    fake.test_exit = 0
    state["vulns"] = ["CVE-1 in x"]
    s = _settings(settings, plans=3)
    llm, _b = fake_llm_factory(lambda *a: '{"assessments": []}')
    run_dir = workflow.run(target, run_id="run_rg", settings=s, llm=llm, echo=False)
    _decide(s, "run_rg", "approve")
    v = list_validations(run_dir)[0]
    assert v.verdict == "regressed" and "vuln:CVE-1 in x" in v.new_findings


def test_patched_copy_lockfiles_resolved_before_rescan(target, settings, fake_llm_factory, rig, monkeypatch):  # noqa: F811
    """The attempt is a fresh copy of the target, which may ship without lockfiles: the validator must
    re-resolve them for the patched manifests *before* the SBOM rescan, else the diff is meaningless."""
    from guardian.tools import resolve

    fake, _ = rig
    fake.test_exit = 0
    order: list[str] = []
    rescan = sandbox.rescan_patched

    def fake_resolve(ctx):
        order.append(f"resolve:{ctx.artifacts.get('target_name')}:{ctx.work_dir.name}")
        return ToolOutput()

    def tracked_rescan(ctx):
        order.append("rescan")
        return rescan(ctx)

    monkeypatch.setattr(resolve, "resolve_lockfiles", fake_resolve)
    monkeypatch.setattr(sandbox, "rescan_patched", tracked_rescan)
    s = _settings(settings, plans=3)
    llm, _b = fake_llm_factory(lambda *a: '{"assessments": []}')
    workflow.run(target, run_id="run_rl", settings=s, llm=llm, echo=False)
    order.clear()  # discovery resolved the original target; only the validator's calls matter here
    _decide(s, "run_rl", "approve")
    assert order[:2] == [f"resolve:{target.name}:work", "rescan"], order


def test_failing_test_that_asserts_the_attack_does_not_fail_the_fix(target, settings, fake_llm_factory, rig,  # noqa: F811
                                                                     monkeypatch):
    """Closing the hole breaks a test like "should accept forged JWTs": the fix is verified, at medium
    confidence, and the test is named for review. Any other new failure still fails the attempt."""
    from guardian.core.models import Evidence

    names = {"new": ["GET basket should accept forged JWTs"]}

    def fake_validate(ctx):
        res = sandbox.SandboxResult(ran=True, kind="npm", verdict="failed_tests", build_ok=True, tests_ran=True,
                                    unit_tests={"passed": 9, "failed": 1, "total": 10},
                                    failed_names={"test": list(names["new"]), "new_vs_baseline": list(names["new"])},
                                    baseline={"verdict": None})
        ev = Evidence(run_id=ctx.run_id, kind="test_result", source_tool="sandbox:docker", facts={})
        return ToolOutput(evidence=[ev], artifacts={"sandbox_result": res})

    monkeypatch.setattr(sandbox, "sandbox_validate", fake_validate)
    s = _settings(settings, plans=3)
    llm, _b = fake_llm_factory(lambda *a: '{"assessments": []}')
    run_dir = workflow.run(target, run_id="run_ex", settings=s, llm=llm, echo=False)
    _decide(s, "run_ex", "approve")
    v = list_validations(run_dir)[0]
    assert v.verdict == "verified" and v.final_confidence.value == "medium"

    names["new"] = ["GET basket should accept forged JWTs", "checkout total is correct"]
    run_dir = workflow.run(target, run_id="run_ex2", settings=s, llm=llm, echo=False)
    _decide(s, "run_ex2", "approve")
    assert list_validations(run_dir)[0].verdict == "failed_tests"
