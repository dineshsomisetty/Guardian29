import io
import json
import tarfile
from pathlib import Path

import pytest

from guardian.core.models import Finding
from guardian.tools import sandbox
from guardian.tools.sandbox import Step, _parse_signatures, _work_tar, parse_test_counts, scripts_profile

TAP = "TAP version 13\nok 1 - a\n# tests 12\n# suites 3\n# pass 11\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n"
SPEC = "✔ a (1ms)\nℹ tests 5\nℹ pass 5\nℹ fail 0\nℹ skipped 2\n"


def test_parse_test_counts_tap_and_spec():
    assert parse_test_counts(TAP) == {"passed": 11, "failed": 1, "skipped": 0}
    assert parse_test_counts(SPEC) == {"passed": 5, "failed": 0, "skipped": 2}
    assert parse_test_counts("no summary here") == {}


def test_scripts_profile_from_package_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {
        "build:server": "tsc", "test:server": "x", "test:api": "y", "test": "all"}}))
    assert scripts_profile(tmp_path) == {"build": ["npm", "run", "build:server"],
                                         "unit": ["npm", "run", "test:server"],
                                         "integration": ["npm", "run", "test:api"]}
    (tmp_path / "package.json").write_text(json.dumps({"scripts": {"test": "jest"}}))
    assert scripts_profile(tmp_path) == {"build": None, "unit": ["npm", "run", "test"], "integration": None}


def test_work_tar_excludes_env_git_node_modules_and_sets_owner(tmp_path):
    for rel in ("app.js", ".env", ".env.local", "node_modules/x/index.js", ".git/config", "lib/a.js",
                "encryptionkeys/jwt.pub"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    with tarfile.open(fileobj=io.BytesIO(_work_tar(tmp_path))) as tf:
        names = {m.name for m in tf.getmembers() if m.isfile()}
        assert all(m.uid == 1000 for m in tf.getmembers())
    assert names == {"app.js", "lib/a.js", "encryptionkeys/jwt.pub"}


def test_parse_signatures():
    ok = _parse_signatures('{"invalid": [], "missing": []}')
    assert ok["verified"] is True
    bad = _parse_signatures('npm warn x\n{"invalid": [{"name": "evil", "version": "1.0.0"}], "missing": []}')
    assert bad["verified"] is False and bad["invalid"] == ["evil@1.0.0"]
    assert _parse_signatures("audited 1000 packages")["verified"] is None


def test_ensure_dockerignore_appends_required(tmp_path):
    (tmp_path / ".dockerignore").write_text("node_modules\n.env\n")
    added = sandbox.ensure_dockerignore(tmp_path)
    assert added == [".env.*", "*.pem", ".git"]
    assert sandbox.ensure_dockerignore(tmp_path) == []


# ---------------------------------------------------------------- verdict logic (docker mocked)
def _cve(purl, vid, fid="fd_x", cvss=7.5):
    return Finding(finding_id=fid, run_id="r", category="cve", title=vid, detector="grype", component_purl=purl,
                   vuln_id=vid, cvss=cvss, evidence_ids=["ev_1"])


TARGET = _cve("pkg:npm/jsonwebtoken@0.4.0", "GHSA-c7hr-j4mj-j2w6", "fd_target", 9.8)


def _step(name, rc=0, tests=None, tmp=None):
    log = Path(tmp) / f"{name}.log"
    log.write_text("")
    return Step(name, ["npm"], rc, 1.0, str(log), False, tests or {})


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    (work / "package.json").write_text("{}")
    before = tmp_path / "before.cdx.json"
    before.write_text(json.dumps({"components": [{"type": "library", "purl": "pkg:npm/jsonwebtoken@0.4.0"}]}))

    def fake_syft(src, out):
        Path(out).write_text(json.dumps({"components": [{"type": "library", "purl": "pkg:npm/jsonwebtoken@9.0.2"}]}))
        return {}

    monkeypatch.setattr("guardian.tools.sbom.run_syft", fake_syft)
    state = {"steps": None}

    def fake_attempt(w, out, attempt_id, limits):
        return {"steps": state["steps"](out), "network_isolated": True, "container_removed": True,
                "base_image": "guardian-sandbox-node:test",
                "provenance": {"verified": True, "invalid": [], "missing": []}}

    monkeypatch.setattr(sandbox, "run_attempt", fake_attempt)
    return work, before, state, tmp_path


def _run(work, before, tmp, after_findings):
    return sandbox.validate(work, tmp / "run", run_id="r", plan_id="pl_1", finding=TARGET, attempt=1,
                            before_findings=[TARGET], before_sbom=before, risk_before=73.0,
                            rescan=lambda sbom, out: (after_findings, []))


def ok_steps(out):
    return [_step("install", tmp=out), _step("install_scripts", tmp=out), _step("audit_signatures", tmp=out),
            _step("build", tmp=out), _step("unit", tests={"passed": 10, "failed": 0, "skipped": 0}, tmp=out),
            _step("integration", tests={"passed": 4, "failed": 0, "skipped": 0}, tmp=out)]


def test_verified_when_target_gone_and_no_new_findings(fake_env):
    work, before, state, tmp = fake_env
    state["steps"] = ok_steps
    vr, ev, _ = _run(work, before, tmp, [])
    assert vr.verdict == "verified" and vr.target_finding_resolved and vr.risk_after == 0.0
    assert vr.unit_tests["passed"] == 10 and vr.final_confidence.value == "medium"  # no image rebuilt
    kinds = {e.kind for e in ev}
    assert {"sbom_diff", "provenance", "test_result", "build_log"} <= kinds
    diff = next(e for e in ev if e.kind == "sbom_diff").facts
    assert diff["changed"][0]["to"] == ["9.0.2"]


def test_not_resolved_when_same_vuln_still_reported(fake_env):
    work, before, state, tmp = fake_env
    state["steps"] = ok_steps
    vr, _, _ = _run(work, before, tmp, [_cve("pkg:npm/jsonwebtoken@0.4.1", "GHSA-c7hr-j4mj-j2w6", "fd_a")])
    assert vr.verdict == "not_resolved" and not vr.target_finding_resolved


def test_regressed_when_patch_adds_new_vuln(fake_env):
    work, before, state, tmp = fake_env
    state["steps"] = ok_steps
    vr, _, _ = _run(work, before, tmp, [_cve("pkg:npm/jws@4.0.0", "GHSA-new-new-new", "fd_new", 5.0)])
    assert vr.verdict == "regressed" and vr.new_findings == ["fd_new"] and vr.risk_after == 50.0


def test_failed_tests_and_failed_build(fake_env):
    work, before, state, tmp = fake_env

    def failing_tests(out):
        s = ok_steps(out)
        s[4] = _step("unit", rc=1, tests={"passed": 9, "failed": 1, "skipped": 0}, tmp=out)
        return s

    state["steps"] = failing_tests
    assert _run(work, before, tmp, [])[0].verdict == "failed_tests"
    state["steps"] = lambda out: [_step("install", rc=1, tmp=out)]
    vr = _run(work, before, tmp, [])[0]
    assert vr.verdict == "failed_build" and not vr.build_ok and not vr.target_finding_resolved
