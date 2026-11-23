import subprocess

import pytest

from guardian.tools.pr_branch import branch_name, create_fix_branch, render_pr_md

FINDING = {"finding_id": "fd_01ABC", "category": "cve", "title": "GHSA-c7hr-j4mj-j2w6 in jsonwebtoken@0.4.0",
           "component_purl": "pkg:npm/jsonwebtoken@0.4.0", "vuln_id": "GHSA-c7hr-j4mj-j2w6",
           "aliases": ["CVE-2015-9235"], "affected_range": "<4.2.2",
           "dependency_paths": [["root", "pkg:npm/jsonwebtoken@0.4.0"]], "evidence_ids": ["ev_1"]}
PLAN = {"plan_id": "pl_1", "plan_hash": "abcdef1234567890", "attempt": 1, "action": "upgrade",
        "target_version": "9.0.2", "expected_risk_reduction": "73 -> 0",
        "ops": [{"op": "set_dependency_version", "file_path": "package.json",
                 "args": {"name": "jsonwebtoken", "version": "9.0.2"}}],
        "rationale": [{"text": "9.0.2 fixes GHSA-c7hr-j4mj-j2w6", "label": "verified", "evidence_ids": ["ev_1"]},
                      {"text": "probably compatible", "label": "inferred", "evidence_ids": []},
                      {"text": "made-up claim", "label": "unsupported", "evidence_ids": []}],
        "rollback": "restore package.json from base commit"}
VAL = {"attempt_id": "va_1", "verdict": "verified", "final_confidence": "high", "build_ok": True,
       "unit_tests": {"passed": 10, "failed": 0, "skipped": 1}, "integration_tests": {"passed": 4, "failed": 0},
       "artifact_rescanned": "guardian-patched:va_1", "target_finding_resolved": True, "new_findings": [],
       "risk_before": 73.0, "risk_after": 0.0, "sbom_diff_evidence_id": "ev_9"}


def git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *a],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / "package.json").write_text('{"dependencies": {"jsonwebtoken": "0.4.0"}}\n')
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def test_pr_md_labels_and_drops_unsupported():
    md = render_pr_md(FINDING, PLAN, VAL)
    assert "**[VERIFIED]** 9.0.2 fixes" in md and "**[INFERRED]** probably compatible" in md
    assert "made-up claim" not in md
    assert "**verified**" in md and "10 passed" in md and "73.0 → 0.0" in md and "Not merged, not pushed" in md


def test_create_branch_commits_patch_and_pr_md(repo, tmp_path_factory):
    (repo / "package.json").write_text('{"dependencies": {"jsonwebtoken": "9.0.2"}}\n')
    out = create_fix_branch(repo, FINDING, PLAN, VAL, ["package.json"], out_dir=tmp_path_factory.mktemp("o"))
    assert out["branch"] == branch_name("fd_01ABC") == "guardian/fix-fd_01ABC" and out["pushed"] is False
    assert git(repo, "branch", "--show-current") == out["branch"]
    changed = git(repo, "diff", "--name-only", out["base_commit"], out["head_commit"]).split()
    assert sorted(changed) == [".guardian/PR.md", "package.json"]


def test_refuses_unverified_and_repos_with_remote(repo):
    with pytest.raises(ValueError):
        create_fix_branch(repo, FINDING, PLAN, {**VAL, "verdict": "failed_tests"}, ["package.json"])
    git(repo, "remote", "add", "origin", "https://example.com/x.git")
    with pytest.raises(RuntimeError, match="G5.5"):
        create_fix_branch(repo, FINDING, PLAN, VAL, ["package.json"])
