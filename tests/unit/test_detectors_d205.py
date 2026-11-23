from pathlib import Path
from types import SimpleNamespace

from guardian.adapters.npm import find_projects, has_lockfile, parse_manifest, read_npmrc
from guardian.tools.detectors import lockfile, typosquat

PKG = """{
  "name": "app",
  "dependencies": {
    "express": "^4.0.0",
    "ngy-cookie": "^6.0.0"
  },
  "devDependencies": {
    "mocha": "^10.0.0"
  }
}
"""


def make(tmp_path: Path, npmrc=True, lock=False) -> Path:
    (tmp_path / "package.json").write_text(PKG)
    if npmrc:
        (tmp_path / ".npmrc").write_text("# comment\npackage-lock=false\n")
    if lock:
        (tmp_path / "package-lock.json").write_text("{}")
    return tmp_path


def ctx(repo: Path, work=None):
    return SimpleNamespace(run_id="run_t", repo=repo, work_dir=work or repo, graph=None)


def test_manifest_lines_and_scope(tmp_path):
    deps = {d.name: d for d in parse_manifest(make(tmp_path) / "package.json")}
    assert deps["ngy-cookie"].line == 5 and deps["ngy-cookie"].scope == "prod"
    assert deps["mocha"].line == 8 and deps["mocha"].scope == "dev"
    assert deps["express"].excerpt == '"express": "^4.0.0",'


def test_npmrc_and_lockfile_helpers(tmp_path):
    make(tmp_path)
    assert read_npmrc(tmp_path) == [(2, "package-lock", "false", "package-lock=false")]
    assert not has_lockfile(tmp_path)
    assert [p.name for p in find_projects(tmp_path)] == ["root"]


def test_lockfile_detector_reports_npmrc_line(tmp_path):
    out = lockfile.detect(ctx(make(tmp_path)))
    (fd,) = out.findings
    assert fd.category.value == "lockfile" and fd.file_path == ".npmrc" and fd.line == 2
    ev = {e.evidence_id: e for e in out.evidence}
    assert all(i in ev for i in fd.evidence_ids)
    assert any(e.excerpt == "package-lock=false" and e.line == 2 for e in out.evidence)


def test_lockfile_detector_checks_original_target_not_work_copy(tmp_path):
    repo, work = tmp_path / "repo", tmp_path / "work"
    repo.mkdir()
    work.mkdir()
    make(repo)
    make(work, lock=True)  # Guardian generated a lockfile in the work copy
    assert len(lockfile.detect(ctx(repo, work)).findings) == 1


def test_lockfile_detector_quiet_when_lockfile_present(tmp_path):
    assert lockfile.detect(ctx(make(tmp_path, npmrc=False, lock=True))).findings == []


def test_typosquat_flags_ngy_cookie_with_file_line_excerpt(tmp_path):
    out = typosquat.detect(ctx(make(tmp_path)))
    assert len(out.findings) == 1 and "ngy-cookie" in out.findings[0].title
    fd = out.findings[0]
    assert fd.file_path == "package.json" and fd.line == 5 and fd.scope.value == "prod"
    ev = {e.evidence_id: e for e in out.evidence}
    assert "ngy-cookie" in ev[fd.evidence_ids[0]].excerpt
    assert ev[fd.evidence_ids[1]].facts["popular_name"]
