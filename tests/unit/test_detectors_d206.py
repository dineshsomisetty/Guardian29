import json
from pathlib import Path
from types import SimpleNamespace

from guardian.tools.detectors import install_scripts, unexpected_change


def _lock(pkgs: dict) -> str:
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app"}, **pkgs}}, indent=2)


BASE_PKG = {"name": "app", "dependencies": {"jsonwebtoken": "~8", "helmet": "~3.9", "epilogue-js": "~0.7",
                                           "qs": "6.0.0"}}
HEAD_PKG = {"name": "app", "dependencies": {"jsonwebtoken": "0.4.0", "helmet": "^4.6.0", "qs": "6.0.0",
                                           "left-pad": "1.0.0"}, "devDependencies": {"mocha": "^10"}}
BASE_LOCK = {"node_modules/qs": {"version": "6.0.0", "integrity": "sha512-AAAA"},
             "node_modules/esbuild": {"version": "0.1.0", "integrity": "sha512-E"}}
HEAD_LOCK = {"node_modules/qs": {"version": "6.0.0", "integrity": "sha512-BBBB"},  # planted: same version, new hash
             "node_modules/esbuild": {"version": "0.2.0", "integrity": "sha512-F", "hasInstallScript": True},
             "node_modules/mocha": {"version": "10.0.0", "dev": True, "hasInstallScript": True}}


def make_repo(tmp: Path) -> SimpleNamespace:
    repo, work = tmp / "repo", tmp / "work"
    for d in (repo / "ftp", work):
        d.mkdir(parents=True)
    (repo / "ftp" / "package.json.bak").write_text(json.dumps(BASE_PKG, indent=2))
    (repo / "ftp" / "package-lock.json.bak").write_text(_lock(BASE_LOCK))
    (repo / "package.json").write_text(json.dumps(HEAD_PKG, indent=2))
    (work / "package.json").write_text(json.dumps(HEAD_PKG, indent=2))
    (work / "package-lock.json").write_text(_lock(HEAD_LOCK))
    return SimpleNamespace(run_id="run_t", repo=repo, work_dir=work, graph=None, settings=None, artifacts={})


def by_cat(out):
    d = {}
    for f in out.findings:
        d.setdefault(f.category.value, []).append(f)
    return d


def test_install_scripts_on_dependencies_with_scope_and_line(tmp_path):
    out = install_scripts.detect(make_repo(tmp_path))
    titles = {f.component_purl: f for f in out.findings}
    assert set(titles) == {"pkg:npm/esbuild@0.2.0", "pkg:npm/mocha@10.0.0"}
    assert titles["pkg:npm/mocha@10.0.0"].scope.value == "dev"
    assert titles["pkg:npm/esbuild@0.2.0"].scope.value == "prod" and titles["pkg:npm/esbuild@0.2.0"].line


def test_planted_integrity_change_detected(tmp_path):
    out = unexpected_change.mini_diff(make_repo(tmp_path))
    (f,) = by_cat(out)["integrity_change"]
    assert f.component_purl == "pkg:npm/qs@6.0.0"
    assert out.artifacts["changes"]["integrity_changed"] == [
        {"purl": "pkg:npm/qs@6.0.0", "from": "sha512-AAAA", "to": "sha512-BBBB"}]


def test_install_script_added_downgrade_major_jump_new_dep_and_legacy_typosquat(tmp_path):
    out = unexpected_change.mini_diff(make_repo(tmp_path))
    c = by_cat(out)
    assert [f.component_purl for f in c["install_script"]] == ["pkg:npm/esbuild@0.2.0"]
    titles = [f.title for f in c["unexpected_change"]]
    assert any("downgrade: jsonwebtoken" in t for t in titles)
    assert any("New dependency: left-pad" in t for t in titles)
    assert [f.title.split(":")[1].split()[0] for f in c["major_jump"]] == ["helmet"]
    (typo,) = c["typosquat"]
    assert typo.file_path == "ftp/package.json.bak" and typo.line and "epilogue-js" in typo.title
    doc = out.artifacts["changes"]
    assert doc["base"] == "ftp/package.json.bak" and doc["head"] == "package.json"
    assert doc["install_scripts_added"] == ["pkg:npm/esbuild@0.2.0"]
    ev = {e.evidence_id for e in out.evidence}
    assert all(set(f.evidence_ids) <= ev for f in out.findings) and doc["evidence_ids"][0] in ev


def test_no_base_means_no_findings(tmp_path):
    ctx = make_repo(tmp_path)
    (ctx.repo / "ftp" / "package.json.bak").unlink()
    out = unexpected_change.mini_diff(ctx)
    assert out.findings == [] and "changes" not in out.artifacts


def test_compare_ref_mode_uses_git_base(tmp_path):
    import subprocess

    repo = tmp_path / "g"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    (repo / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"qs": "6.0.0"}}, indent=2))
    run("add", ".")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
    (repo / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"qs": "6.0.0",
                                                                                  "evil-pkg": "1.0.0"}}, indent=2))
    ctx = SimpleNamespace(run_id="r", repo=repo, work_dir=repo, graph=None,
                          settings=SimpleNamespace(compare_ref="HEAD"), artifacts={})
    out = unexpected_change.mini_diff(ctx)
    assert out.artifacts["changes"]["mode"] == "git:HEAD"
    assert out.artifacts["changes"]["added"] == ["pkg:npm/evil-pkg@1.0.0"]
    assert [f.title for f in out.findings] == ["New dependency: evil-pkg 1.0.0"]
