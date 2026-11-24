"""D2-06: install-script detector and unexpected-change detector (legacy .bak + --compare-ref). No network."""

import dataclasses
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from guardian.core.models import FindingCategory
from guardian.tools.detectors import install_scripts, unexpected_change
from guardian.tools.detectors.unexpected_change import (
    compare_ref_diff,
    diff_locks,
    diff_manifests,
    legacy_diff,
)
from guardian.tools.detectors.unexpected_change import (
    detect as detect_changes,
)
from guardian.tools.registry import ToolContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "juice-shop"


def make_ctx(tmp_path, settings, repo: Path, work: Path | None = None, **artifacts) -> ToolContext:
    run_dir = tmp_path / "run"
    run_dir.mkdir(exist_ok=True)
    return ToolContext(run_id="run_t", run_dir=run_dir, repo=repo, settings=settings, work_dir=work,
                       artifacts=dict(artifacts))


# ---------------------------------------------------------------- install scripts


@pytest.fixture
def juice(tmp_path):
    work = tmp_path / "work"
    (work / "frontend").mkdir(parents=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copyfile(FIXTURES / "root" / name, work / name)
        shutil.copyfile(FIXTURES / "frontend" / name, work / "frontend" / name)
    return work


@pytest.fixture
def npm_cache(tmp_path, monkeypatch):
    cache = tmp_path / "npmcache"
    monkeypatch.setattr(install_scripts, "CACHE", cache)
    monkeypatch.setattr(install_scripts.time, "sleep", lambda s: None)
    return cache


def offline(settings):
    return dataclasses.replace(settings, offline=True)


def test_install_scripts_offline_with_empty_cache_still_finds_packages(tmp_path, settings, juice, npm_cache,
                                                                       monkeypatch):
    def no_network(*a, **k):
        raise AssertionError("network used in offline mode")

    monkeypatch.setattr(install_scripts.httpx, "get", no_network)
    out = install_scripts.detect(make_ctx(tmp_path, offline(settings), juice, juice))

    purls = [f.component_purl for f in out.findings]
    assert len(purls) == len(set(purls))
    for expected in ("pkg:npm/%40scarf/scarf@1.4.0", "pkg:npm/sqlite3@5.1.7", "pkg:npm/esbuild@0.28.2"):
        assert purls.count(expected) == 1, expected
    assert all(f.category == FindingCategory.INSTALL_SCRIPT for f in out.findings)
    assert all(f.evidence_ids and f.detector == "detector:install_scripts" for f in out.findings)
    assert not any(f.component_purl.startswith("pkg:npm/juice-shop") for f in out.findings)  # root entry ""
    for ev in out.evidence:
        assert ev.facts["has_install_script"] is True
        assert ev.facts["hooks"] is None and ev.facts["scripts_source"].startswith("unavailable")
        assert ev.excerpt is None
    scarf = next(f for f in out.findings if "scarf" in f.title)
    assert scarf.title == "Dependency @scarf/scarf@1.4.0 runs an install script"  # no hooks known offline
    assert not npm_cache.exists()


def test_install_scripts_reads_registry_once_and_caches(tmp_path, settings, juice, npm_cache, monkeypatch):
    calls = []

    class Resp:
        status_code = 200

        def __init__(self, name):
            self.name = name

        def json(self):
            return {"scripts": {"postinstall": f"node {self.name}.js", "test": "mocha"}}

    def fake_get(url, **kw):
        calls.append(url)
        return Resp(url.rsplit("/", 2)[-2])

    monkeypatch.setattr(install_scripts.httpx, "get", fake_get)
    first = install_scripts.detect(make_ctx(tmp_path, settings, juice, juice))
    n_calls = len(calls)
    assert n_calls == len(first.findings) > 0
    assert not any(url.count("%40") for url in calls)  # scoped names keep '@' literal in the registry URL
    esbuild = next(f for f in first.findings if f.component_purl == "pkg:npm/esbuild@0.28.2")
    assert esbuild.title.endswith("(postinstall)")
    ev = next(e for e in first.evidence if e.facts["package"] == "esbuild")
    assert ev.facts["hooks"] == ["postinstall"] and "test" not in (ev.excerpt or "")
    assert ev.excerpt == "postinstall: node esbuild.js"

    second = install_scripts.detect(make_ctx(tmp_path, offline(settings), juice, juice))
    assert len(calls) == n_calls  # served from the disk cache, even offline
    assert {f.title for f in second.findings} == {f.title for f in first.findings}


def test_install_scripts_registry_failure_degrades_to_unavailable(tmp_path, settings, juice, npm_cache,
                                                                  monkeypatch):
    import httpx

    def fail(*a, **k):
        raise httpx.ConnectError("boom")

    monkeypatch.setattr(install_scripts.httpx, "get", fail)
    out = install_scripts.detect(make_ctx(tmp_path, settings, juice, juice))
    assert out.findings and all(e.facts["hooks"] is None for e in out.evidence)


def test_install_scripts_flags_dev_scope_and_skips_links(tmp_path, settings, npm_cache):
    work = tmp_path / "w"
    work.mkdir()
    (work / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0.0"}}))
    lock = {"packages": {
        "": {"name": "proj", "version": "1.0.0", "hasInstallScript": True},
        "node_modules/a": {"version": "1.0.0", "hasInstallScript": True, "dev": True},
        "node_modules/b": {"version": "1.0.0"},
        "node_modules/c": {"version": "1.0.0", "hasInstallScript": True, "link": True},
        "node_modules/x/node_modules/@s/d": {"version": "2.0.0", "hasInstallScript": True},
    }}
    (work / "package-lock.json").write_text(json.dumps(lock))
    out = install_scripts.detect(make_ctx(tmp_path, offline(settings), work, work))
    by_purl = {f.component_purl: f for f in out.findings}
    assert set(by_purl) == {"pkg:npm/a@1.0.0", "pkg:npm/%40s/d@2.0.0"}
    assert by_purl["pkg:npm/a@1.0.0"].scope.value == "dev"
    assert by_purl["pkg:npm/%40s/d@2.0.0"].scope.value == "prod"


def test_install_scripts_project_without_lockfile_is_skipped(tmp_path, settings, npm_cache):
    work = tmp_path / "w"
    work.mkdir()
    (work / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0.0"}}))
    out = install_scripts.detect(make_ctx(tmp_path, offline(settings), work, work))
    assert out.findings == [] and out.evidence == []


# ---------------------------------------------------------------- pure diff helpers


def lock(**pkgs) -> dict:
    return {"lockfileVersion": 3, "packages": {"": {"name": "p"}, **{
        f"node_modules/{n}": e for n, e in pkgs.items()}}}


def test_diff_manifests_added_removed_changed_and_major_jump():
    base = {"dependencies": {"express": "^4.17.1", "lodash": "~3.10.0", "gone": "1.0.0"},
            "devDependencies": {"mocha": "^9.0.0"}}
    head = {"dependencies": {"express": "^4.19.0", "lodash": "^4.0.0", "@scope/new": "^1.2.3"},
            "devDependencies": {"mocha": "^9.0.0"}}
    d = diff_manifests(base, head)
    assert d["added"] == ["pkg:npm/%40scope/new@1.2.3"]
    assert d["removed"] == ["pkg:npm/gone@1.0.0"]
    changed = {c["name"]: c for c in d["changed"]}
    assert set(changed) == {"express", "lodash"}
    assert changed["express"]["major_jump"] is False
    assert changed["lodash"]["major_jump"] is True
    assert (changed["lodash"]["from"], changed["lodash"]["to"]) == ("3.10.0", "4.0.0")


def test_diff_manifests_downgrade_and_non_semver_are_not_major_jumps():
    d = diff_manifests({"dependencies": {"a": "^5.0.0", "b": "latest"}},
                       {"dependencies": {"a": "^4.0.0", "b": "next"}})
    assert {c["name"]: c["major_jump"] for c in d["changed"]} == {"a": False, "b": False}


def test_diff_locks_flags_same_algorithm_different_digest():
    base = lock(express={"version": "4.0.0", "integrity": "sha512-AAAA"})
    head = lock(express={"version": "4.0.0", "integrity": "sha512-BBBB"})
    d = diff_locks(base, head)
    assert d["integrity_changed"] == [{"purl": "pkg:npm/express@4.0.0", "from": "sha512-AAAA", "to": "sha512-BBBB"}]
    assert d["install_scripts_added"] == []


def test_diff_locks_sha1_to_sha512_and_missing_integrity_are_not_flagged():
    base = lock(a={"version": "1.0.0", "integrity": "sha1-xxxx"}, b={"version": "1.0.0"},
                c={"version": "1.0.0", "integrity": "sha512-same"})
    head = lock(a={"version": "1.0.0", "integrity": "sha512-yyyy"}, b={"version": "1.0.0", "integrity": "sha512-z"},
                c={"version": "1.0.0", "integrity": "sha512-same"})
    assert diff_locks(base, head)["integrity_changed"] == []


def test_diff_locks_new_version_of_a_package_is_not_an_integrity_change():
    base = lock(a={"version": "1.0.0", "integrity": "sha512-one"})
    head = lock(a={"version": "1.1.0", "integrity": "sha512-two"})
    assert diff_locks(base, head)["integrity_changed"] == []


def test_diff_locks_install_script_added_distinguishes_new_packages():
    base = lock(old={"version": "1.0.0"}, steady={"version": "1.0.0", "hasInstallScript": True})
    head = lock(old={"version": "1.0.0", "hasInstallScript": True}, steady={"version": "1.0.0", "hasInstallScript": True},
                fresh={"version": "2.0.0", "hasInstallScript": True})
    added = {s["purl"]: s["new_package"] for s in diff_locks(base, head)["install_scripts_added"]}
    assert added == {"pkg:npm/fresh@2.0.0": True, "pkg:npm/old@1.0.0": False}


def test_diff_locks_reads_lockfile_v1_nested_dependencies():
    base = {"dependencies": {"a": {"version": "1.0.0", "integrity": "sha512-A",
                                   "dependencies": {"b": {"version": "1.0.0", "integrity": "sha512-B"}}}}}
    head = {"dependencies": {"a": {"version": "1.0.0", "integrity": "sha512-A",
                                   "dependencies": {"b": {"version": "1.0.0", "integrity": "sha512-C"}}}}}
    assert [c["purl"] for c in diff_locks(base, head)["integrity_changed"]] == ["pkg:npm/b@1.0.0"]


# ---------------------------------------------------------------- legacy .bak baseline


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


@pytest.fixture
def legacy_tree(tmp_path):
    root = tmp_path / "legacy"
    write_json(root / "package.json", {"dependencies": {"express": "^4.19.0", "newdep": "1.0.0"}})
    write_json(root / "ftp" / "package.json.bak", {"dependencies": {"express": "^3.0.0", "olddep": "1.0.0"}})
    return root


def test_legacy_diff_produces_changes_but_no_findings(tmp_path, settings, legacy_tree):
    out = detect_changes(make_ctx(tmp_path, settings, legacy_tree, legacy_tree))
    assert out.findings == []
    changes = out.artifacts["changes"]
    assert changes["base"] == "ftp/package.json.bak" and changes["head"] == "package.json"
    assert changes["added"] == ["pkg:npm/newdep@1.0.0"] and changes["removed"] == ["pkg:npm/olddep@1.0.0"]
    assert [c["name"] for c in changes["changed"] if c["major_jump"]] == ["express"]
    assert changes["evidence_ids"] == [out.evidence[0].evidence_id]
    assert out.evidence[0].kind == "changes" and out.evidence[0].file_path == "ftp/package.json.bak"


def test_legacy_diff_without_baseline_returns_nothing(tmp_path, settings):
    assert legacy_diff(tmp_path) is None
    (tmp_path / "package.json").write_text("{}")
    out = detect_changes(make_ctx(tmp_path, settings, tmp_path, tmp_path))
    assert out.findings == [] and out.evidence == [] and "changes" not in out.artifacts


def test_legacy_diff_integrity_change_is_a_finding_but_install_scripts_are_not(tmp_path, settings, legacy_tree):
    write_json(legacy_tree / "ftp" / "package-lock.json.bak", lock(
        express={"version": "4.0.0", "integrity": "sha512-OLD"}, native={"version": "1.0.0"}))
    write_json(legacy_tree / "package-lock.json", lock(
        express={"version": "4.0.0", "integrity": "sha512-NEW"}, native={"version": "1.0.0", "hasInstallScript": True}))
    out = detect_changes(make_ctx(tmp_path, settings, legacy_tree, legacy_tree))
    assert [f.category for f in out.findings] == [FindingCategory.INTEGRITY_CHANGE]
    f = out.findings[0]
    assert f.component_purl == "pkg:npm/express@4.0.0" and f.evidence_ids
    assert out.artifacts["changes"]["install_scripts_added"] == []
    assert {e.evidence_id for e in out.evidence} >= set(f.evidence_ids)


def test_legacy_diff_with_matching_integrity_has_no_findings(tmp_path, settings, legacy_tree):
    same = lock(express={"version": "4.0.0", "integrity": "sha512-SAME"})
    write_json(legacy_tree / "ftp" / "package-lock.json.bak", same)
    write_json(legacy_tree / "package-lock.json", same)
    assert detect_changes(make_ctx(tmp_path, settings, legacy_tree, legacy_tree)).findings == []


# ---------------------------------------------------------------- compare-ref on a real (temp) git repo


def git(repo: Path, *args: str) -> str:
    cmd = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.test", "-c",
           "commit.gpgsign=false", *args]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    write_json(repo / "package.json", {"name": "app", "dependencies": {"express": "^4.17.1", "lodash": "^3.10.0",
                                                                        "oldsha": "1.0.0"}})
    write_json(repo / "package-lock.json", lock(
        express={"version": "4.17.1", "integrity": "sha512-ORIGINAL"},
        lodash={"version": "3.10.0", "integrity": "sha512-LODASH3"},
        oldsha={"version": "1.0.0", "integrity": "sha1-OLD"},
        native={"version": "1.0.0", "integrity": "sha512-NATIVE"}))
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")
    return repo


def change_working_tree(repo: Path) -> None:
    write_json(repo / "package.json", {"name": "app", "dependencies": {
        "express": "^4.17.1", "lodash": "^4.17.21", "oldsha": "1.0.0", "newdep": "^1.0.0"}})
    write_json(repo / "package-lock.json", lock(
        express={"version": "4.17.1", "integrity": "sha512-TAMPERED"},  # same name@version, different bytes
        lodash={"version": "4.17.21", "integrity": "sha512-LODASH4"},
        oldsha={"version": "1.0.0", "integrity": "sha512-UPGRADED"},  # sha1 -> sha512: not flagged
        native={"version": "1.0.0", "integrity": "sha512-NATIVE", "hasInstallScript": True},
        newdep={"version": "1.0.0", "integrity": "sha512-NEW", "hasInstallScript": True}))


def test_compare_ref_yields_all_four_finding_kinds(tmp_path, settings, git_repo):
    change_working_tree(git_repo)
    head_sha = git(git_repo, "rev-parse", "HEAD")
    out = detect_changes(make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref="HEAD"))

    by_cat = {}
    for f in out.findings:
        by_cat.setdefault(f.category, []).append(f)
    assert set(by_cat) == {FindingCategory.UNEXPECTED_CHANGE, FindingCategory.MAJOR_JUMP,
                           FindingCategory.INTEGRITY_CHANGE, FindingCategory.INSTALL_SCRIPT}
    assert [f.component_purl for f in by_cat[FindingCategory.UNEXPECTED_CHANGE]] == ["pkg:npm/newdep@1.0.0"]
    assert by_cat[FindingCategory.UNEXPECTED_CHANGE][0].line is not None  # located in package.json
    assert [f.component_purl for f in by_cat[FindingCategory.MAJOR_JUMP]] == ["pkg:npm/lodash@4.17.21"]
    assert [f.component_purl for f in by_cat[FindingCategory.INTEGRITY_CHANGE]] == ["pkg:npm/express@4.17.1"]
    scripts = {f.component_purl: f.title for f in by_cat[FindingCategory.INSTALL_SCRIPT]}
    assert set(scripts) == {"pkg:npm/native@1.0.0", "pkg:npm/newdep@1.0.0"}
    assert "new dependency with an install script" in scripts["pkg:npm/newdep@1.0.0"]
    assert "install script added" in scripts["pkg:npm/native@1.0.0"]
    assert not any("oldsha" in (f.component_purl or "") for f in out.findings)  # sha1 -> sha512

    ev_ids = {e.evidence_id for e in out.evidence}
    for f in out.findings:
        assert f.evidence_ids and set(f.evidence_ids) <= ev_ids
        assert f.detector == "detector:unexpected_change"
    diff_ev = {e.evidence_id: e for e in out.evidence if e.kind == "diff"}
    assert len(diff_ev) == len(out.findings)
    assert all(e.facts["compare_ref"] == "HEAD" for e in diff_ev.values())

    changes = out.artifacts["changes"]
    assert changes["compare_sha"] == head_sha and changes["compare_ref"] == "HEAD"
    assert changes["base"] == f"HEAD ({head_sha[:12]})" and changes["head"] == "working tree"
    assert changes["added"] == ["pkg:npm/newdep@1.0.0"]
    assert [c["purl"] for c in changes["integrity_changed"]] == ["pkg:npm/express@4.17.1"]
    assert set(changes["evidence_ids"]) <= ev_ids and len(changes["evidence_ids"]) == len(out.evidence)
    summary_ev = next(e for e in out.evidence if e.kind == "changes")
    assert summary_ev.facts["major_jumps"] == 1 and summary_ev.facts["integrity_changed"] == 1
    json.dumps(changes)  # changes.json-serialisable


def test_compare_ref_unchanged_tree_has_no_findings(tmp_path, settings, git_repo):
    out = detect_changes(make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref="HEAD"))
    assert out.findings == []
    assert out.artifacts["changes"]["added"] == [] and out.artifacts["changes"]["changed"] == []


def test_compare_ref_against_earlier_commit_and_new_project(tmp_path, settings, git_repo):
    change_working_tree(git_repo)
    write_json(git_repo / "frontend" / "package.json", {"dependencies": {"zone.js": "^0.14.0"}})
    git(git_repo, "add", ".")
    git(git_repo, "commit", "-q", "-m", "second")
    first = git(git_repo, "rev-parse", "HEAD~1")
    out = detect_changes(make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref=first))
    assert out.artifacts["changes"]["compare_sha"] == first
    assert FindingCategory.MAJOR_JUMP in {f.category for f in out.findings}
    assert not any("zone.js" in f.title for f in out.findings)  # project that did not exist at the ref


def test_compare_ref_uses_resolved_lockfile_from_work_copy_when_target_has_none(tmp_path, settings, git_repo):
    (git_repo / "package-lock.json").unlink()
    git(git_repo, "add", "-A")
    git(git_repo, "commit", "-q", "-m", "drop lock")
    base = git(git_repo, "rev-parse", "HEAD~1")
    work = tmp_path / "work"
    work.mkdir()
    write_json(work / "package-lock.json", lock(express={"version": "4.17.1", "integrity": "sha512-TAMPERED"}))
    _, per_project = compare_ref_diff(git_repo, work, base)
    assert per_project[0]["lockfile_compared"] is True
    assert [c["purl"] for c in per_project[0]["integrity_changed"]] == ["pkg:npm/express@4.17.1"]


@pytest.mark.parametrize("ref", ["--output=x", "a b", "main;rm -rf /", "$(id)", "", "-x", "a\nb"])
def test_compare_ref_rejects_bad_ref_strings(tmp_path, settings, git_repo, ref):
    with pytest.raises(ValueError, match="unexpected git ref"):
        compare_ref_diff(git_repo, git_repo, ref)
    ctx = make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref=ref or "bad ref")
    if ref:
        with pytest.raises(ValueError):
            detect_changes(ctx)


def test_compare_ref_unknown_ref_fails_loudly(git_repo):
    with pytest.raises(RuntimeError):
        compare_ref_diff(git_repo, git_repo, "no-such-branch")


def test_compare_ref_findings_are_capped_per_kind(tmp_path, settings, git_repo, monkeypatch):
    deps = {f"extra{i}": "1.0.0" for i in range(5)}
    write_json(git_repo / "package.json", {"dependencies": {"express": "^4.17.1", **deps}})
    monkeypatch.setattr(unexpected_change, "MAX_FINDINGS_PER_KIND", 2)
    out = detect_changes(make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref="HEAD"))
    assert len([f for f in out.findings if f.category == FindingCategory.UNEXPECTED_CHANGE]) == 2
    assert len(out.artifacts["changes"]["added"]) == 5  # counts stay complete in changes.json
