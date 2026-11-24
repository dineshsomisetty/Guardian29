# Document the contract for the surrounding module or callable.
"""D2-06: install-script detector and unexpected-change detector (legacy .bak + --compare-ref). No network."""

# Load dataclasses for changes install tests.
import dataclasses
# Load json for changes install tests.
import json
# Load shutil for changes install tests.
import shutil
# Load subprocess for changes install tests.
import subprocess
# Import Path from pathlib.
from pathlib import Path

# Load pytest for changes install tests.
import pytest

# Import FindingCategory from guardian.core.models.
from guardian.core.models import FindingCategory
# Import install_scripts, unexpected_change from guardian.tools.detectors.
from guardian.tools.detectors import install_scripts, unexpected_change
# Import compare_ref_diff, diff_locks, diff_manifests, legacy_diff from guardian.tools.detectors.unexpected_change.
from guardian.tools.detectors.unexpected_change import (
    # Supply the next part of the expression started above.
    compare_ref_diff,
    # Supply the next part of the expression started above.
    diff_locks,
    # Supply the next part of the expression started above.
    diff_manifests,
    # Supply the next part of the expression started above.
    legacy_diff,
# Close the current expression or collection.
)
# Import detect from guardian.tools.detectors.unexpected_change.
from guardian.tools.detectors.unexpected_change import (
    # Supply the next part of the expression started above.
    detect as detect_changes,
# Close the current expression or collection.
)
# Import ToolContext from guardian.tools.registry.
from guardian.tools.registry import ToolContext

# Store the expression on this line in FIXTURES.
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "juice-shop"


# Define make_ctx for changes install tests.
# Inputs include tmp_path, settings, repo, work.
def make_ctx(tmp_path, settings, repo: Path, work: Path | None = None, **artifacts) -> ToolContext:
    # Store tmp_path / 'run' in run_dir.
    run_dir = tmp_path / "run"
    # Call run_dir.mkdir at this point.
    run_dir.mkdir(exist_ok=True)
    # Return the result of ToolContext to the caller.
    return ToolContext(run_id="run_t", run_dir=run_dir, repo=repo, settings=settings, work_dir=work,
                       # Supply artifacts as named arguments to the surrounding call.
                       # These names connect the values to the receiving parameters.
                       artifacts=dict(artifacts))


# ---------------------------------------------------------------- install scripts


# Apply the pytest.fixture decorator to the declaration below.
@pytest.fixture
# Define juice for changes install tests.
# Inputs include tmp_path.
def juice(tmp_path):
    # Store tmp_path / 'work' in work.
    work = tmp_path / "work"
    # Call (work / 'frontend').mkdir at this point.
    (work / "frontend").mkdir(parents=True)
    # Iterate over ('package.json', 'package-lock.json').
    # Bind each item to name before processing it.
    for name in ("package.json", "package-lock.json"):
        # Call shutil.copyfile at this point.
        shutil.copyfile(FIXTURES / "root" / name, work / name)
        # Call shutil.copyfile at this point.
        shutil.copyfile(FIXTURES / "frontend" / name, work / "frontend" / name)
    # Return work to the caller.
    return work


# Apply the pytest.fixture decorator to the declaration below.
@pytest.fixture
# Define npm_cache for changes install tests.
# Inputs include tmp_path, monkeypatch.
def npm_cache(tmp_path, monkeypatch):
    # Store tmp_path / 'npmcache' in cache.
    cache = tmp_path / "npmcache"
    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(install_scripts, "CACHE", cache)
    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(install_scripts.time, "sleep", lambda s: None)
    # Return cache to the caller.
    return cache


# Define offline for changes install tests.
# Inputs include settings.
def offline(settings):
    # Return the result of dataclasses.replace to the caller.
    return dataclasses.replace(settings, offline=True)


# Exercise the expected behavior for install scripts offline with empty cache still finds packages.
def test_install_scripts_offline_with_empty_cache_still_finds_packages(tmp_path, settings, juice, npm_cache,
                                                                       # Continue the function signature with its remaining arguments.
                                                                       monkeypatch):
    # Define no_network for changes install tests.
    # This helper has no explicit input parameters.
    def no_network(*a, **k):
        # Raise AssertionError('network used in offline mode').
        # The error leaves this branch and can be handled by the caller.
        raise AssertionError("network used in offline mode")

    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(install_scripts.httpx, "get", no_network)
    # Store the result of install_scripts.detect in out.
    out = install_scripts.detect(make_ctx(tmp_path, offline(settings), juice, juice))

    # Store values selected or transformed from the input in purls.
    purls = [f.component_purl for f in out.findings]
    # Check that len(purls) == len(set(purls)).
    assert len(purls) == len(set(purls))
    # Iterate over the expression on this line.
    # Bind each item to expected before processing it.
    for expected in ("pkg:npm/%40scarf/scarf@1.4.0", "pkg:npm/sqlite3@5.1.7", "pkg:npm/esbuild@0.28.2"):
        # Check that purls.count(expected) == 1.
        assert purls.count(expected) == 1, expected
    # Check that all(...).
    assert all(f.category == FindingCategory.INSTALL_SCRIPT for f in out.findings)
    # Check that all(...).
    assert all(f.evidence_ids and f.detector == "detector:install_scripts" for f in out.findings)
    # Check that the expression on this line.
    assert not any(f.component_purl.startswith("pkg:npm/juice-shop") for f in out.findings)  # root entry ""
    # Iterate over out.evidence.
    # Bind each item to ev before processing it.
    for ev in out.evidence:
        # Check that ev.facts['has_install_script'] is True.
        assert ev.facts["has_install_script"] is True
        # Check that the expression on this line.
        assert ev.facts["hooks"] is None and ev.facts["scripts_source"].startswith("unavailable")
        # Check that ev.excerpt is None.
        assert ev.excerpt is None
    # Store the result of next in scarf.
    scarf = next(f for f in out.findings if "scarf" in f.title)
    # Check that the expression on this line.
    assert scarf.title == "Dependency @scarf/scarf@1.4.0 runs an install script"  # no hooks known offline
    # Check that not npm_cache.exists().
    assert not npm_cache.exists()


# Exercise the expected behavior for install scripts reads registry once and caches.
def test_install_scripts_reads_registry_once_and_caches(tmp_path, settings, juice, npm_cache, monkeypatch):
    # Store an ordered collection in calls.
    calls = []

    # Define Resp for changes install tests.
    # Group the related fields or methods under this type.
    class Resp:
        # Give status_code its starting value.
        # The initial value is 200.
        status_code = 200

        # Define __init__ for changes install tests.
        # Inputs include name.
        def __init__(self, name):
            # Store name in self.name.
            self.name = name

        # Define json for changes install tests.
        # This helper has no explicit input parameters.
        def json(self):
            # Return a mapping keyed by the fields below to the caller.
            return {"scripts": {"postinstall": f"node {self.name}.js", "test": "mocha"}}

    # Define fake_get for changes install tests.
    # Inputs include url.
    def fake_get(url, **kw):
        # Call calls.append at this point.
        calls.append(url)
        # Return the result of Resp to the caller.
        return Resp(url.rsplit("/", 2)[-2])

    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(install_scripts.httpx, "get", fake_get)
    # Store the result of install_scripts.detect in first.
    first = install_scripts.detect(make_ctx(tmp_path, settings, juice, juice))
    # Store the result of len in n_calls.
    n_calls = len(calls)
    # Check that n_calls == len(first.findings) > 0.
    assert n_calls == len(first.findings) > 0
    # Check that not any((url.count('%40') for url in calls)).
    assert not any(url.count("%40") for url in calls)  # scoped names keep '@' literal in the registry URL
    # Store the result of next in esbuild.
    esbuild = next(f for f in first.findings if f.component_purl == "pkg:npm/esbuild@0.28.2")
    # Check that esbuild.title.endswith('(postinstall)').
    assert esbuild.title.endswith("(postinstall)")
    # Store the result of next in ev.
    ev = next(e for e in first.evidence if e.facts["package"] == "esbuild")
    # Check that the expression on this line.
    assert ev.facts["hooks"] == ["postinstall"] and "test" not in (ev.excerpt or "")
    # Check that ev.excerpt == 'postinstall: node esbuild.js'.
    assert ev.excerpt == "postinstall: node esbuild.js"

    # Store the result of install_scripts.detect in second.
    second = install_scripts.detect(make_ctx(tmp_path, offline(settings), juice, juice))
    # Check that len(calls) == n_calls.
    assert len(calls) == n_calls  # served from the disk cache, even offline
    # Check that the expression on this line.
    assert {f.title for f in second.findings} == {f.title for f in first.findings}


# Exercise the expected behavior for install scripts registry failure degrades to unavailable.
def test_install_scripts_registry_failure_degrades_to_unavailable(tmp_path, settings, juice, npm_cache,
                                                                  # Continue the function signature with its remaining arguments.
                                                                  monkeypatch):
    # Load httpx for changes install tests.
    import httpx

    # Define fail for changes install tests.
    # This helper has no explicit input parameters.
    def fail(*a, **k):
        # Raise httpx.ConnectError('boom').
        # The error leaves this branch and can be handled by the caller.
        raise httpx.ConnectError("boom")

    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(install_scripts.httpx, "get", fail)
    # Store the result of install_scripts.detect in out.
    out = install_scripts.detect(make_ctx(tmp_path, settings, juice, juice))
    # Check that the expression on this line.
    assert out.findings and all(e.facts["hooks"] is None for e in out.evidence)


# Exercise the expected behavior for install scripts flags dev scope and skips links.
def test_install_scripts_flags_dev_scope_and_skips_links(tmp_path, settings, npm_cache):
    # Store tmp_path / 'w' in work.
    work = tmp_path / "w"
    # Call work.mkdir at this point.
    work.mkdir()
    # Call (work / 'package.json').write_text at this point.
    (work / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0.0"}}))
    # Store a mapping keyed by the fields below in lock.
    lock = {"packages": {
        # Supply the next part of the expression started above.
        "": {"name": "proj", "version": "1.0.0", "hasInstallScript": True},
        # Supply the next part of the expression started above.
        "node_modules/a": {"version": "1.0.0", "hasInstallScript": True, "dev": True},
        # Supply the next part of the expression started above.
        "node_modules/b": {"version": "1.0.0"},
        # Supply the next part of the expression started above.
        "node_modules/c": {"version": "1.0.0", "hasInstallScript": True, "link": True},
        # Supply the next part of the expression started above.
        "node_modules/x/node_modules/@s/d": {"version": "2.0.0", "hasInstallScript": True},
    # Close the current expression or collection.
    }}
    # Call (work / 'package-lock.json').write_text at this point.
    (work / "package-lock.json").write_text(json.dumps(lock))
    # Store the result of install_scripts.detect in out.
    out = install_scripts.detect(make_ctx(tmp_path, offline(settings), work, work))
    # Store a lookup built from the input records in by_purl.
    by_purl = {f.component_purl: f for f in out.findings}
    # Check that set(by_purl) == {'pkg:npm/a@1.0.0', 'pkg:npm/%40s/d@2.0.0'}.
    assert set(by_purl) == {"pkg:npm/a@1.0.0", "pkg:npm/%40s/d@2.0.0"}
    # Check that by_purl['pkg:npm/a@1.0.0'].scope.value == 'dev'.
    assert by_purl["pkg:npm/a@1.0.0"].scope.value == "dev"
    # Check that by_purl['pkg:npm/%40s/d@2.0.0'].scope.value == 'prod'.
    assert by_purl["pkg:npm/%40s/d@2.0.0"].scope.value == "prod"


# Exercise the expected behavior for install scripts project without lockfile is skipped.
def test_install_scripts_project_without_lockfile_is_skipped(tmp_path, settings, npm_cache):
    # Store tmp_path / 'w' in work.
    work = tmp_path / "w"
    # Call work.mkdir at this point.
    work.mkdir()
    # Call (work / 'package.json').write_text at this point.
    (work / "package.json").write_text(json.dumps({"dependencies": {"a": "1.0.0"}}))
    # Store the result of install_scripts.detect in out.
    out = install_scripts.detect(make_ctx(tmp_path, offline(settings), work, work))
    # Check that out.findings == [] and out.evidence == [].
    assert out.findings == [] and out.evidence == []


# ---------------------------------------------------------------- pure diff helpers


# Define lock for changes install tests.
# This helper has no explicit input parameters.
def lock(**pkgs) -> dict:
    # Return a mapping keyed by the fields below to the caller.
    return {"lockfileVersion": 3, "packages": {"": {"name": "p"}, **{
        # Supply the next part of the expression started above.
        f"node_modules/{n}": e for n, e in pkgs.items()}}}


# Exercise the expected behavior for diff manifests added removed changed and major jump.
def test_diff_manifests_added_removed_changed_and_major_jump():
    # Store a mapping keyed by the fields below in base.
    base = {"dependencies": {"express": "^4.17.1", "lodash": "~3.10.0", "gone": "1.0.0"},
            # Provide the mapping fields devDependencies on this line.
            "devDependencies": {"mocha": "^9.0.0"}}
    # Store a mapping keyed by the fields below in head.
    head = {"dependencies": {"express": "^4.19.0", "lodash": "^4.0.0", "@scope/new": "^1.2.3"},
            # Provide the mapping fields devDependencies on this line.
            "devDependencies": {"mocha": "^9.0.0"}}
    # Store the result of diff_manifests in d.
    d = diff_manifests(base, head)
    # Check that d['added'] == ['pkg:npm/%40scope/new@1.2.3'].
    assert d["added"] == ["pkg:npm/%40scope/new@1.2.3"]
    # Check that d['removed'] == ['pkg:npm/gone@1.0.0'].
    assert d["removed"] == ["pkg:npm/gone@1.0.0"]
    # Store a lookup built from the input records in changed.
    changed = {c["name"]: c for c in d["changed"]}
    # Check that set(changed) == {'express', 'lodash'}.
    assert set(changed) == {"express", "lodash"}
    # Check that changed['express']['major_jump'] is False.
    assert changed["express"]["major_jump"] is False
    # Check that changed['lodash']['major_jump'] is True.
    assert changed["lodash"]["major_jump"] is True
    # Check that the expression on this line.
    assert (changed["lodash"]["from"], changed["lodash"]["to"]) == ("3.10.0", "4.0.0")


# Exercise the expected behavior for diff manifests downgrade and non semver are not major jumps.
def test_diff_manifests_downgrade_and_non_semver_are_not_major_jumps():
    # Store the result of diff_manifests in d.
    d = diff_manifests({"dependencies": {"a": "^5.0.0", "b": "latest"}},
                       # Supply the next part of the expression started above.
                       {"dependencies": {"a": "^4.0.0", "b": "next"}})
    # Check that the expression on this line.
    assert {c["name"]: c["major_jump"] for c in d["changed"]} == {"a": False, "b": False}


# Exercise the expected behavior for diff locks flags same algorithm different digest.
def test_diff_locks_flags_same_algorithm_different_digest():
    # Store the result of lock in base.
    base = lock(express={"version": "4.0.0", "integrity": "sha512-AAAA"})
    # Store the result of lock in head.
    head = lock(express={"version": "4.0.0", "integrity": "sha512-BBBB"})
    # Store the result of diff_locks in d.
    d = diff_locks(base, head)
    # Check that the expression on this line.
    assert d["integrity_changed"] == [{"purl": "pkg:npm/express@4.0.0", "from": "sha512-AAAA", "to": "sha512-BBBB"}]
    # Check that d['install_scripts_added'] == [].
    assert d["install_scripts_added"] == []


# Exercise the expected behavior for diff locks sha1 to sha512 and missing integrity are not flagged.
def test_diff_locks_sha1_to_sha512_and_missing_integrity_are_not_flagged():
    # Store the result of lock in base.
    base = lock(a={"version": "1.0.0", "integrity": "sha1-xxxx"}, b={"version": "1.0.0"},
                # Supply c as named arguments to the surrounding call.
                # These names connect the values to the receiving parameters.
                c={"version": "1.0.0", "integrity": "sha512-same"})
    # Store the result of lock in head.
    head = lock(a={"version": "1.0.0", "integrity": "sha512-yyyy"}, b={"version": "1.0.0", "integrity": "sha512-z"},
                # Supply c as named arguments to the surrounding call.
                # These names connect the values to the receiving parameters.
                c={"version": "1.0.0", "integrity": "sha512-same"})
    # Check that diff_locks(base, head)['integrity_changed'] == [].
    assert diff_locks(base, head)["integrity_changed"] == []


# Exercise the expected behavior for diff locks new version of a package is not an integrity change.
def test_diff_locks_new_version_of_a_package_is_not_an_integrity_change():
    # Store the result of lock in base.
    base = lock(a={"version": "1.0.0", "integrity": "sha512-one"})
    # Store the result of lock in head.
    head = lock(a={"version": "1.1.0", "integrity": "sha512-two"})
    # Check that diff_locks(base, head)['integrity_changed'] == [].
    assert diff_locks(base, head)["integrity_changed"] == []


# Exercise the expected behavior for diff locks install script added distinguishes new packages.
def test_diff_locks_install_script_added_distinguishes_new_packages():
    # Store the result of lock in base.
    base = lock(old={"version": "1.0.0"}, steady={"version": "1.0.0", "hasInstallScript": True})
    # Store the result of lock in head.
    head = lock(old={"version": "1.0.0", "hasInstallScript": True}, steady={"version": "1.0.0", "hasInstallScript": True},
                # Supply fresh as named arguments to the surrounding call.
                # These names connect the values to the receiving parameters.
                fresh={"version": "2.0.0", "hasInstallScript": True})
    # Store a lookup built from the input records in added.
    added = {s["purl"]: s["new_package"] for s in diff_locks(base, head)["install_scripts_added"]}
    # Check that the expression on this line.
    assert added == {"pkg:npm/fresh@2.0.0": True, "pkg:npm/old@1.0.0": False}


# Exercise the expected behavior for diff locks reads lockfile v1 nested dependencies.
def test_diff_locks_reads_lockfile_v1_nested_dependencies():
    # Store a mapping keyed by the fields below in base.
    base = {"dependencies": {"a": {"version": "1.0.0", "integrity": "sha512-A",
                                   # Provide the mapping fields dependencies, integrity on this line.
                                   "dependencies": {"b": {"version": "1.0.0", "integrity": "sha512-B"}}}}}
    # Store a mapping keyed by the fields below in head.
    head = {"dependencies": {"a": {"version": "1.0.0", "integrity": "sha512-A",
                                   # Provide the mapping fields dependencies, integrity on this line.
                                   "dependencies": {"b": {"version": "1.0.0", "integrity": "sha512-C"}}}}}
    # Check that the expression on this line.
    assert [c["purl"] for c in diff_locks(base, head)["integrity_changed"]] == ["pkg:npm/b@1.0.0"]


# ---------------------------------------------------------------- legacy .bak baseline


# Define write_json for changes install tests.
# Inputs include path, data.
def write_json(path: Path, data: dict) -> None:
    # Call path.parent.mkdir at this point.
    path.parent.mkdir(parents=True, exist_ok=True)
    # Call path.write_text at this point.
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


# Apply the pytest.fixture decorator to the declaration below.
@pytest.fixture
# Define legacy_tree for changes install tests.
# Inputs include tmp_path.
def legacy_tree(tmp_path):
    # Store tmp_path / 'legacy' in root.
    root = tmp_path / "legacy"
    # Call write_json at this point.
    write_json(root / "package.json", {"dependencies": {"express": "^4.19.0", "newdep": "1.0.0"}})
    # Call write_json at this point.
    write_json(root / "ftp" / "package.json.bak", {"dependencies": {"express": "^3.0.0", "olddep": "1.0.0"}})
    # Return root to the caller.
    return root


# Exercise the expected behavior for legacy diff produces changes but no findings.
def test_legacy_diff_produces_changes_but_no_findings(tmp_path, settings, legacy_tree):
    # Store the result of detect_changes in out.
    out = detect_changes(make_ctx(tmp_path, settings, legacy_tree, legacy_tree))
    # Check that out.findings == [].
    assert out.findings == []
    # Store out.artifacts['changes'] in changes.
    changes = out.artifacts["changes"]
    # Check that the expression on this line.
    assert changes["base"] == "ftp/package.json.bak" and changes["head"] == "package.json"
    # Check that the expression on this line.
    assert changes["added"] == ["pkg:npm/newdep@1.0.0"] and changes["removed"] == ["pkg:npm/olddep@1.0.0"]
    # Check that the expression on this line.
    assert [c["name"] for c in changes["changed"] if c["major_jump"]] == ["express"]
    # Check that changes['evidence_ids'] == [out.evidence[0].evidence_id].
    assert changes["evidence_ids"] == [out.evidence[0].evidence_id]
    # Check that the expression on this line.
    assert out.evidence[0].kind == "changes" and out.evidence[0].file_path == "ftp/package.json.bak"


# Exercise the expected behavior for legacy diff without baseline returns nothing.
def test_legacy_diff_without_baseline_returns_nothing(tmp_path, settings):
    # Check that legacy_diff(tmp_path) is None.
    assert legacy_diff(tmp_path) is None
    # Call (tmp_path / 'package.json').write_text at this point.
    (tmp_path / "package.json").write_text("{}")
    # Store the result of detect_changes in out.
    out = detect_changes(make_ctx(tmp_path, settings, tmp_path, tmp_path))
    # Check that the expression on this line.
    assert out.findings == [] and out.evidence == [] and "changes" not in out.artifacts


# Exercise the expected behavior for legacy diff integrity change is a finding but install scripts are not.
def test_legacy_diff_integrity_change_is_a_finding_but_install_scripts_are_not(tmp_path, settings, legacy_tree):
    # Call write_json at this point.
    write_json(legacy_tree / "ftp" / "package-lock.json.bak", lock(
        # Supply express, native as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        express={"version": "4.0.0", "integrity": "sha512-OLD"}, native={"version": "1.0.0"}))
    # Call write_json at this point.
    write_json(legacy_tree / "package-lock.json", lock(
        # Supply express, native as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        express={"version": "4.0.0", "integrity": "sha512-NEW"}, native={"version": "1.0.0", "hasInstallScript": True}))
    # Store the result of detect_changes in out.
    out = detect_changes(make_ctx(tmp_path, settings, legacy_tree, legacy_tree))
    # Check that the expression on this line.
    assert [f.category for f in out.findings] == [FindingCategory.INTEGRITY_CHANGE]
    # Store out.findings[0] in f.
    f = out.findings[0]
    # Check that f.component_purl == 'pkg:npm/express@4.0.0' and f.evidence_ids.
    assert f.component_purl == "pkg:npm/express@4.0.0" and f.evidence_ids
    # Check that out.artifacts['changes']['install_scripts_added'] == [].
    assert out.artifacts["changes"]["install_scripts_added"] == []
    # Check that {e.evidence_id for e in out.evidence} >= set(f.evidence_ids).
    assert {e.evidence_id for e in out.evidence} >= set(f.evidence_ids)


# Exercise the expected behavior for legacy diff with matching integrity has no findings.
def test_legacy_diff_with_matching_integrity_has_no_findings(tmp_path, settings, legacy_tree):
    # Store the result of lock in same.
    same = lock(express={"version": "4.0.0", "integrity": "sha512-SAME"})
    # Call write_json at this point.
    write_json(legacy_tree / "ftp" / "package-lock.json.bak", same)
    # Call write_json at this point.
    write_json(legacy_tree / "package-lock.json", same)
    # Check that the expression on this line.
    assert detect_changes(make_ctx(tmp_path, settings, legacy_tree, legacy_tree)).findings == []


# ---------------------------------------------------------------- compare-ref on a real (temp) git repo


# Define git for changes install tests.
# Inputs include repo.
def git(repo: Path, *args: str) -> str:
    # Store an ordered collection in cmd.
    cmd = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.test", "-c",
           # Supply the next part of the expression started above.
           "commit.gpgsign=false", *args]
    # Return the result of the expression on this line to the caller.
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()


# Apply the pytest.fixture decorator to the declaration below.
@pytest.fixture
# Define git_repo for changes install tests.
# Inputs include tmp_path.
def git_repo(tmp_path):
    # Store tmp_path / 'repo' in repo.
    repo = tmp_path / "repo"
    # Call repo.mkdir at this point.
    repo.mkdir()
    # Call git at this point.
    git(repo, "init", "-q")
    # Call write_json at this point.
    write_json(repo / "package.json", {"name": "app", "dependencies": {"express": "^4.17.1", "lodash": "^3.10.0",
                                                                        # Provide the mapping fields oldsha on this line.
                                                                        "oldsha": "1.0.0"}})
    # Call write_json at this point.
    write_json(repo / "package-lock.json", lock(
        # Supply express as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        express={"version": "4.17.1", "integrity": "sha512-ORIGINAL"},
        # Supply lodash as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        lodash={"version": "3.10.0", "integrity": "sha512-LODASH3"},
        # Supply oldsha as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        oldsha={"version": "1.0.0", "integrity": "sha1-OLD"},
        # Supply native as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        native={"version": "1.0.0", "integrity": "sha512-NATIVE"}))
    # Call git at this point.
    git(repo, "add", ".")
    # Call git at this point.
    git(repo, "commit", "-q", "-m", "base")
    # Return repo to the caller.
    return repo


# Define change_working_tree for changes install tests.
# Inputs include repo.
def change_working_tree(repo: Path) -> None:
    # Call write_json at this point.
    write_json(repo / "package.json", {"name": "app", "dependencies": {
        # Provide the mapping fields express, lodash, oldsha, newdep on this line.
        "express": "^4.17.1", "lodash": "^4.17.21", "oldsha": "1.0.0", "newdep": "^1.0.0"}})
    # Call write_json at this point.
    write_json(repo / "package-lock.json", lock(
        # Supply express as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        express={"version": "4.17.1", "integrity": "sha512-TAMPERED"},  # same name@version, different bytes
        # Supply lodash as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        lodash={"version": "4.17.21", "integrity": "sha512-LODASH4"},
        # Supply oldsha as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        oldsha={"version": "1.0.0", "integrity": "sha512-UPGRADED"},  # sha1 -> sha512: not flagged
        # Supply native as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        native={"version": "1.0.0", "integrity": "sha512-NATIVE", "hasInstallScript": True},
        # Supply newdep as named arguments to the surrounding call.
        # These names connect the values to the receiving parameters.
        newdep={"version": "1.0.0", "integrity": "sha512-NEW", "hasInstallScript": True}))


# Exercise the expected behavior for compare ref yields all four finding kinds.
def test_compare_ref_yields_all_four_finding_kinds(tmp_path, settings, git_repo):
    # Call change_working_tree at this point.
    change_working_tree(git_repo)
    # Store the result of git in head_sha.
    head_sha = git(git_repo, "rev-parse", "HEAD")
    # Store the result of detect_changes in out.
    out = detect_changes(make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref="HEAD"))

    # Store a mapping keyed by the fields below in by_cat.
    by_cat = {}
    # Iterate over out.findings.
    # Bind each item to f before processing it.
    for f in out.findings:
        # Call by_cat.setdefault(f.category, []).append at this point.
        by_cat.setdefault(f.category, []).append(f)
    # Check that the expression on this line.
    assert set(by_cat) == {FindingCategory.UNEXPECTED_CHANGE, FindingCategory.MAJOR_JUMP,
                           # Supply the next part of the expression started above.
                           FindingCategory.INTEGRITY_CHANGE, FindingCategory.INSTALL_SCRIPT}
    # Check that the expression on this line.
    assert [f.component_purl for f in by_cat[FindingCategory.UNEXPECTED_CHANGE]] == ["pkg:npm/newdep@1.0.0"]
    # Check that by_cat[FindingCategory.UNEXPECTED_CHANGE][0].line is not None.
    assert by_cat[FindingCategory.UNEXPECTED_CHANGE][0].line is not None  # located in package.json
    # Check that the expression on this line.
    assert [f.component_purl for f in by_cat[FindingCategory.MAJOR_JUMP]] == ["pkg:npm/lodash@4.17.21"]
    # Check that the expression on this line.
    assert [f.component_purl for f in by_cat[FindingCategory.INTEGRITY_CHANGE]] == ["pkg:npm/express@4.17.1"]
    # Store a lookup built from the input records in scripts.
    scripts = {f.component_purl: f.title for f in by_cat[FindingCategory.INSTALL_SCRIPT]}
    # Check that the expression on this line.
    assert set(scripts) == {"pkg:npm/native@1.0.0", "pkg:npm/newdep@1.0.0"}
    # Check that the expression on this line.
    assert "new dependency with an install script" in scripts["pkg:npm/newdep@1.0.0"]
    # Check that 'install script added' in scripts['pkg:npm/native@1.0.0'].
    assert "install script added" in scripts["pkg:npm/native@1.0.0"]
    # Check that the expression on this line.
    assert not any("oldsha" in (f.component_purl or "") for f in out.findings)  # sha1 -> sha512

    # Store values selected or transformed from the input in ev_ids.
    ev_ids = {e.evidence_id for e in out.evidence}
    # Iterate over out.findings.
    # Bind each item to f before processing it.
    for f in out.findings:
        # Check that f.evidence_ids and set(f.evidence_ids) <= ev_ids.
        assert f.evidence_ids and set(f.evidence_ids) <= ev_ids
        # Check that f.detector == 'detector:unexpected_change'.
        assert f.detector == "detector:unexpected_change"
    # Store a lookup built from the input records in diff_ev.
    diff_ev = {e.evidence_id: e for e in out.evidence if e.kind == "diff"}
    # Check that len(diff_ev) == len(out.findings).
    assert len(diff_ev) == len(out.findings)
    # Check that all(...).
    assert all(e.facts["compare_ref"] == "HEAD" for e in diff_ev.values())

    # Store out.artifacts['changes'] in changes.
    changes = out.artifacts["changes"]
    # Check that the expression on this line.
    assert changes["compare_sha"] == head_sha and changes["compare_ref"] == "HEAD"
    # Check that the expression on this line.
    assert changes["base"] == f"HEAD ({head_sha[:12]})" and changes["head"] == "working tree"
    # Check that changes['added'] == ['pkg:npm/newdep@1.0.0'].
    assert changes["added"] == ["pkg:npm/newdep@1.0.0"]
    # Check that the expression on this line.
    assert [c["purl"] for c in changes["integrity_changed"]] == ["pkg:npm/express@4.17.1"]
    # Check that the expression on this line.
    assert set(changes["evidence_ids"]) <= ev_ids and len(changes["evidence_ids"]) == len(out.evidence)
    # Store the result of next in summary_ev.
    summary_ev = next(e for e in out.evidence if e.kind == "changes")
    # Check that the expression on this line.
    assert summary_ev.facts["major_jumps"] == 1 and summary_ev.facts["integrity_changed"] == 1
    # Call json.dumps at this point.
    json.dumps(changes)  # changes.json-serialisable


# Exercise the expected behavior for compare ref unchanged tree has no findings.
def test_compare_ref_unchanged_tree_has_no_findings(tmp_path, settings, git_repo):
    # Store the result of detect_changes in out.
    out = detect_changes(make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref="HEAD"))
    # Check that out.findings == [].
    assert out.findings == []
    # Check that the expression on this line.
    assert out.artifacts["changes"]["added"] == [] and out.artifacts["changes"]["changed"] == []


# Exercise the expected behavior for compare ref against earlier commit and new project.
def test_compare_ref_against_earlier_commit_and_new_project(tmp_path, settings, git_repo):
    # Call change_working_tree at this point.
    change_working_tree(git_repo)
    # Call write_json at this point.
    write_json(git_repo / "frontend" / "package.json", {"dependencies": {"zone.js": "^0.14.0"}})
    # Call git at this point.
    git(git_repo, "add", ".")
    # Call git at this point.
    git(git_repo, "commit", "-q", "-m", "second")
    # Store the result of git in first.
    first = git(git_repo, "rev-parse", "HEAD~1")
    # Store the result of detect_changes in out.
    out = detect_changes(make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref=first))
    # Check that out.artifacts['changes']['compare_sha'] == first.
    assert out.artifacts["changes"]["compare_sha"] == first
    # Check that the expression on this line.
    assert FindingCategory.MAJOR_JUMP in {f.category for f in out.findings}
    # Check that not any(('zone.js' in f.title for f in out.findings)).
    assert not any("zone.js" in f.title for f in out.findings)  # project that did not exist at the ref


# Exercise the expected behavior for compare ref uses resolved lockfile from work copy when target has none.
def test_compare_ref_uses_resolved_lockfile_from_work_copy_when_target_has_none(tmp_path, settings, git_repo):
    # Call (git_repo / 'package-lock.json').unlink at this point.
    (git_repo / "package-lock.json").unlink()
    # Call git at this point.
    git(git_repo, "add", "-A")
    # Call git at this point.
    git(git_repo, "commit", "-q", "-m", "drop lock")
    # Store the result of git in base.
    base = git(git_repo, "rev-parse", "HEAD~1")
    # Store tmp_path / 'work' in work.
    work = tmp_path / "work"
    # Call work.mkdir at this point.
    work.mkdir()
    # Call write_json at this point.
    write_json(work / "package-lock.json", lock(express={"version": "4.17.1", "integrity": "sha512-TAMPERED"}))
    # Store the result of compare_ref_diff in (_, per_project).
    _, per_project = compare_ref_diff(git_repo, work, base)
    # Check that per_project[0]['lockfile_compared'] is True.
    assert per_project[0]["lockfile_compared"] is True
    # Check that the expression on this line.
    assert [c["purl"] for c in per_project[0]["integrity_changed"]] == ["pkg:npm/express@4.17.1"]


# Apply the pytest.mark.parametrize decorator to the declaration below.
@pytest.mark.parametrize("ref", ["--output=x", "a b", "main;rm -rf /", "$(id)", "", "-x", "a\nb"])
# Exercise the expected behavior for compare ref rejects bad ref strings.
def test_compare_ref_rejects_bad_ref_strings(tmp_path, settings, git_repo, ref):
    # Enter the context managed by pytest.raises(ValueError, match='unexpected git ref').
    with pytest.raises(ValueError, match="unexpected git ref"):
        # Call compare_ref_diff at this point.
        compare_ref_diff(git_repo, git_repo, ref)
    # Store the result of make_ctx in ctx.
    ctx = make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref=ref or "bad ref")
    # Check whether ref.
    if ref:
        # Enter the context managed by pytest.raises(ValueError).
        with pytest.raises(ValueError):
            # Call detect_changes at this point.
            detect_changes(ctx)


# Exercise the expected behavior for compare ref unknown ref fails loudly.
def test_compare_ref_unknown_ref_fails_loudly(git_repo):
    # Enter the context managed by pytest.raises(RuntimeError).
    with pytest.raises(RuntimeError):
        # Call compare_ref_diff at this point.
        compare_ref_diff(git_repo, git_repo, "no-such-branch")


# Exercise the expected behavior for compare ref findings are capped per kind.
def test_compare_ref_findings_are_capped_per_kind(tmp_path, settings, git_repo, monkeypatch):
    # Store a lookup built from the input records in deps.
    deps = {f"extra{i}": "1.0.0" for i in range(5)}
    # Call write_json at this point.
    write_json(git_repo / "package.json", {"dependencies": {"express": "^4.17.1", **deps}})
    # Call monkeypatch.setattr at this point.
    monkeypatch.setattr(unexpected_change, "MAX_FINDINGS_PER_KIND", 2)
    # Store the result of detect_changes in out.
    out = detect_changes(make_ctx(tmp_path, settings, git_repo, git_repo, compare_ref="HEAD"))
    # Check that the expression on this line.
    assert len([f for f in out.findings if f.category == FindingCategory.UNEXPECTED_CHANGE]) == 2
    # Check that len(out.artifacts['changes']['added']) == 5.
    assert len(out.artifacts["changes"]["added"]) == 5  # counts stay complete in changes.json
