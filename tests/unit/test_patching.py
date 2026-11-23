import json
from pathlib import Path

import pytest

from guardian.tools import patching
from guardian.tools.patching import PatchError, apply_op, apply_ops

PKG = """{
  "name": "app",
  "dependencies": {
    "express": "^4.0.0",
    "jsonwebtoken": "0.4.0",
    "ngy-cookie": "^6.0.0"
  },
  "devDependencies": {
    "mocha": "^10.0.0"
  }
}
"""
CI = """jobs:
  test:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 #v7.0.1
      - name: coverage
        uses: coverallsapp/github-action@v2
"""
SHA = "8d6379e14d29928660c4ba802d8e85393440b329"


@pytest.fixture
def work(tmp_path):
    (tmp_path / "package.json").write_text(PKG)
    (tmp_path / ".npmrc").write_text("package-lock=false\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(CI)
    return tmp_path


def test_set_dependency_version_diff(work):
    r = apply_op(work, {"op": "set_dependency_version", "file_path": "package.json",
                        "args": {"name": "jsonwebtoken", "version": "9.0.2"}})
    assert '-    "jsonwebtoken": "0.4.0",' in r.diff and '+    "jsonwebtoken": "9.0.2",' in r.diff
    assert json.loads((work / "package.json").read_text())["dependencies"]["jsonwebtoken"] == "9.0.2"
    assert r.facts["from"] == "0.4.0" and r.file_path == "package.json"


def test_remove_last_entry_keeps_valid_json(work):
    r = apply_op(work, {"op": "remove_dependency", "file_path": "package.json", "args": {"name": "ngy-cookie"}})
    data = json.loads((work / "package.json").read_text())  # trailing comma fixed
    assert "ngy-cookie" not in data["dependencies"] and data["dependencies"]["jsonwebtoken"] == "0.4.0"
    assert '-    "ngy-cookie": "^6.0.0"' in r.diff


def test_replace_dependency(work):
    apply_op(work, {"op": "replace_dependency", "file_path": "package.json",
                    "args": {"name": "ngy-cookie", "new_name": "ngx-cookie", "version": "^6.0.1"}})
    deps = json.loads((work / "package.json").read_text())["dependencies"]
    assert "ngy-cookie" not in deps and deps["ngx-cookie"] == "^6.0.1"


def test_pin_action_sha_with_resolver(work):
    r = patching.pin_action_sha(work, ".github/workflows/ci.yml", {"action": "coverallsapp/github-action", "ref": "v2"},
                                resolver=lambda a, ref: SHA)
    text = (work / ".github/workflows/ci.yml").read_text()
    assert f"uses: coverallsapp/github-action@{SHA} # v2" in text
    assert "actions/checkout@3d3c42e5" in text  # untouched
    assert r.facts["occurrences"] == 1 and "-        uses: coverallsapp/github-action@v2" in r.diff


def test_generate_lockfile_drops_npmrc_setting(work):
    def fake_resolve(d):
        (Path(d) / "package-lock.json").write_text('{"lockfileVersion": 3}')
        return {"flags": ["--package-lock-only", "--ignore-scripts"]}

    r = patching.generate_lockfile(work, "package.json", {}, resolver=fake_resolve)
    assert (work / ".npmrc").read_text() == "" and "-package-lock=false" in r.diff
    assert r.facts["npmrc_changed"] and r.facts["lockfile"] == "package-lock.json"
    assert "--ignore-scripts" in r.facts["resolve_flags"]


@pytest.mark.parametrize("path", ["../outside.json", "/etc/passwd", "..\\x.json"])
def test_refuses_paths_outside_work_copy(work, path):
    with pytest.raises((PermissionError, PatchError)):
        apply_op(work, {"op": "set_dependency_version", "file_path": path, "args": {"name": "x", "version": "1"}})


@pytest.mark.parametrize("args", [{"name": "express", "version": "1.0.0; rm -rf /"},
                                  {"name": "../evil", "version": "1.0.0"},
                                  {"name": "not-declared", "version": "1.0.0"}])
def test_rejects_bad_args(work, args):
    with pytest.raises(PatchError):
        apply_op(work, {"op": "set_dependency_version", "file_path": "package.json", "args": args})


def test_unknown_op_and_missing_action(work):
    with pytest.raises(PatchError):
        apply_op(work, {"op": "git_push", "file_path": "package.json", "args": {}})
    with pytest.raises(PatchError):
        patching.pin_action_sha(work, ".github/workflows/ci.yml", {"action": "foo/bar", "ref": "v1", "sha": SHA})


def test_apply_ops_emits_patch_diff_evidence(work, tmp_path_factory):
    out = tmp_path_factory.mktemp("patches")
    results, ev = apply_ops(work, [
        {"op": "set_dependency_version", "file_path": "package.json", "args": {"name": "express", "version": "4.21.2"}},
        {"op": "pin_action_sha", "file_path": ".github/workflows/ci.yml",
         "args": {"action": "coverallsapp/github-action", "ref": "v2", "sha": SHA}},
    ], "run_t", out)
    assert [e.kind for e in ev] == ["patch_diff", "patch_diff"]
    assert ev[0].facts["lines_added"] == 1 and ev[0].facts["lines_removed"] == 1
    assert Path(ev[1].artifact_path).read_text() == results[1].diff
