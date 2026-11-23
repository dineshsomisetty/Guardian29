"""D2-07 patch ops, confinement (G6.6) and the plan_preview / apply_plan / resolve_action_sha tools."""

import dataclasses
import json
from pathlib import Path

import pytest

from guardian.core.models import Evidence, PatchOp, new_id
from guardian.tools import patching
from guardian.tools.patching import (
    ActionRefArgs,
    PatchError,
    PlanArgs,
    apply_ops,
    apply_plan,
    confined,
    plan_preview,
    resolve_action_sha,
)
from guardian.tools.registry import ToolContext

PACKAGE_JSON = """{
  "name": "demo",
  "version": "1.0.0",
  "scripts": {
    "lodash": "echo scripts section is not a dependency section"
  },
  "dependencies": {
    "express": "^4.17.1",
    "lodash": "4.17.15",
    "moment": "~2.29.1"
  },
  "devDependencies": {
    "mocha": "^9.0.0"
  }
}
"""

WORKFLOW = """name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v4 # node
        with:
          node-version: 20
      - uses: "actions/cache@v3"
"""

SHA = "a" * 40


def op(kind, file_path="package.json", /, **args):
    return PatchOp(op=kind, file_path=file_path, args=args)


def one(tmp_path: Path, text: str, o: PatchOp, filename="package.json") -> str:
    (tmp_path / filename).write_text(text, encoding="utf-8", newline="")
    apply_ops(tmp_path, [o], None, write=True)
    return (tmp_path / filename).read_bytes().decode("utf-8")


def changed_lines(before: str, after: str) -> list[int]:
    b, a = before.splitlines(keepends=True), after.splitlines(keepends=True)
    return [i for i in range(min(len(a), len(b))) if a[i] != b[i]]


# ---------------------------------------------------------------- package.json ops


def test_set_dependency_version_touches_only_that_line(tmp_path):
    out = one(tmp_path, PACKAGE_JSON, op("set_dependency_version", name="lodash", version="4.17.21"))
    assert json.loads(out)["dependencies"]["lodash"] == "4.17.21"
    assert json.loads(out)["scripts"]["lodash"].startswith("echo")  # same name in scripts is not edited
    assert out == PACKAGE_JSON.replace('"lodash": "4.17.15"', '"lodash": "4.17.21"')


def test_set_dependency_version_in_dev_dependencies(tmp_path):
    out = one(tmp_path, PACKAGE_JSON, op("set_dependency_version", name="mocha", version="^10.2.0"))
    assert json.loads(out)["devDependencies"]["mocha"] == "^10.2.0"
    assert changed_lines(PACKAGE_JSON, out) == [12]


def test_set_dependency_version_preserves_crlf(tmp_path):
    crlf = PACKAGE_JSON.replace("\n", "\r\n")
    out = one(tmp_path, crlf, op("set_dependency_version", name="express", version="4.19.2"))
    assert out == crlf.replace("^4.17.1", "4.19.2")
    assert "\r\n" in out and "\n" not in out.replace("\r\n", "")


@pytest.mark.parametrize("version", ['1.0.0", "evil": "x', "1.0.0\n", "$(rm)", ""])
def test_set_dependency_version_rejects_unexpected_version_spec(tmp_path, version):
    (tmp_path / "package.json").write_text(PACKAGE_JSON)
    with pytest.raises(PatchError):
        apply_ops(tmp_path, [op("set_dependency_version", name="lodash", version=version)], None, write=True)
    assert (tmp_path / "package.json").read_text() == PACKAGE_JSON


def test_remove_middle_dependency_keeps_commas(tmp_path):
    out = one(tmp_path, PACKAGE_JSON, op("remove_dependency", name="lodash"))
    assert list(json.loads(out)["dependencies"]) == ["express", "moment"]
    assert out == PACKAGE_JSON.replace('    "lodash": "4.17.15",\n', "")


def test_remove_last_dependency_drops_trailing_comma(tmp_path):
    out = one(tmp_path, PACKAGE_JSON, op("remove_dependency", name="moment"))
    assert list(json.loads(out)["dependencies"]) == ["express", "lodash"]
    assert '"4.17.15"\n  }' in out
    assert out == PACKAGE_JSON.replace('"lodash": "4.17.15",\n    "moment": "~2.29.1"', '"lodash": "4.17.15"')


def test_remove_only_dependency_in_section_still_parses(tmp_path):
    out = one(tmp_path, PACKAGE_JSON, op("remove_dependency", name="mocha"))
    assert json.loads(out)["devDependencies"] == {}


def test_replace_dependency_renames_and_sets_version(tmp_path):
    out = one(tmp_path, PACKAGE_JSON, op("replace_dependency", name="moment", new_name="dayjs", version="^1.11.10"))
    deps = json.loads(out)["dependencies"]
    assert "moment" not in deps and deps["dayjs"] == "^1.11.10"
    assert changed_lines(PACKAGE_JSON, out) == [9]


def test_replace_dependency_without_version_keeps_range(tmp_path):
    out = one(tmp_path, PACKAGE_JSON, op("replace_dependency", name="moment", new_name="dayjs"))
    assert json.loads(out)["dependencies"]["dayjs"] == "~2.29.1"


def test_unknown_dependency_raises(tmp_path):
    (tmp_path / "package.json").write_text(PACKAGE_JSON)
    for o in (op("set_dependency_version", name="nope", version="1.0.0"), op("remove_dependency", name="nope"),
              op("replace_dependency", name="nope", new_name="other")):
        with pytest.raises(PatchError, match="not found"):
            apply_ops(tmp_path, [o], None, write=True)


def test_invalid_package_name_is_rejected(tmp_path):
    (tmp_path / "package.json").write_text(PACKAGE_JSON)
    with pytest.raises(PatchError, match="package name"):
        apply_ops(tmp_path, [op("remove_dependency", name='lodash": "1')], None, write=True)


def test_unimplemented_op_raises(tmp_path):
    (tmp_path / "package.json").write_text(PACKAGE_JSON)
    with pytest.raises(PatchError, match="not implemented"):
        apply_ops(tmp_path, [op("block_package", name="x")], None, write=True)


def test_ops_on_same_file_compose_and_manifest_still_parses(tmp_path):
    (tmp_path / "package.json").write_text(PACKAGE_JSON)
    ops = [op("set_dependency_version", name="lodash", version="4.17.21"), op("remove_dependency", name="moment")]
    results = apply_ops(tmp_path, ops, None, write=True)
    data = json.loads((tmp_path / "package.json").read_text())
    assert data["dependencies"] == {"express": "^4.17.1", "lodash": "4.17.21"}
    assert [r["op"] for r in results] == ["set_dependency_version", "remove_dependency"]
    assert all("package.json" in r["diff"] for r in results)


def test_write_false_changes_nothing_but_returns_diff(tmp_path):
    (tmp_path / "package.json").write_text(PACKAGE_JSON)
    results = apply_ops(tmp_path, [op("remove_dependency", name="lodash")], None, write=False)
    assert (tmp_path / "package.json").read_text() == PACKAGE_JSON
    assert '-    "lodash": "4.17.15",' in results[0]["diff"]


def test_edit_that_breaks_json_is_refused_and_not_written(tmp_path):
    broken = PACKAGE_JSON.replace('"mocha": "^9.0.0"', '"mocha": "^9.0.0",')  # trailing comma already invalid
    (tmp_path / "package.json").write_text(broken)
    with pytest.raises(json.JSONDecodeError):
        apply_ops(tmp_path, [op("set_dependency_version", name="express", version="4.19.2")], None, write=True)
    assert (tmp_path / "package.json").read_text() == broken


# ---------------------------------------------------------------- workflow ops


def test_pin_action_sha_rewrites_only_the_uses_line(tmp_path):
    out = one(tmp_path, WORKFLOW, op("pin_action_sha", "ci.yml", action="actions/checkout", ref="v3", sha=SHA), filename="ci.yml")
    assert out == WORKFLOW.replace("actions/checkout@v3", f"actions/checkout@{SHA} # v3")


def test_pin_action_sha_replaces_existing_comment_and_keeps_quotes(tmp_path):
    out = one(tmp_path, WORKFLOW, op("pin_action_sha", "ci.yml", action="actions/setup-node", ref="v4", sha=SHA),
              filename="ci.yml")
    assert f"- uses: actions/setup-node@{SHA} # v4\n" in out
    assert "# node" not in out
    out2 = one(tmp_path, WORKFLOW, op("pin_action_sha", "ci.yml", action="actions/cache", ref="v3", sha=SHA),
               filename="ci.yml")
    assert f'- uses: "actions/cache@{SHA}" # v3\n' in out2


@pytest.mark.parametrize("sha", ["v3", "a" * 39, "a" * 41, "A" * 40, "g" * 40, "", "a" * 40 + "\n"])
def test_pin_action_sha_rejects_non_40_hex(tmp_path, sha):
    (tmp_path / "ci.yml").write_text(WORKFLOW)
    with pytest.raises(PatchError, match="40-char"):
        apply_ops(tmp_path, [op("pin_action_sha", "ci.yml", action="actions/checkout", ref="v3", sha=sha)], None,
                  write=True)
    assert (tmp_path / "ci.yml").read_text() == WORKFLOW


def test_pin_action_sha_unknown_use_raises(tmp_path):
    (tmp_path / "ci.yml").write_text(WORKFLOW)
    with pytest.raises(PatchError, match="not found"):
        apply_ops(tmp_path, [op("pin_action_sha", "ci.yml", action="actions/checkout", ref="v9", sha=SHA)], None,
                  write=True)


# ---------------------------------------------------------------- generate_lockfile


def test_generate_lockfile_drops_disable_and_copies_lockfiles(tmp_path):
    root, src = tmp_path / "copy", tmp_path / "resolved"
    (root / "frontend").mkdir(parents=True)
    (src / "frontend").mkdir(parents=True)
    npmrc = "registry=https://registry.npmjs.org/\npackage-lock=false\nsave-exact=true\n"
    (root / ".npmrc").write_text(npmrc)
    (src / "package-lock.json").write_text('{"lockfileVersion": 3}\n')
    (src / "frontend" / "package-lock.json").write_text('{"lockfileVersion": 3, "x": 1}\n')

    results = apply_ops(root, [op("generate_lockfile", ".npmrc", projects=["root", "frontend"])], src, write=True)

    assert (root / ".npmrc").read_text() == "registry=https://registry.npmjs.org/\nsave-exact=true\n"
    assert (root / "package-lock.json").read_text() == '{"lockfileVersion": 3}\n'
    assert (root / "frontend" / "package-lock.json").read_text() == '{"lockfileVersion": 3, "x": 1}\n'
    assert [lf["file"] for lf in results[0]["lockfiles"]] == ["package-lock.json", "frontend/package-lock.json"]
    assert "--ignore-scripts" in results[0]["lockfiles"][0]["source"]


def test_generate_lockfile_without_resolved_lockfile_raises(tmp_path):
    (tmp_path / ".npmrc").write_text("package-lock=false\n")
    with pytest.raises(PatchError, match="no resolved lockfile"):
        apply_ops(tmp_path, [op("generate_lockfile", ".npmrc", projects=["root"])], None, write=True)
    with pytest.raises(PatchError, match="no resolved lockfile"):
        apply_ops(tmp_path, [op("generate_lockfile", ".npmrc", projects=["root"])], tmp_path / "empty", write=True)


def test_generate_lockfile_project_cannot_escape(tmp_path):
    root, src = tmp_path / "copy", tmp_path / "resolved"
    root.mkdir()
    src.mkdir()
    (root / ".npmrc").write_text("package-lock=false\n")
    (tmp_path / "package-lock.json").write_text("{}")
    with pytest.raises(PatchError, match="outside"):
        apply_ops(root, [op("generate_lockfile", ".npmrc", projects=[".."])], src, write=True)


# ---------------------------------------------------------------- confinement (G6.6)


def test_confined_accepts_inside_and_refuses_escape(tmp_path):
    assert confined(tmp_path, "a/b.txt") == (tmp_path / "a" / "b.txt").resolve()
    for bad in ("../x", "a/../../x", str(tmp_path.parent / "x"), ".", ""):
        with pytest.raises(PatchError, match="outside"):
            confined(tmp_path, bad)


def test_apply_ops_refuses_path_escape_without_writing(tmp_path):
    root = tmp_path / "copy"
    root.mkdir()
    (tmp_path / "x").write_text(PACKAGE_JSON)
    for bad in ("../x", str(tmp_path / "x")):
        with pytest.raises(PatchError, match="outside"):
            apply_ops(root, [op("set_dependency_version", bad, name="lodash", version="1.0.0")], None, write=True)
    assert (tmp_path / "x").read_text() == PACKAGE_JSON


# ---------------------------------------------------------------- tools


@pytest.fixture
def ctx(tmp_path, settings):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(PACKAGE_JSON)
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "junk.js").write_text("x")
    (repo / ".github").mkdir()
    (repo / ".github" / "ci.yml").write_text(WORKFLOW)
    run_dir = tmp_path / "runs" / "run_1"
    run_dir.mkdir(parents=True)
    return ToolContext(run_id="run_1", run_dir=run_dir, repo=repo, settings=settings)


def snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def plan_args(*ops: PatchOp, attempt: str | None = None) -> PlanArgs:
    return PlanArgs(plan_id=new_id("pl"), attempt_id=attempt, ops=list(ops))


def test_plan_args_validation():
    good = op("remove_dependency", name="lodash")
    with pytest.raises(ValueError):
        PlanArgs(plan_id="pl_bad", ops=[good])
    with pytest.raises(ValueError):
        PlanArgs(plan_id=new_id("pl"), attempt_id="at_bad", ops=[good])
    with pytest.raises(ValueError):
        PlanArgs(plan_id=new_id("pl"), ops=[])
    with pytest.raises(ValueError):
        PlanArgs(plan_id=new_id("pl"), ops=[good] * 21)


@pytest.mark.parametrize("action,ref", [("../x", "v1"), ("a/b", "v1;ls"), ("a/b", "x..y"), ("a/..", "v1"), ("nope", "v1")])
def test_action_ref_args_reject_bad_input(action, ref):
    with pytest.raises(ValueError):
        ActionRefArgs(action=action, ref=ref)


def test_action_ref_args_accept_normal_input():
    assert ActionRefArgs(action="actions/checkout", ref="v4.1.1").ref == "v4.1.1"
    assert ActionRefArgs(action="github/codeql-action/analyze", ref="main").action.endswith("analyze")


def test_plan_preview_writes_nothing(ctx):
    before_repo = snapshot(ctx.repo)
    out = plan_preview(ctx, plan_args(op("set_dependency_version", name="lodash", version="4.17.21"),
                                      op("pin_action_sha", ".github/ci.yml", action="actions/checkout", ref="v3",
                                         sha=SHA)))
    assert snapshot(ctx.repo) == before_repo
    assert list(ctx.run_dir.iterdir()) == []
    assert '+    "lodash": "4.17.21",' in out.artifacts["preview_diff"]
    assert f"actions/checkout@{SHA} # v3" in out.artifacts["preview_diff"]
    (ev,) = out.evidence
    assert ev.kind == "patch_diff" and ev.facts["preview"] is True
    assert ev.facts["files"] == [".github/ci.yml", "package.json"]


def test_plan_preview_generate_lockfile_does_not_copy(ctx, tmp_path):
    (ctx.repo / ".npmrc").write_text("package-lock=false\n")
    resolved = tmp_path / "resolved"
    resolved.mkdir()
    (resolved / "package-lock.json").write_text("{}\n")
    ctx.work_dir = resolved
    out = plan_preview(ctx, plan_args(op("generate_lockfile", ".npmrc", projects=["root"])))
    assert not (ctx.repo / "package-lock.json").exists()
    assert (ctx.repo / ".npmrc").read_text() == "package-lock=false\n"
    assert out.evidence[0].facts["lockfiles_added"] == ["package-lock.json"]


def test_apply_plan_builds_attempt_work_copy(ctx):
    attempt = new_id("at")
    before_repo = snapshot(ctx.repo)
    out = apply_plan(ctx, plan_args(op("remove_dependency", name="moment"), attempt=attempt))
    work = ctx.run_dir / "attempts" / attempt / "work"
    assert out.artifacts["attempt_dir"] == work
    assert "moment" not in json.loads((work / "package.json").read_text())["dependencies"]
    assert (work / ".github" / "ci.yml").read_text() == WORKFLOW  # untouched files copied verbatim
    assert not (work / "node_modules").exists()  # same ignore rules as the discovery work copy
    assert snapshot(ctx.repo) == before_repo
    assert out.evidence[0].facts["attempt_id"] == attempt and out.evidence[0].facts["preview"] is False


def test_apply_plan_refuses_reused_attempt_id(ctx):
    attempt = new_id("at")
    args = plan_args(op("remove_dependency", name="moment"), attempt=attempt)
    apply_plan(ctx, args)
    marker = ctx.run_dir / "attempts" / attempt / "work" / "package.json"
    first = marker.read_text()
    with pytest.raises(PatchError, match="already exists"):
        apply_plan(ctx, args)
    assert marker.read_text() == first


def test_apply_plan_requires_attempt_id(ctx):
    with pytest.raises(PatchError, match="attempt_id"):
        apply_plan(ctx, plan_args(op("remove_dependency", name="moment")))
    assert not (ctx.run_dir / "attempts").exists()


def test_apply_plan_path_escape_is_refused(ctx):
    with pytest.raises(PatchError, match="outside"):
        apply_plan(ctx, plan_args(op("set_dependency_version", "../x", name="a", version="1"), attempt=new_id("at")))


# ---------------------------------------------------------------- resolve_action_sha


@pytest.fixture
def sha_env(tmp_path, monkeypatch):
    cache = tmp_path / "cache" / "action_shas.json"
    monkeypatch.setattr(patching, "_SHA_CACHE", cache)
    calls: list[tuple[str, str]] = []

    def fake_ls_remote(action, ref):
        calls.append((action, ref))
        return SHA, "tag"

    monkeypatch.setattr(patching, "ls_remote", fake_ls_remote)
    return cache, calls


def test_resolve_action_sha_queries_then_caches(ctx, sha_env):
    cache, calls = sha_env
    args = ActionRefArgs(action="actions/checkout", ref="v3")
    out = resolve_action_sha(ctx, args)
    assert out.artifacts["action_sha"] == SHA and calls == [("actions/checkout", "v3")]
    assert json.loads(cache.read_text())["actions/checkout@v3"] == {"sha": SHA, "ref_type": "tag"}
    again = resolve_action_sha(ctx, args)
    assert again.artifacts["action_sha"] == SHA and calls == [("actions/checkout", "v3")]  # no second lookup
    assert again.evidence[0].facts["source"] == "cache"


def test_resolve_action_sha_writes_registry_metadata_evidence(ctx, sha_env):
    out = resolve_action_sha(ctx, ActionRefArgs(action="actions/checkout", ref="v3"))
    (ev,) = out.evidence
    assert isinstance(ev, Evidence) and ev.kind == "registry_metadata"
    assert ev.facts == {"action": "actions/checkout", "ref": "v3", "sha": SHA, "ref_type": "tag",
                        "source": "git ls-remote github.com"}


def test_resolve_action_sha_offline_uses_cache_only(ctx, sha_env):
    cache, calls = sha_env
    cache.parent.mkdir(parents=True)
    cache.write_text(json.dumps({"actions/checkout@v3": {"sha": SHA, "ref_type": "tag"}}))
    ctx.settings = dataclasses.replace(ctx.settings, offline=True)
    assert resolve_action_sha(ctx, ActionRefArgs(action="actions/checkout", ref="v3")).artifacts["action_sha"] == SHA
    with pytest.raises(PatchError, match="not in cache"):
        resolve_action_sha(ctx, ActionRefArgs(action="actions/setup-node", ref="v4"))
    assert calls == []


def test_resolve_action_sha_ignores_corrupt_cache(ctx, sha_env):
    cache, calls = sha_env
    cache.parent.mkdir(parents=True)
    cache.write_text("{not json")
    assert resolve_action_sha(ctx, ActionRefArgs(action="actions/checkout", ref="v3")).artifacts["action_sha"] == SHA
    assert calls == [("actions/checkout", "v3")]


def test_ls_remote_prefers_peeled_tag_and_validates_sha(monkeypatch):
    annotated, peeled = "b" * 40, "c" * 40
    stdout = (f"{annotated}\trefs/tags/v3\n{peeled}\trefs/tags/v3^{{}}\n" f"{'d' * 40}\trefs/heads/v3\n")

    class Proc:
        pass

    proc = Proc()
    proc.stdout = stdout
    monkeypatch.setattr(patching, "run", lambda *a, **k: proc)
    assert patching.ls_remote("actions/checkout", "v3") == (peeled, "tag")
    proc.stdout = ""
    with pytest.raises(PatchError, match="not found"):
        patching.ls_remote("actions/checkout", "v3")
    proc.stdout = "not-a-sha\trefs/heads/v3\n"
    with pytest.raises(PatchError, match="not found"):
        patching.ls_remote("actions/checkout", "v3")
