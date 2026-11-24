"""Sharded integration suite and the fast path for CI/container-only fixes. Every docker call is a fake."""

import json
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from guardian.core.models import PatchOp
from guardian.tools import sandbox
from guardian.tools.registry import ToolContext

API = 'node --import ./helpers/env.mjs --import tsx --test --test-force-exit "test/api/**/*.test.ts"'
SCRIPTS = {"build:server": "tsc", "test:server": "node --test unit", "test:api": API}
AT = "at_" + "S" * 26
SUFFIX = AT[-10:].lower()


def make_project(root: Path, nfiles: int = 7, scripts=None) -> Path:
    (root / "test" / "api" / "helpers").mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"scripts": scripts or SCRIPTS}))
    (root / "package-lock.json").write_text("{}")
    for i in range(nfiles):
        (root / "test" / "api" / f"t{i}.test.ts").write_text("x" * (100 * (i + 1)))
    (root / "test" / "api" / "helpers" / "setup.ts").write_text("not a test")
    (root / "test" / "api" / "sub").mkdir(exist_ok=True)
    (root / "test" / "api" / "sub" / "deep.test.ts").write_text("y" * 50)
    return root


class Fake:
    """Thread-safe fake docker: per-shard exit codes / timeouts, records mounts and removals."""

    def __init__(self, shard_rc=None, timeout_shard=None, delay=0.0, unit_rc=0):
        self.calls, self.lock = [], threading.Lock()
        self.images: set[str] = set()
        self.shard_rc = shard_rc or {}
        self.timeout_shard, self.delay, self.unit_rc = timeout_shard, delay, unit_rc
        self.running = self.peak = 0
        self.shard_files: list[list[str]] = []
        self.mounts: list[str] = []

    def __call__(self, argv, timeout):
        with self.lock:
            self.calls.append(argv)
        cp = lambda rc, out="": subprocess.CompletedProcess(argv, rc, out, "")  # noqa: E731
        sub = argv[1]
        if sub == "info":
            return cp(0)
        if sub == "image":
            return cp(0 if argv[-1] in self.images else 1)
        if sub == "build":
            with self.lock:
                self.images.add(argv[argv.index("-t") + 1])
            return cp(0, "built")
        if sub == "rm":
            return cp(0)
        script, name = argv[-1], argv[argv.index("--name") + 1]
        if sub == "run" and ("test:server" in script or "--test" in script or "test:api" in script):
            with self.lock:
                self.running += 1
                self.peak = max(self.peak, self.running)
                self.mounts.append(next(a for a in argv if a.startswith("type=bind")))
            try:
                time.sleep(self.delay)
                if "--test-force-exit" in script and "test:api" not in script:
                    files = [w for w in script.split() if w.endswith(".test.ts")]
                    with self.lock:
                        self.shard_files.append(files)
                    k = int(name.rsplit("-", 1)[1])
                    if self.timeout_shard == k:
                        raise subprocess.TimeoutExpired(argv, timeout, output="partial")
                    rc = self.shard_rc.get(k, 0)
                    n = len(files)
                    out = (f"# pass {n - (1 if rc else 0)}\n# fail {1 if rc else 0}\n"
                           + (f"not ok 1 - broken in shard {k}\n" if rc else ""))
                    return cp(rc, out)
                if "test:server" in script:
                    return cp(self.unit_rc, "# pass 3\n# fail 0\n")
                return cp(0, "# pass 9\n# fail 0\n")
            finally:
                with self.lock:
                    self.running -= 1
        return cp(0, "build ok")


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setenv("GUARDIAN_SANDBOX", "docker")
    monkeypatch.setattr(sandbox, "_inflight", {})
    yield
    sandbox.set_runner(None)


def run(work, fake):
    sandbox.set_runner(fake)
    return sandbox.run_sandbox(work, AT, fake, 60)


def work_dir(tmp_path, **kw):
    return make_project(tmp_path / "run" / "attempts" / AT / "work", **kw)


# ---------------------------------------------------------------- split


def test_split_is_deterministic_complete_and_exclusive(tmp_path):
    w = make_project(tmp_path / "w")
    files = sandbox.test_files(w, ["test/api/**/*.test.ts"])
    assert len(files) == 8 and "test/api/helpers/setup.ts" not in files and "test/api/sub/deep.test.ts" in files
    a = sandbox.split_files(w, files, 3)
    assert a == sandbox.split_files(w, list(reversed(files)), 3)  # input order does not matter
    flat = [f for sh in a for f in sh]
    assert sorted(flat) == files and len(flat) == len(set(flat))  # every file in exactly one shard
    sizes = [sum((w / f).stat().st_size for f in sh) for sh in a]
    assert max(sizes) - min(sizes) <= 400  # balanced by size, not by count
    assert len(sandbox.split_files(w, files, 99)) == 8 and sandbox.split_files(w, files, 1) == [files]


def test_commands_replace_the_glob_with_the_shards_files(tmp_path):
    w = make_project(tmp_path / "w")
    cmds, why = sandbox.shard_commands(w, "test:api", 3)
    assert why == "" and len(cmds) == 3
    for c in cmds:
        assert c.startswith("node --import ./helpers/env.mjs --import tsx --test --test-force-exit test/api/")
        assert "**" not in c
    assert sum(c.count(".test.ts") for c in cmds) == 8


@pytest.mark.parametrize("script", [
    "npm run a && npm run b", "jest --runInBand", "node --test", 'node --test "test/api/**/*.test.ts" | tee x',
    "nyc node --test \"test/api/**/*.test.ts\"", 'node --test "../x/*.test.ts"'])
def test_unsplittable_scripts_fall_back_with_a_reason(tmp_path, script):
    w = make_project(tmp_path / "w", scripts={"test:api": script})
    cmds, why = sandbox.shard_commands(w, "test:api", 3)
    assert cmds == [] and why


def test_pre_hook_or_single_file_is_not_split(tmp_path):
    w = make_project(tmp_path / "w", scripts={"test:api": API, "pretest:api": "echo hi"})
    assert sandbox.shard_commands(w, "test:api", 3)[0] == []
    w2 = make_project(tmp_path / "w2", nfiles=0)
    (w2 / "test" / "api" / "sub" / "deep.test.ts").unlink()
    assert "nothing to split" in sandbox.shard_commands(w2, "test:api", 3)[1]


# ---------------------------------------------------------------- run


def test_sharded_run_merges_counts_and_lists_phases_in_order(tmp_path):
    w = work_dir(tmp_path)
    fake = Fake(delay=0.1)
    res = run(w, fake)
    assert [p.name for p in res.phases] == ["install", "build", "test", "integration-1", "integration-2", "integration-3"]
    assert res.shards == 3 and res.verdict is None
    assert res.integration_tests == {"passed": 8, "failed": 0, "total": 8}  # summed over the shards
    assert sorted(f for fs in fake.shard_files for f in fs) == sandbox.test_files(w, ["test/api/**/*.test.ts"])
    assert fake.peak == 4  # unit + 3 shards at the same time
    assert len(set(fake.mounts)) == 4  # never one shared writable directory
    for a in (a for a in fake.calls if a[1] == "run"):
        assert a[a.index("--network") + 1] == "none" and "--rm" in a and "--read-only" in a
        assert a[a.index("--user") + 1] == "1000:1000" and "no-new-privileges" in a
        assert a[a.index("--memory") + 1] == "4g" and a[a.index("--cpus") + 1] == "2"
    removed = {a[-1] for a in fake.calls if a[1] == "rm"}
    assert {f"guardian-{SUFFIX}-integration-{k}" for k in (1, 2, 3)} <= removed
    assert not list(w.parent.glob(".par-*"))  # every snapshot gone


def test_failing_shard_gives_failed_tests_with_unioned_names(tmp_path):
    w = work_dir(tmp_path)
    res = run(w, Fake(shard_rc={1: 1, 3: 1}))
    assert res.verdict == "failed_tests"
    assert res.integration_tests["failed"] == 2 and res.integration_tests["total"] == 8
    assert res.failed_names["integration"] == ["broken in shard 1", "broken in shard 3"]
    assert not list(w.parent.glob(".par-*"))


def test_timeout_shard_is_timeout_and_everything_is_removed(tmp_path):
    w = work_dir(tmp_path)
    fake = Fake(timeout_shard=2, delay=0.05, shard_rc={1: 1})
    res = run(w, fake)
    assert res.verdict == "timeout"  # outranks the failed sibling
    assert [p.name for p in res.phases][-4:] == ["test", "integration-1", "integration-2", "integration-3"]
    assert res.phases[-2].timed_out
    removed = {a[-1] for a in fake.calls if a[1] == "rm"}
    assert {f"guardian-{SUFFIX}-{n}" for n in ("build", "test", "integration-1", "integration-2", "integration-3")} <= removed
    assert not list(w.parent.glob(".par-*"))


def test_one_shard_equals_the_old_single_container(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_SANDBOX_SHARDS", "1")
    w = work_dir(tmp_path)
    fake = Fake()
    res = run(w, fake)
    assert [p.name for p in res.phases] == ["install", "build", "test", "integration"] and res.shards == 1
    assert res.shard_note == "GUARDIAN_SANDBOX_SHARDS=1"
    assert any("npm run test:api" in a[-1] for a in fake.calls if a[1] == "run")
    assert res.integration_tests["total"] == 9  # the fake's whole-suite answer, unchanged


def test_unshardable_script_keeps_one_container_and_says_why(tmp_path):
    w = work_dir(tmp_path, scripts={**SCRIPTS, "test:api": "jest --runInBand"})
    res = run(w, Fake())
    assert [p.name for p in res.phases][-1] == "integration" and res.shards == 1 and "not a `node --test`" in res.shard_note


def test_baseline_comparison_still_excuses_failures_that_already_exist(tmp_path):
    ctx = SimpleNamespace(settings=SimpleNamespace(llm_cache_dir=tmp_path / "c" / "llm"), run_dir=tmp_path / "run")
    base = {"lock_hash": "k", "verdict": "failed_tests", "build_ok": True, "unit_tests": {"passed": 3, "failed": 0, "total": 3},
            "integration_tests": {"passed": 7, "failed": 1, "total": 8},
            "failed_names": {"integration": ["broken in shard 1"]}}
    w = work_dir(tmp_path)
    res = run(w, Fake(shard_rc={1: 1}))  # shard 1 fails with the same test the baseline already had
    sandbox.compare_with_baseline(ctx, res, Fake(), base)
    assert res.verdict is None and res.failed_names["new_vs_baseline"] == []
    res2 = run(work_dir(tmp_path / "again"), Fake(shard_rc={2: 1}))  # a different test fails: blamed on the fix
    sandbox.compare_with_baseline(ctx, res2, Fake(), base)
    assert res2.verdict == "failed_tests" and res2.failed_names["new_vs_baseline"] == ["broken in shard 2"]


# ---------------------------------------------------------------- fast path


def op(kind, path):
    return PatchOp(op=kind, file_path=path, args={})


def plan(*ops):
    return SimpleNamespace(ops=list(ops))


def test_fast_path_accepts_only_ci_and_container_files():
    ok = [plan(op("pin_action_sha", ".github/workflows/ci.yml")),
          plan(op("pin_image_digest", "Dockerfile")),
          plan(op("update_base_image", "docker/Dockerfile.prod"), op("pin_image_digest", "docker-compose.test.yml")),
          plan(op("pin_action_sha", ".gitlab-ci.yml"))]
    for p in ok:
        assert sandbox.fast_path_files([p]) is not None
    files = sandbox.fast_path_files(ok)
    assert files == sorted(set(files)) and ".github/workflows/ci.yml" in files


@pytest.mark.parametrize("bad", [
    plan(op("pin_action_sha", ".github/workflows/ci.yml"), op("set_dependency_version", "package.json")),
    plan(op("pin_action_sha", "package.json")),  # right op, wrong file
    plan(op("pin_action_sha", "src/app.ts")),
    plan(op("pin_image_digest", "Dockerfile.sh/../server.ts")),
    plan(op("pin_image_digest", "../Dockerfile")),
    plan(op("pin_action_sha", ".github/../src/x.yml")),
    plan(op("block_package", "package.json")),
    plan(op("generate_lockfile", ".npmrc")),
    plan(op("rename_import", "Dockerfile")),  # a source op even on an allowed name
    plan(op("pin_image_digest", "my-Dockerfile.txt")),
])
def test_fast_path_refused_for_anything_else(bad):
    assert sandbox.fast_path_files([bad]) is None
    assert sandbox.fast_path_files([plan(op("pin_action_sha", ".github/a.yml")), bad]) is None  # one bad plan sinks the set


def test_fast_path_opt_out_and_empty(monkeypatch):
    assert sandbox.fast_path_files([]) is None
    monkeypatch.setenv("GUARDIAN_SANDBOX_FAST_PATH", "0")
    assert sandbox.fast_path_files([plan(op("pin_action_sha", ".github/a.yml"))]) is None


def test_fast_path_result_says_what_was_not_run_and_never_claims_a_pass(tmp_path):
    fake = Fake()
    res = sandbox.fast_path_validate(tmp_path, tmp_path, "r", AT, fake, [".github/workflows/ci.yml"])
    assert res.fast_path and not res.ran and res.verdict is None
    assert res.reason.startswith("not run: this change does not touch application code")
    assert ".github/workflows/ci.yml" in res.reason and res.skipped == ["install", "build", "unit_tests", "integration_tests"]
    assert res.build_ok is None and not res.tests_ran and res.unit_tests == {} and res.integration_tests == {}
    assert fake.calls == []  # no docker at all
    assert res.reason in sandbox.known_limitations(res, tmp_path)


def test_fast_path_runs_the_image_build_for_a_dockerfile_change_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_IMAGE_BUILD", "1")
    (tmp_path / "Dockerfile").write_text("FROM node:22\n")
    sandbox.set_runner(Fake())

    class F(Fake):
        def __call__(self, argv, timeout):
            out = super().__call__(argv, timeout)
            if argv[1] == "build":
                return subprocess.CompletedProcess(argv, 1, "no", "")  # build fails: disclosed, tests still "not run"
            return out

    res = sandbox.fast_path_validate(tmp_path, tmp_path, "r", AT, F(), ["Dockerfile"])
    assert [p.name for p in res.phases] == ["image_build"] and res.ran and res.build_ok is None and not res.tests_ran
    assert any("docker build failed" in n for n in res.notes)
    res2 = sandbox.fast_path_validate(tmp_path, tmp_path, "r", AT, Fake(), [".github/workflows/ci.yml"])
    assert not res2.phases  # a workflow-only change has no image to build


def test_resolve_lockfiles_skips_npm_when_the_manifest_is_unchanged(tmp_path, monkeypatch):
    from guardian.tools import resolve

    base, work = tmp_path / "base", tmp_path / "work"
    for d in (base, work):
        d.mkdir()
        (d / "package.json").write_text('{"name": "x", "dependencies": {"a": "1"}}')
    (base / "package-lock.json").write_text('{"lockfileVersion": 3}')
    calls = []
    monkeypatch.setattr(resolve, "run", lambda *a, **k: calls.append(a))
    ctx = ToolContext(run_id="r", run_dir=tmp_path, repo=work, settings=SimpleNamespace(), work_dir=work,
                      artifacts={"baseline_lock_root": base})
    out = resolve.resolve_lockfiles(ctx)
    assert calls == [] and (work / "package-lock.json").read_text() == '{"lockfileVersion": 3}'
    assert "no npm call" in out.evidence[0].facts["source"]
    (work / "package-lock.json").unlink()
    (work / "package.json").write_text('{"name": "x", "dependencies": {"a": "2"}}')  # manifest edited: npm must run
    resolve.resolve_lockfiles(ctx)
    assert len(calls) == 1
