"""Validation speed: deps-image cache, parallel test phases, baseline in-flight sharing and prewarm.
Every G6 rule must hold in the parallel paths too; all docker calls go through the injected fake runner."""

import json
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from guardian.tools import sandbox
from guardian.tools.registry import ToolContext

SCRIPTS = {"build:server": "tsc", "test:server": "node --test", "test:api": "node --test api"}


def make_project(root: Path, lock: str = "{}") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(json.dumps({"scripts": SCRIPTS}))
    (root / "package-lock.json").write_text(lock)
    return root


class Fake:
    """Thread-safe fake docker/syft: records calls, simulates image cache, per-phase exit codes and timeouts."""

    def __init__(self, cached_tags=(), unit_rc=0, integ_rc=0, timeout_on=None, delay=0.0, build_out="ok"):
        self.calls, self.lock = [], threading.Lock()
        self.images = set(cached_tags)
        self.unit_rc, self.integ_rc, self.timeout_on, self.delay, self.build_out = unit_rc, integ_rc, timeout_on, delay, build_out
        self.running = self.peak = 0
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
            time.sleep(self.delay)
            ok = "--mount" not in (Path(argv[-1]) / "Dockerfile").read_text() or self.build_out != "nobuildkit"
            if not ok:
                return cp(1, "the --mount option requires BuildKit")
            with self.lock:
                self.images.add(argv[argv.index("-t") + 1])
            return cp(0, "built")
        if sub == "rm":
            return cp(0)
        script = argv[-1]
        if sub == "run" and ("test:server" in script or "test:api" in script):
            with self.lock:
                self.running += 1
                self.peak = max(self.peak, self.running)
                self.mounts.append(next(a for a in argv if a.startswith("type=bind")))
            try:
                time.sleep(self.delay)
                if self.timeout_on and self.timeout_on in script:
                    raise subprocess.TimeoutExpired(argv, timeout, output="partial")
                if "test:server" in script:
                    return cp(self.unit_rc, "Tests: 1 failed, 2 passed, 3 total" if self.unit_rc else "Tests: 3 passed, 3 total")
                return cp(self.integ_rc, "Tests: 1 failed, 4 passed, 5 total" if self.integ_rc else "Tests: 5 passed, 5 total")
            finally:
                with self.lock:
                    self.running -= 1
        return cp(0, "build ok")


@pytest.fixture(autouse=True)
def _reset(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDIAN_SANDBOX", "docker")
    monkeypatch.setattr(sandbox, "_inflight", {})
    yield
    sandbox.set_runner(None)


def run(work, fake, attempt="at_" + "S" * 26):
    sandbox.set_runner(fake)
    return sandbox.run_sandbox(work, attempt, fake, 60)


# ---------------------------------------------------------------- parallel phases


def test_parallel_tests_same_verdict_and_phase_order(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    par = run(w, Fake(delay=0.05))
    assert [p.name for p in par.phases] == ["install", "build", "test", "integration"]  # step order, not finish order
    assert par.verdict is None and par.unit_tests["total"] == 3 and par.integration_tests["total"] == 5
    seq_env = pytest.MonkeyPatch()
    seq_env.setenv("GUARDIAN_SANDBOX_PARALLEL", "0")
    try:
        seq = run(w, Fake())
    finally:
        seq_env.undo()
    assert [p.name for p in seq.phases] == [p.name for p in par.phases]
    assert (seq.verdict, seq.unit_tests, seq.integration_tests, seq.build_ok) == (
        par.verdict, par.unit_tests, par.integration_tests, par.build_ok)


def test_parallel_phases_overlap_in_private_copies_with_full_g6_limits(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    fake = Fake(delay=0.2)
    run(w, fake)
    assert fake.peak == 2  # unit + integration really ran together
    assert len(set(fake.mounts)) == 2  # ... each on its own directory, never the same bind mount
    runs = [a for a in fake.calls if a[1] == "run"]
    assert len(runs) == 3  # build + 2 tests
    for a in runs:
        assert a[a.index("--network") + 1] == "none" and "--rm" in a and "--read-only" in a
        assert a[a.index("--user") + 1] == "1000:1000" and "no-new-privileges" in a and "ALL" in a
        assert a[a.index("--memory") + 1] == "4g" and a[a.index("--pids-limit") + 1] == "512"
    assert not list(w.parent.glob(".par-*"))  # snapshots removed
    assert {a[-1] for a in fake.calls if a[1] == "rm"} >= {"guardian-" + ("S" * 26)[-10:].lower() + "-" + n
                                                          for n in ("build", "test", "integration")}


def test_knob_off_runs_sequentially_in_one_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_SANDBOX_PARALLEL", "0")
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    fake = Fake(delay=0.05)
    run(w, fake)
    assert fake.peak == 1 and len(set(fake.mounts)) == 1


def test_integration_failure_in_parallel_gives_failed_tests_and_cleans_up(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    fake = Fake(integ_rc=1, delay=0.05)
    res = run(w, fake)
    assert res.verdict == "failed_tests" and res.unit_tests["failed"] == 0 and res.integration_tests["failed"] == 1
    assert "integration" in res.failed_names and "test" not in res.failed_names
    assert any(a[1] == "rm" and a[-1].endswith("-integration") for a in fake.calls)
    assert not list(w.parent.glob(".par-*"))


def test_timeout_in_one_parallel_phase_is_timeout_and_both_containers_removed(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    fake = Fake(timeout_on="test:api", delay=0.05)
    res = run(w, fake)
    assert res.verdict == "timeout"
    assert [p.name for p in res.phases][-2:] == ["test", "integration"] and res.phases[-1].timed_out
    removed = {a[-1] for a in fake.calls if a[1] == "rm"}
    assert any(r.endswith("-integration") for r in removed) and any(r.endswith("-test") for r in removed)
    assert not list(w.parent.glob(".par-*"))


def test_unit_timeout_outranks_integration_result(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    res = run(w, Fake(timeout_on="test:server", integ_rc=1))
    assert res.verdict == "timeout"  # same verdict the sequential order gave (unit phase first)


def test_failed_build_never_starts_the_test_phases(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")

    class BadBuild(Fake):
        def __call__(self, argv, timeout):
            if argv[1] == "run" and "build:server" in argv[-1]:
                self.calls.append(argv)
                return subprocess.CompletedProcess(argv, 2, "tsc error", "")
            return super().__call__(argv, timeout)

    fake = BadBuild()
    res = run(w, fake)
    assert res.verdict == "failed_build" and res.build_ok is False
    assert not any("test:" in a[-1] for a in fake.calls if a[1] == "run")


# ---------------------------------------------------------------- deps image cache


def test_cache_hit_skips_install_cache_miss_builds(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    tag = sandbox.deps_tag(w, "npm")
    hit = Fake(cached_tags=[tag])
    res = run(w, hit)
    assert not any(a[1] == "build" for a in hit.calls)
    assert res.phases[0].name == "install" and res.phases[0].seconds == 0.0 and "cached" in res.phases[0].output
    miss = Fake()
    run(w, miss)
    assert sum(a[1] == "build" for a in miss.calls) == 1


def test_changed_lockfile_does_not_reuse_the_cached_image(tmp_path):
    a = make_project(tmp_path / "a" / "attempts" / ("at_" + "S" * 26) / "work", lock='{"v":1}')
    b = make_project(tmp_path / "b" / "attempts" / ("at_" + "S" * 26) / "work", lock='{"v":2}')
    assert sandbox.deps_tag(a, "npm") != sandbox.deps_tag(b, "npm")
    fake = Fake(cached_tags=[sandbox.deps_tag(a, "npm")])
    run(b, fake)
    builds = [x for x in fake.calls if x[1] == "build"]
    assert len(builds) == 1 and builds[0][builds[0].index("-t") + 1] == sandbox.deps_tag(b, "npm")


def test_inspect_happens_before_any_build_context_is_assembled(tmp_path, monkeypatch):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    monkeypatch.setattr(sandbox, "_deps_context", lambda *a, **k: pytest.fail("context built despite a cache hit"))
    res = run(w, Fake(cached_tags=[sandbox.deps_tag(w, "npm")]))
    assert res.verdict is None


def test_concurrent_callers_build_the_same_deps_image_once(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    fake = Fake(delay=0.2)
    sandbox.set_runner(fake)
    tag = sandbox.deps_tag(w, "npm")
    results = [sandbox.SandboxResult(), sandbox.SandboxResult()]
    ts = [threading.Thread(target=sandbox._build_deps_image, args=(fake, w, "npm", tag, 60, r)) for r in results]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(a[1] == "build" for a in fake.calls) == 1
    assert all(r.phases and r.phases[-1].exit_code == 0 for r in results)


def test_buildkit_missing_falls_back_to_a_mountless_build(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    fake = Fake(build_out="nobuildkit")
    res = run(w, fake)
    assert res.verdict is None
    assert sum(a[1] == "build" for a in fake.calls) == 2
    assert [p.name for p in res.phases].count("install") == 1  # the rejected attempt is not reported as the install


def test_dockerfile_splits_stages_per_project_and_keeps_layout(tmp_path):
    w = make_project(tmp_path / "w")
    (w / "frontend" / "src").mkdir(parents=True)
    (w / "package.json").write_text(json.dumps({"scripts": {
        "build": "npm run build:frontend && npm run build:server", "build:frontend": "cd frontend && npm run build",
        "build:server": "tsc"}}))
    (w / "frontend" / "package.json").write_text(json.dumps({"dependencies": {"a": "1"}, "scripts": {"build": "ng build"}}))
    (w / "frontend" / "package-lock.json").write_text("{}")
    df = sandbox._npm_dockerfile(w, tmp_path, True)
    assert df.count("FROM node:22-slim") == 3  # root stage, frontend stage, final
    assert "AS p0" in df and "AS p1" in df
    assert "COPY --from=p0 /deps/ /deps/" in df and "COPY --from=p1 /deps/frontend/ /deps/frontend/" in df
    assert df.index("COPY --from=p0") < df.index("COPY --from=p1")
    # the slow frontend build lives only in its own stage, so a root-lock change leaves those layers cached
    root_stage = df.split("AS p1")[0]
    assert "npm run build" not in root_stage and "npm audit signatures" in root_stage
    assert "--mount=type=cache" in df and "--mount" not in sandbox._npm_dockerfile(w, tmp_path, False)
    single = sandbox._npm_dockerfile(make_project(tmp_path / "one"), tmp_path, True)
    assert single.count("FROM") == 1 and "COPY --from" not in single


# ---------------------------------------------------------------- baseline: shared, in-flight, prewarm


def baseline_ctx(tmp_path, lock="{}"):
    run_dir = tmp_path / "run"
    make_project(run_dir / "work", lock)
    settings = SimpleNamespace(llm_cache_dir=tmp_path / "cache" / "llm")
    return ToolContext(run_id="r", run_dir=run_dir, repo=run_dir / "work", settings=settings, work_dir=run_dir / "work")


def test_baseline_cache_hit_skips_the_sandbox_and_changed_lock_does_not_hit(tmp_path):
    ctx = baseline_ctx(tmp_path)
    fake = Fake()
    sandbox.set_runner(fake)
    first = sandbox._baseline(ctx, fake)
    n = len(fake.calls)
    assert first["verdict"] is None and n > 0
    assert sandbox._baseline(ctx, fake) == first and len(fake.calls) == n  # run cache
    (ctx.run_dir / "sandbox_baseline.json").unlink()
    again = sandbox._baseline(ctx, fake)  # shared (cross-run) cache
    assert again == first and len(fake.calls) == n
    other = baseline_ctx(tmp_path / "other", lock='{"different": 1}')
    other.settings = ctx.settings  # same shared cache dir
    sandbox._baseline(other, fake)
    assert len(fake.calls) > n  # a different lockfile hash computes its own baseline


def test_inflight_baseline_is_shared_not_run_twice(tmp_path):
    ctx = baseline_ctx(tmp_path)
    fake = Fake(delay=0.2)
    sandbox.set_runner(fake)
    out = []
    ts = [threading.Thread(target=lambda: out.append(sandbox._baseline(ctx, fake))) for _ in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(out) == 3 and out[0] == out[1] == out[2]
    assert sum(1 for a in fake.calls if a[1] == "run" and "build:server" in a[-1]) == 1


def test_inflight_failure_propagates_to_waiters_and_is_cleared(tmp_path):
    ctx = baseline_ctx(tmp_path)

    class Boom(Fake):
        def __call__(self, argv, timeout):
            if argv[1] == "build":
                time.sleep(0.2)
                raise RuntimeError("daemon exploded")
            return super().__call__(argv, timeout)

    sandbox.set_runner(Boom())
    errs = []

    def call():
        try:
            sandbox._baseline(ctx, Boom())
        except RuntimeError as e:
            errs.append(str(e))

    ts = [threading.Thread(target=call) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errs == ["daemon exploded"] * 2 and sandbox._inflight == {}
    assert sandbox._baseline(ctx, Fake())["verdict"] is None  # a later caller recomputes cleanly


def test_prewarm_is_nonblocking_and_validation_reuses_its_result(tmp_path):
    ctx = baseline_ctx(tmp_path)
    fake = Fake(delay=0.3)
    sandbox.set_runner(fake)
    t0 = time.monotonic()
    th = sandbox.prewarm_baseline(ctx)
    assert th is not None and time.monotonic() - t0 < 0.2  # returned immediately
    assert sandbox.baseline_is_cached(ctx) is False
    th.join(10)
    assert sandbox.baseline_is_cached(ctx) is True
    n = len(fake.calls)
    assert sandbox._baseline(ctx, fake)["verdict"] is None and len(fake.calls) == n
    assert sandbox.prewarm_baseline(ctx) is None  # already cached: nothing started
    assert not (ctx.run_dir / "baseline").exists()  # scratch copy removed


def test_prewarm_failure_is_swallowed_and_validation_still_computes_it(tmp_path):
    ctx = baseline_ctx(tmp_path)

    class Boom(Fake):
        def __call__(self, argv, timeout):
            if argv[1] == "build":
                raise RuntimeError("boom")
            return super().__call__(argv, timeout)

    sandbox.set_runner(Boom())
    th = sandbox.prewarm_baseline(ctx)
    th.join(10)  # must not raise in the caller or leave the cache half-written
    assert not th.is_alive() and sandbox.baseline_is_cached(ctx) is False
    assert not list((tmp_path / "cache").rglob("*.tmp"))
    assert sandbox._baseline(ctx, Fake())["verdict"] is None


def test_prewarm_respects_off_and_opt_out(tmp_path, monkeypatch):
    ctx = baseline_ctx(tmp_path)
    fake = Fake()
    sandbox.set_runner(fake)
    monkeypatch.setenv("GUARDIAN_SANDBOX", "off")
    assert sandbox.prewarm_baseline(ctx) is None
    monkeypatch.setenv("GUARDIAN_SANDBOX", "docker")
    monkeypatch.setenv("GUARDIAN_PREWARM_BASELINE", "0")
    assert sandbox.prewarm_baseline(ctx) is None and fake.calls == []


def test_timing_summary_lists_every_phase(tmp_path):
    w = make_project(tmp_path / "run" / "attempts" / ("at_" + "S" * 26) / "work")
    res = run(w, Fake())
    s = sandbox.timing_summary(res)
    assert all(n in s for n in ("install", "build", "test", "integration"))
