"""D2-08: sandbox pipeline with a fake docker runner (no Docker needed), sbom_diff, mode switch."""

import json
import subprocess
from pathlib import Path

import pytest

from guardian.tools import sandbox
from guardian.tools.registry import ToolContext


class FakeDocker:
    def __init__(self, test_exit=0, timeout_on=None, info_rc=0, baseline_exit=0):
        self.calls: list[list[str]] = []
        self.test_exit, self.timeout_on, self.info_rc = test_exit, timeout_on, info_rc
        self.baseline_exit = baseline_exit  # the unpatched project's tests (sandbox baseline) pass by default

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        cp = lambda rc, out="": subprocess.CompletedProcess(argv, rc, out, "")  # noqa: E731
        sub = argv[1]
        if sub == "info":
            return cp(self.info_rc)
        if sub == "image":
            return cp(1)
        if sub == "build":
            return cp(0, "added 5 packages")
        if sub == "rm":
            return cp(0)
        script = argv[-1]
        if self.timeout_on and self.timeout_on in script:
            raise subprocess.TimeoutExpired(argv, timeout, output="partial")
        if "test:server" in script:
            mount = next((a for a in argv if a.startswith("type=bind")), "")
            rc = self.baseline_exit if "baseline" in mount.replace("\\", "/") else self.test_exit
            return cp(rc, "Tests: 1 failed, 2 passed, 3 total" if rc else "Tests: 3 passed, 3 total")
        return cp(0, "build ok token=abcdef123456")


@pytest.fixture
def work(tmp_path):
    w = tmp_path / "run" / "attempts" / ("at_" + "A" * 26) / "work"
    w.mkdir(parents=True)
    (w / "package.json").write_text(json.dumps({"scripts": {"build:server": "tsc", "test:server": "jest"}}))
    (w / "package-lock.json").write_text("{}")
    return w


def ctx_for(work, tmp_path):
    return ToolContext(run_id="r", run_dir=tmp_path / "run", repo=work, settings=None, work_dir=work)


def use(monkeypatch, fake, mode="docker"):
    monkeypatch.setenv("GUARDIAN_SANDBOX", mode)
    sandbox.set_runner(fake)
    return fake


@pytest.fixture(autouse=True)
def _reset():
    yield
    sandbox.set_runner(None)


def test_happy_path(work, tmp_path, monkeypatch):
    fake = use(monkeypatch, FakeDocker())
    out = sandbox.sandbox_validate(ctx_for(work, tmp_path))
    res = out.artifacts["sandbox_result"]
    assert res.ran and res.verdict is None and res.build_ok is True and res.tests_ran
    assert res.unit_tests == {"passed": 3, "failed": 0, "total": 3}
    kinds = {e.kind for e in out.evidence}
    assert kinds == {"build_log", "test_result"}
    assert "[REDACTED]" in next(e for e in out.evidence if e.kind == "build_log").excerpt
    runs = [a for a in fake.calls if a[1] == "run"]
    assert len(runs) == 2
    for a in runs:  # G6
        assert a[a.index("--network") + 1] == "none"
        assert "--rm" in a and "--read-only" in a and "no-new-privileges" in a
        assert a[a.index("--user") + 1] == "1000:1000"
        assert a[a.index("--memory") + 1] == "4g" and a[a.index("--pids-limit") + 1] == "512"
        assert not any(x.startswith("--env") and "KEY" in x for x in a)
    assert any(a[1] == "rm" for a in fake.calls)  # G6.5 explicit cleanup
    assert not (work / "node_modules").exists()


def test_test_failure(work, tmp_path, monkeypatch):
    use(monkeypatch, FakeDocker(test_exit=1))
    res = sandbox.sandbox_validate(ctx_for(work, tmp_path)).artifacts["sandbox_result"]
    assert res.verdict == "failed_tests" and res.build_ok is True and res.unit_tests["failed"] == 1


def test_timeout_cleans_up(work, tmp_path, monkeypatch):
    fake = use(monkeypatch, FakeDocker(timeout_on="build:server"))
    res = sandbox.sandbox_validate(ctx_for(work, tmp_path)).artifacts["sandbox_result"]
    assert res.verdict == "timeout"
    removed = [a for a in fake.calls if a[1] == "rm"]
    assert removed and removed[0][-1].startswith("guardian-")


def test_deps_image_cached(work, tmp_path, monkeypatch):
    fake = FakeDocker()
    orig = fake.__call__

    def cached(argv, timeout):
        if argv[1] == "image":
            return subprocess.CompletedProcess(argv, 0, "", "")
        return orig(argv, timeout)

    use(monkeypatch, cached)
    sandbox.sandbox_validate(ctx_for(work, tmp_path))
    assert not any(a[1] == "build" for a in fake.calls)


def test_auto_degrades_without_docker(work, tmp_path, monkeypatch):
    use(monkeypatch, FakeDocker(info_rc=1), mode="auto")
    out = sandbox.sandbox_validate(ctx_for(work, tmp_path))
    res = out.artifacts["sandbox_result"]
    assert not res.ran and res.build_ok is None and "not running" in res.reason and not out.evidence


def test_off_never_touches_docker(work, tmp_path, monkeypatch):
    fake = use(monkeypatch, FakeDocker(), mode="off")
    res = sandbox.sandbox_validate(ctx_for(work, tmp_path)).artifacts["sandbox_result"]
    assert not res.ran and fake.calls == []


def test_pip_flow(tmp_path, monkeypatch):
    w = tmp_path / "run" / "attempts" / ("at_" + "B" * 26) / "work"
    (w / "tests").mkdir(parents=True)
    (w / "requirements.txt").write_text("django==4.2\n")
    (w / "manage.py").write_text("")
    fake = use(monkeypatch, FakeDocker())
    res = sandbox.sandbox_validate(ctx_for(w, tmp_path)).artifacts["sandbox_result"]
    assert res.ran and res.kind == "pip" and res.build_ok is True
    scripts = [a[-1] for a in fake.calls if a[1] == "run"]
    assert "compileall" in scripts[0] and "manage.py check" in scripts[0] and "pytest" in scripts[1]


def test_no_shell_true():
    src = Path(sandbox.__file__).read_text()
    assert "shell=True" not in src and "os.system" not in src


def _bom(*comps):
    return {"components": [{"name": n, "version": v, "purl": f"pkg:npm/{n}@{v}"} for n, v in comps]}


def test_sbom_diff_facts():
    before = _bom(("a", "1.0.0"), ("b", "2.0.0"), ("c", "1.0.0"))
    after = _bom(("a", "1.0.0"), ("c", "2.0.0"), ("d", "1.0.0"))
    assert sandbox.sbom_diff(before, after) == {
        "added": ["pkg:npm/d@1.0.0"], "removed": ["pkg:npm/b@2.0.0"],
        "changed": [{"name": "c", "from": "1.0.0", "to": "2.0.0"}],
        "components_before": 3, "components_after": 3}


def test_parse_counts():
    assert sandbox.parse_counts("  12 passing\n  2 failing") == {"passed": 12, "failed": 2, "total": 14}
    assert sandbox.parse_counts("4 passed, 1 failed in 0.3s") == {"passed": 4, "failed": 1, "total": 5}
    assert sandbox.parse_counts("nothing") == {}


def test_base_image_follows_target_toolchain(tmp_path):
    from guardian.tools.sandbox import NODE_IMAGE, PY_IMAGE, base_image

    npm = tmp_path / "npm"
    npm.mkdir()
    (npm / "package.json").write_text('{"engines": {"node": "22 - 26"}}', encoding="utf-8")
    assert base_image(npm, "npm") == "node:22-slim"
    (npm / "package.json").write_text('{"name": "x"}', encoding="utf-8")
    assert base_image(npm, "npm") == NODE_IMAGE
    pip = tmp_path / "pip"
    pip.mkdir()
    (pip / "Dockerfile").write_text("FROM python:3.10-slim-bookworm AS builder\n", encoding="utf-8")
    assert base_image(pip, "pip") == "python:3.10-slim"
    (pip / "Dockerfile").unlink()
    assert base_image(pip, "pip") == PY_IMAGE


class TapDocker(FakeDocker):
    """node --test style output; the patched copy lives under attempts/, the baseline under baseline/."""

    def __init__(self, baseline_fail, patched_fail):
        super().__init__()
        self.baseline_fail, self.patched_fail = baseline_fail, patched_fail

    def __call__(self, argv, timeout):
        if argv[1] == "run" and "test:server" in argv[-1]:
            self.calls.append(argv)
            mount = next(a for a in argv if a.startswith("type=bind"))
            failing = self.baseline_fail if "baseline" in mount.replace("\\", "/") else self.patched_fail
            body = "".join(f"    not ok {i} - {n}\n" for i, n in enumerate(failing, 1))
            body += "not ok 9 - suite\n" if failing else ""
            out = f"{body}# tests 10\n# pass {10 - len(failing)}\n# fail {len(failing)}\n"
            return subprocess.CompletedProcess(argv, 1 if failing else 0, out, "")
        return super().__call__(argv, timeout)


def _baseline_rig(tmp_path, monkeypatch, baseline_fail, patched_fail):
    base = tmp_path / "run" / "work"
    base.mkdir(parents=True)
    (base / "package.json").write_text(json.dumps({"scripts": {"build:server": "tsc", "test:server": "node --test"}}))
    (base / "package-lock.json").write_text("{}")
    w = tmp_path / "run" / "attempts" / ("at_" + "B" * 26) / "work"
    w.mkdir(parents=True)
    (w / "package.json").write_text((base / "package.json").read_text())
    (w / "package-lock.json").write_text('{"changed": true}')
    fake = TapDocker(baseline_fail, patched_fail)
    use(monkeypatch, fake)
    return sandbox.sandbox_validate(ctx_for(w, tmp_path)), fake


def test_failures_that_already_fail_unpatched_are_not_blamed_on_the_fix(tmp_path, monkeypatch):
    """Juice Shop's own suite has 2 failing jwtForgedChallenge tests on the unmodified app: a fix must still pass."""
    out, _ = _baseline_rig(tmp_path, monkeypatch, ["jwt forged A", "jwt forged B"], ["jwt forged A", "jwt forged B"])
    res = out.artifacts["sandbox_result"]
    assert res.verdict is None and res.unit_tests == {"passed": 8, "failed": 2, "total": 10}
    assert res.failed_names["test"] == ["jwt forged A", "jwt forged B"] and res.failed_names["new_vs_baseline"] == []
    facts = next(e for e in out.evidence if e.kind == "test_result").facts
    assert facts["baseline"]["failed_names"]["test"] == ["jwt forged A", "jwt forged B"]  # disclosed
    assert (tmp_path / "run" / "sandbox_baseline.json").is_file()
    assert not (tmp_path / "run" / "work" / "build").exists()  # baseline ran on a scratch copy


def test_a_test_that_newly_fails_after_the_patch_fails_validation(tmp_path, monkeypatch):
    out, fake = _baseline_rig(tmp_path, monkeypatch, ["jwt forged A"], ["jwt forged A", "login works"])
    res = out.artifacts["sandbox_result"]
    assert res.verdict == "failed_tests" and res.failed_names["new_vs_baseline"] == ["login works"]
    assert all("--network" in c and "none" in c for c in fake.calls if c[1] == "run")  # G6.3


def test_failing_tests_parses_tap_leaves_django_and_pytest():
    tap = "        not ok 4 - child one\n        not ok 5 - child two\n    not ok 5 - parent\nnot ok 40 - verify\n"
    assert sandbox.failing_tests(tap) == {"child one", "child two"}
    assert sandbox.failing_tests("FAIL: test_login (app.tests.LoginTest)\nERROR: test_x (a.B)\n") == {
        "test_login (app.tests.LoginTest)", "test_x (a.B)"}
    assert sandbox.failing_tests("FAILED tests/test_a.py::test_b - assert 1\n") == {"tests/test_a.py::test_b"}
    assert sandbox.parse_counts("# tests 443\n# pass 439\n# fail 2\n") == {"passed": 439, "failed": 2, "total": 441}


def test_deps_image_recipe_uses_target_node_and_rebuilds_only_native_addons(tmp_path, monkeypatch):
    """Juice Shop's API tests need sqlite3's native binding: install with scripts off, then rebuild only packages
    shipping a binding.gyp, inside the container, on the node version the project declares."""
    w = tmp_path / "run" / "attempts" / ("at_" + "E" * 26) / "work"
    w.mkdir(parents=True)
    (w / "package.json").write_text(json.dumps({"engines": {"node": "20 - 24"}, "scripts": {"build:server": "tsc"}}))
    (w / "package-lock.json").write_text("{}")
    seen = {}

    class Capture(FakeDocker):
        def __call__(self, argv, timeout):
            if argv[1] == "build":
                seen["dockerfile"] = (Path(argv[-1]) / "Dockerfile").read_text(encoding="utf-8")
                seen["tag"] = argv[argv.index("-t") + 1]
            return super().__call__(argv, timeout)

    use(monkeypatch, Capture())
    sandbox.sandbox_validate(ctx_for(w, tmp_path))
    df = seen["dockerfile"]
    assert df.startswith("FROM node:20-slim") and "npm ci --ignore-scripts" in df
    assert "binding.gyp" in df and "npm rebuild $native" in df and "SCARF_ANALYTICS=false" in df
    assert seen["tag"].endswith(f"-{sandbox.DEPS_RECIPE}")


def test_a_suite_that_never_passes_unpatched_is_disclosed_as_not_runnable(tmp_path, monkeypatch):
    out, _ = _baseline_rig(tmp_path, monkeypatch, [f"t{i}" for i in range(10)], [f"t{i}" for i in range(10)])
    res = out.artifacts["sandbox_result"]
    assert res.verdict is None  # identical to the baseline: not blamed on the fix
    assert res.notes and "not runnable in the sandbox" in res.notes[0]
    facts = next(e for e in out.evidence if e.kind == "test_result").facts
    assert facts["notes"] == res.notes


def test_multi_project_npm_installs_every_project_and_runs_the_full_build(tmp_path, monkeypatch):
    """Juice Shop layout: root server + frontend/ app. Both get their dependencies; the full `build` runs
    (the API tests need the built frontend); both node_modules are linked into the read-only test container."""
    w = tmp_path / "run" / "attempts" / ("at_" + "F" * 26) / "work"
    (w / "frontend").mkdir(parents=True)
    scripts = {"build": "npm run build:frontend && npm run build:server", "build:server": "tsc",
               "test:server": "node --test", "test:api": "node --test api"}
    (w / "package.json").write_text(json.dumps({"dependencies": {"express": "4"}, "scripts": scripts}))
    (w / "package-lock.json").write_text("{}")
    (w / "frontend" / "package.json").write_text(json.dumps({"dependencies": {"@angular/core": "20"}}))
    (w / "frontend" / "package-lock.json").write_text("{}")
    seen = {}

    class Capture(FakeDocker):
        def __call__(self, argv, timeout):
            if argv[1] == "build":
                seen["dockerfile"] = (Path(argv[-1]) / "Dockerfile").read_text(encoding="utf-8")
            return super().__call__(argv, timeout)

    fake = use(monkeypatch, Capture())
    sandbox.sandbox_validate(ctx_for(w, tmp_path))
    df = seen["dockerfile"]
    assert "RUN cd /deps/ && npm ci --ignore-scripts --no-audit" in df
    assert "RUN cd /deps/frontend && npm ci --ignore-scripts --legacy-peer-deps" in df
    runs = [a[-1] for a in fake.calls if a[1] == "run"]
    build = next(r for r in runs if "npm run build" in r)
    assert "npm run build\n" in build + "\n" and "npm run build:server" not in build
    assert "ln -s /deps/frontend/node_modules /work/frontend/node_modules" in build
    assert all("--network" in a and "none" in a for a in fake.calls if a[1] == "run")


def test_subproject_built_by_the_root_build_is_prebuilt_in_the_deps_image(tmp_path, monkeypatch):
    """Juice Shop: build = build:frontend (cd frontend && npm run build) + build:server. The frontend build may
    fetch web fonts, so it runs while the deps image is made; validation copies its dist/ and builds the server
    part with --network none."""
    w = tmp_path / "run" / "attempts" / ("at_" + "G" * 26) / "work"
    (w / "frontend" / "src").mkdir(parents=True)
    scripts = {"build": "npm run build:frontend && npm run build:server", "build:frontend": "cd frontend && npm run build",
               "build:server": "tsc", "test:server": "node --test"}
    (w / "package.json").write_text(json.dumps({"dependencies": {"express": "4"}, "scripts": scripts}))
    (w / "package-lock.json").write_text("{}")
    (w / "frontend" / "package.json").write_text(json.dumps({"dependencies": {"a": "1"}, "scripts": {"build": "ng build"}}))
    (w / "frontend" / "package-lock.json").write_text("{}")
    (w / "frontend" / "src" / "main.ts").write_text("console.log(1)")
    assert sandbox.prebuilt_subprojects(w) == ["frontend"]
    h1 = sandbox.lock_hash(w, "npm")
    (w / "frontend" / "src" / "main.ts").write_text("console.log(2)")
    assert sandbox.lock_hash(w, "npm") != h1  # frontend sources are part of the deps image
    seen = {}

    class Capture(FakeDocker):
        def __call__(self, argv, timeout):
            if argv[1] == "build":
                ctx = Path(argv[-1])
                seen["dockerfile"] = (ctx / "Dockerfile").read_text(encoding="utf-8")
                seen["src_copied"] = (ctx / "frontend" / "src" / "main.ts").is_file()
            return super().__call__(argv, timeout)

    fake = use(monkeypatch, Capture())
    sandbox.sandbox_validate(ctx_for(w, tmp_path))
    assert "RUN cd /deps/frontend && NG_CLI_ANALYTICS=false npm run build" in seen["dockerfile"] and seen["src_copied"]
    build = next(a[-1] for a in fake.calls if a[1] == "run" and "npm run build" in a[-1])
    assert "cp -r /deps/frontend/dist /work/frontend/dist" in build and build.endswith("npm run build:server")


def test_validator_lockfiles_start_from_discoverys_resolution(tmp_path, monkeypatch):
    """Juice Shop ships no lockfile: resolving the patched copy from scratch let unrelated packages drift (25
    'new' dependencies). The copy is seeded with discovery's lockfile and npm only updates it."""
    from types import SimpleNamespace

    from guardian.tools import resolve

    base, w = tmp_path / "base", tmp_path / "attempt"
    for d in (base, w):
        d.mkdir()
        (d / "package.json").write_text('{"dependencies": {"a": "1"}}', encoding="utf-8")
    (base / "package-lock.json").write_text('{"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}')
    calls = []
    monkeypatch.setattr(resolve, "run", lambda args, cwd, timeout: calls.append((args, cwd)))
    ctx = SimpleNamespace(work_dir=w, repo=w, run_id="r", artifacts={"target_name": "x", "baseline_lock_root": base})
    out = resolve.resolve_lockfiles(ctx)
    assert (w / "package-lock.json").read_text() == (base / "package-lock.json").read_text()  # seeded first
    assert calls and "--package-lock-only" in calls[0][0] and "--ignore-scripts" in calls[0][0]
    assert out.evidence[0].facts["source"].startswith("discovery's lockfile")


def test_an_upgrade_may_add_its_own_dependencies_but_nothing_else(tmp_path):
    """express-jwt 5.x brings jws, jwa, lodash.set...: expected. A package outside its subtree is still flagged
    (and new vulnerabilities, e.g. in lodash.set, are judged separately and always fail the attempt)."""
    from guardian.agents.validator import _unexpected_added
    from guardian.core.models import PatchOp, RemediationPlan

    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {
        "": {}, "node_modules/express-jwt": {"dependencies": {"jws": "^3", "lodash.set": "^4"}},
        "node_modules/jws": {"dependencies": {"jwa": "^1"}}, "node_modules/jwa": {}, "node_modules/lodash.set": {},
        "node_modules/left-pad": {}}}))
    plan = RemediationPlan(plan_id="pl_x", plan_hash="h", finding_id="f", attempt=1, action="upgrade",
                           ops=[PatchOp(op="set_dependency_version", file_path="package.json",
                                        args={"name": "express-jwt", "version": "^5.3.3"})],
                           expected_risk_reduction="x", rollback="x", evidence_ids=["ev_1"])
    added = ["pkg:npm/jws@3.2.3", "pkg:npm/jwa@1.4.2", "pkg:npm/lodash.set@4.3.2", "pkg:npm/left-pad@1.3.0"]
    assert _unexpected_added(plan, added, tmp_path) == ["pkg:npm/left-pad@1.3.0"]
    assert len(_unexpected_added(plan, added)) == 4  # without the lockfile nothing is assumed
