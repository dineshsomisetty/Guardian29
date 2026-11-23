"""D2-08: sandbox pipeline with a fake docker runner (no Docker needed), sbom_diff, mode switch."""

import json
import subprocess
from pathlib import Path

import pytest

from guardian.tools import sandbox
from guardian.tools.registry import ToolContext


class FakeDocker:
    def __init__(self, test_exit=0, timeout_on=None, info_rc=0):
        self.calls: list[list[str]] = []
        self.test_exit, self.timeout_on, self.info_rc = test_exit, timeout_on, info_rc

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
            return cp(self.test_exit, "Tests: 1 failed, 2 passed, 3 total" if self.test_exit else
                      "Tests: 3 passed, 3 total")
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
