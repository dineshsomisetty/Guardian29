"""D2-08 Docker sandbox validation + rescan/diff for one patched attempt copy. Owner: Dev1.

Install phase (network on, registry only, no secrets): a deps image is built from the manifests only, tagged by
lockfile hash so retries are fast. Build/test phase: fresh container, `--network none` (G6.3), non-root (G6.1),
CPU/mem/pids/time limits (G6.2), only the work copy mounted (G6.4), `--rm` + explicit removal (G6.5).
All docker calls are argv lists through `tools.binaries.run` (never a shell).

Env: GUARDIAN_SANDBOX=auto|docker|off (default auto), GUARDIAN_SANDBOX_TIMEOUT seconds per phase (default 900).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from guardian.core.models import Evidence
from guardian.guardrails.redact import redact
from guardian.tools import binaries
from guardian.tools.registry import ToolContext, ToolOutput

LOG_LINES = 200
NODE_IMAGE = "node:22-slim"  # default when package.json has no engines.node
PY_IMAGE = "python:3.11-slim"  # default when the target's Dockerfile names no python base
LIMITS = ["--cpus", "2", "--memory", "4g", "--pids-limit", "512"]
HARDEN = ["--user", "1000:1000", "--security-opt", "no-new-privileges", "--cap-drop", "ALL"]

Runner = Callable[[list[str], int], "subprocess.CompletedProcess"]
_runner: Runner | None = None  # tests inject a fake


def set_runner(fn: Runner | None) -> None:
    global _runner
    _runner = fn


def default_runner(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    return binaries.run(argv, timeout=timeout, ok_codes=tuple(range(256)))


def mode() -> str:
    m = os.environ.get("GUARDIAN_SANDBOX", "auto").strip().lower()
    return m if m in {"auto", "docker", "off"} else "auto"


def phase_timeout() -> int:
    try:
        return max(1, int(os.environ.get("GUARDIAN_SANDBOX_TIMEOUT", "900")))
    except ValueError:
        return 900


def docker_available(runner: Runner) -> tuple[bool, str]:
    try:
        p = runner([_docker(), "info"], 10)
    except binaries.BinaryMissing:
        return False, "docker binary not found"
    except subprocess.TimeoutExpired:
        return False, "docker info did not answer within 10s"
    except Exception as exc:  # noqa: BLE001
        return False, f"docker info failed: {type(exc).__name__}"
    return (p.returncode == 0, "docker daemon answered" if p.returncode == 0 else "docker daemon not running")


def _docker() -> str:
    return binaries.find("docker") if _runner is None else "docker"


# ---------------------------------------------------------------- result types


@dataclass
class Phase:
    name: str
    argv: list[str]
    exit_code: int | None
    output: str
    seconds: float
    timed_out: bool = False


@dataclass
class SandboxResult:
    ran: bool = False
    reason: str = ""
    kind: str | None = None  # npm | pip
    verdict: str | None = None  # None (ok) | failed_build | failed_tests | timeout
    build_ok: bool | None = None
    unit_tests: dict[str, int] = field(default_factory=dict)
    integration_tests: dict[str, int] = field(default_factory=dict)
    phases: list[Phase] = field(default_factory=list)
    tests_ran: bool = False
    image: str | None = None


# ---------------------------------------------------------------- helpers


def tail(text: str, n: int = LOG_LINES) -> str:
    return redact("\n".join(text.splitlines()[-n:]))


def detect_kind(work: Path) -> str | None:
    if (work / "package.json").exists():
        return "npm"
    if (work / "requirements.txt").exists():
        return "pip"
    return None


def _scripts(work: Path) -> dict:
    try:
        return json.loads((work / "package.json").read_text(encoding="utf-8")).get("scripts") or {}
    except (OSError, ValueError):
        return {}


def lock_hash(work: Path, kind: str) -> str:
    names = ["package.json", "package-lock.json"] if kind == "npm" else ["requirements.txt"]
    h = hashlib.sha256(kind.encode())
    for n in names:
        p = work / n
        if p.exists():
            h.update(n.encode() + p.read_bytes())
    return h.hexdigest()[:16]


def parse_counts(text: str) -> dict[str, int]:
    """Best-effort pass/fail counts from jest, mocha or pytest output."""
    passed = failed = None
    if m := re.search(r"Tests:\s+(?:(\d+) failed,\s*)?(?:\d+ skipped,\s*)?(?:(\d+) passed)?", text):
        failed, passed = int(m.group(1) or 0), int(m.group(2) or 0)
    else:
        mp, mf = re.search(r"(\d+) passing", text), re.search(r"(\d+) failing", text)
        if mp or mf:
            passed, failed = int(mp.group(1)) if mp else 0, int(mf.group(1)) if mf else 0
        else:
            pp, pf = re.search(r"(\d+) passed", text), re.search(r"(\d+) failed", text)
            if pp or pf:
                passed, failed = int(pp.group(1)) if pp else 0, int(pf.group(1)) if pf else 0
    if passed is None:
        return {}
    return {"passed": passed, "failed": failed or 0, "total": passed + (failed or 0)}


def _name(attempt_id: str, tag: str) -> str:
    return f"guardian-{attempt_id[-10:].lower()}-{tag}"


def _run_args(name: str, image: str, work: Path, script: str, network: bool = False) -> list[str]:
    argv = [_docker(), "run", "--rm", "--name", name, *LIMITS, *HARDEN, "--read-only",
            "--tmpfs", "/tmp:rw,size=512m", "--env", "HOME=/tmp", "--env", "CI=true"]
    if not network:
        argv += ["--network", "none"]
    argv += ["--mount", f"type=bind,source={work},target=/work", "--workdir", "/work", image, "sh", "-c", script]
    return argv


def _build_deps_image(runner: Runner, work: Path, kind: str, tag: str, timeout: int, res: SandboxResult) -> bool:
    ctx = Path(tempfile.mkdtemp(prefix="guardian-deps-"))
    try:
        if kind == "npm":
            lock = work / "package-lock.json"
            shutil.copy2(work / "package.json", ctx / "package.json")
            if lock.exists():
                shutil.copy2(lock, ctx / "package-lock.json")
            cmd = "npm ci --ignore-scripts" if lock.exists() else "npm install --ignore-scripts"
            (ctx / "Dockerfile").write_text(
                f"FROM {NODE_IMAGE}\nWORKDIR /deps\nCOPY . /deps/\nRUN {cmd} --no-audit --no-fund\n", encoding="utf-8")
        else:
            shutil.copy2(work / "requirements.txt", ctx / "requirements.txt")
            (ctx / "Dockerfile").write_text(
                f"FROM {PY_IMAGE}\nRUN python -m venv /venv\nCOPY requirements.txt /tmp/\n"
                "RUN /venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt\n", encoding="utf-8")
        (ctx / ".dockerignore").write_text(".env\n*.pem\n*.key\n.npmrc\n.git\n", encoding="utf-8")
        inspect = runner([_docker(), "image", "inspect", tag], 30)
        if inspect.returncode == 0:
            res.phases.append(Phase("install", ["docker", "image", "inspect", tag], 0,
                                    f"deps image {tag} cached (lockfile hash match)", 0.0))
            return True
        argv = [_docker(), "build", "--memory", "4g", "--cpu-quota", "200000", "-t", tag, str(ctx)]
        return _phase(runner, res, "install", argv, timeout, None).exit_code == 0
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


def base_image(work: Path, kind: str) -> str:
    """Pick the toolchain the target declares, so the sandbox builds with what the project expects:
    npm -> lowest major in engines.node (e.g. "22 - 26" -> node:22-slim); pip -> the python:X.Y tag in the
    target's Dockerfile. Falls back to NODE_IMAGE / PY_IMAGE."""
    if kind == "npm":
        node = str((_read_json(work / "package.json").get("engines") or {}).get("node") or "")
        majors = [int(m) for m in re.findall(r"(?<![\d.])(\d{2})(?=[.\sx*]|$)", node) if 14 <= int(m) <= 30]
        return f"node:{min(majors)}-slim" if majors else NODE_IMAGE
    df = work / "Dockerfile"
    if df.is_file():
        m = re.search(r"^FROM\s+python:(\d+\.\d+)", df.read_text(encoding="utf-8", errors="replace"), re.M)
        if m:
            return f"python:{m.group(1)}-slim"
    return PY_IMAGE


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _phase(runner: Runner, res: SandboxResult, name: str, argv: list[str], timeout: int,
           container: str | None) -> Phase:
    t0 = time.monotonic()
    try:
        p = runner(argv, timeout)
        ph = Phase(name, argv, p.returncode, (p.stdout or "") + (p.stderr or ""), time.monotonic() - t0)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
        ph = Phase(name, argv, None, out + f"\n[timeout after {timeout}s]", time.monotonic() - t0, True)
    if ph.timed_out and container:
        _cleanup(runner, container)
    res.phases.append(ph)
    return ph


def _cleanup(runner: Runner, container: str) -> None:
    try:
        runner([_docker(), "rm", "-f", container], 30)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------- the pipeline


def run_sandbox(work: Path, attempt_id: str, runner: Runner, timeout: int) -> SandboxResult:
    res = SandboxResult()
    kind = detect_kind(work)
    if kind is None:
        res.reason = "no package.json or requirements.txt: nothing to build"
        return res
    res.kind, res.ran = kind, True
    base = base_image(work, kind)
    tag = f"guardian-deps:{kind}-{lock_hash(work, kind)}-{re.sub(r'[^a-z0-9.]+', '-', base)}"
    res.image = tag
    containers: list[str] = []
    link = work / "node_modules"
    try:
        if not _build_deps_image(runner, work, kind, tag, timeout, res):
            res.verdict = "timeout" if res.phases[-1].timed_out else "failed_build"
            res.build_ok = False if res.verdict == "failed_build" else None
            return res
        steps: list[tuple[str, str]] = []  # (phase name, shell script)
        if kind == "npm":
            sc = _scripts(work)
            pre = "trap 'rm -f /work/node_modules' EXIT; ln -s /deps/node_modules /work/node_modules && "
            build = "build:server" if "build:server" in sc else ("build" if "build" in sc else None)
            if build:
                steps.append(("build", pre + f"npm run {build}"))
            test = "test:server" if "test:server" in sc else (
                "test" if "test" in sc and "no test specified" not in sc["test"] else None)
            if test:
                steps.append(("test", pre + f"npm run {test}"))
        else:
            py = "/venv/bin/python"
            steps.append(("build", f"{py} -m compileall -q /work" +
                          (f" && {py} manage.py check" if (work / "manage.py").exists() else "")))
            if (work / "tests").is_dir() or list(work.glob("test_*.py")):
                steps.append(("test", f"{py} -m pytest -q -p no:cacheprovider"))
        build_ran = False
        for phase_name, script in steps:
            cname = _name(attempt_id, phase_name)
            containers.append(cname)
            ph = _phase(runner, res, phase_name, _run_args(cname, tag, work, script), timeout, cname)
            if ph.timed_out:
                res.verdict = "timeout"
                return res
            if phase_name == "build":
                build_ran = True
                res.build_ok = ph.exit_code == 0
                if not res.build_ok:
                    res.verdict = "failed_build"
                    return res
            else:
                counts = parse_counts(ph.output)
                if kind == "pip" and "No module named pytest" in ph.output:
                    continue  # no test runner in the project's requirements: tests not run
                res.tests_ran = True
                res.unit_tests = counts or {"passed": int(ph.exit_code == 0), "failed": int(ph.exit_code != 0),
                                            "total": 1}
                if ph.exit_code != 0:
                    res.verdict = "failed_tests"
                    return res
        if not build_ran:
            res.build_ok = None  # install ok, no build script to run
        return res
    finally:
        for c in containers:
            _cleanup(runner, c)  # G6.5 even after --rm
        try:
            if os.path.lexists(link):
                link.unlink()
        except OSError:
            pass  # a Linux symlink created through the bind mount may be unreadable on Windows hosts


# ---------------------------------------------------------------- tool: sandbox_validate


def _evidence(ctx: ToolContext, res: SandboxResult, attempt_id: str) -> list[Evidence]:
    out = []
    for kind, names in (("build_log", ("install", "build")), ("test_result", ("test",))):
        phs = [p for p in res.phases if p.name in names]
        if not phs:
            continue
        text = "\n".join(f"$ {' '.join(p.argv[:2])} [{p.name}] exit={p.exit_code}\n{p.output}" for p in phs)
        out.append(Evidence(
            run_id=ctx.run_id, kind=kind, source_tool="sandbox:docker",
            facts={"attempt_id": attempt_id, "ecosystem": res.kind, "image": res.image,
                   "phases": [{"name": p.name, "exit_code": p.exit_code, "timed_out": p.timed_out,
                               "seconds": round(p.seconds, 1),
                               "network": "none" if p.name != "install" else "registry-only"} for p in phs],
                   **({"unit_tests": res.unit_tests, "integration_tests": "not run"} if kind == "test_result"
                      else {})},
            excerpt=tail(text)))
    return out


def sandbox_validate(ctx: ToolContext) -> ToolOutput:
    work = ctx.work_dir
    attempt_id = ctx.artifacts.get("attempt_id") or work.parent.name
    runner = _runner or default_runner
    m = mode()
    res = SandboxResult()
    if m == "off":
        res.reason = "GUARDIAN_SANDBOX=off"
    else:
        ok, why = docker_available(runner)
        if not ok:
            res.reason = f"Docker not available ({why}); build/tests not run" + (
                " [GUARDIAN_SANDBOX=docker was requested]" if m == "docker" else "")
        else:
            res = run_sandbox(work, attempt_id, runner, phase_timeout())
    return ToolOutput(evidence=_evidence(ctx, res, attempt_id) if res.ran else [],
                      artifacts={"sandbox_result": res},
                      summary=("sandbox " + (res.verdict or "ok")) if res.ran else f"sandbox skipped: {res.reason}")


# ---------------------------------------------------------------- rescan + SBOM diff


def _components(bom: dict) -> dict[str, list[dict]]:
    by_name: dict[str, list[dict]] = {}
    for c in bom.get("components", []):
        by_name.setdefault(c.get("name") or c.get("purl", ""), []).append(c)
    return by_name


def _label(c: dict) -> str:
    return c.get("purl") or f"{c.get('name')}@{c.get('version')}"


def sbom_diff(before: dict, after: dict) -> dict:
    b, a = _components(before), _components(after)
    added: list[str] = []
    removed: list[str] = []
    changed: list[dict] = []
    for name in sorted(set(b) | set(a)):
        bv = {c.get("version"): c for c in b.get(name, [])}
        av = {c.get("version"): c for c in a.get(name, [])}
        only_b = sorted((v for v in bv if v not in av), key=str)
        only_a = sorted((v for v in av if v not in bv), key=str)
        for vb, va in zip(only_b, only_a, strict=False):
            changed.append({"name": name, "from": vb, "to": va})
        removed += [_label(bv[v]) for v in only_b[len(only_a):]]
        added += [_label(av[v]) for v in only_a[len(only_b):]]
    return {"added": sorted(added), "removed": sorted(removed), "changed": changed,
            "components_before": len(before.get("components", [])),
            "components_after": len(after.get("components", []))}


def _grype_keys(data: dict) -> set[tuple[str, str]]:
    return {(m.get("vulnerability", {}).get("id", ""), m.get("artifact", {}).get("name", ""))
            for m in data.get("matches", [])}


def rescan_patched(ctx: ToolContext) -> ToolOutput:
    """Syft the patched copy, Grype it, diff against the original SBOM. Facts of the sbom_diff Evidence are
    exactly the contract's; new/resolved vulnerabilities go into a separate scanner_output Evidence."""
    work = ctx.work_dir
    after_path = ctx.run_dir / "sbom.after.cdx.json"
    from guardian.tools.sbom import EXCLUDES

    syft_args = [binaries.find("syft"), "scan", f"dir:{work}", "-o", f"cyclonedx-json={after_path}", "-q"]
    for ex in EXCLUDES:
        syft_args += ["--exclude", ex]
    binaries.run(syft_args, timeout=900, env={**os.environ, "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true"})
    after = json.loads(after_path.read_text(encoding="utf-8"))
    before_path = ctx.run_dir / "sbom.cdx.json"
    before = json.loads(before_path.read_text(encoding="utf-8")) if before_path.exists() else {}
    diff = sbom_diff(before, after)
    evidence = [Evidence(run_id=ctx.run_id, kind="sbom_diff", source_tool="guardian:sbom_diff", facts=diff,
                         artifact_path="sbom.after.cdx.json", sha256=binaries.sha256_file(after_path))]
    new_vulns: list[str] = []
    try:
        proc = binaries.run([binaries.find("grype"), f"sbom:{after_path}", "-o", "json", "-q"], timeout=900)
        (ctx.run_dir / "grype.after.json").write_text(proc.stdout, encoding="utf-8")
        a_keys = _grype_keys(json.loads(proc.stdout))
        gb = ctx.run_dir / "grype.json"
        b_keys = _grype_keys(json.loads(gb.read_text(encoding="utf-8"))) if gb.exists() else set()
        new_vulns = sorted(f"{v} in {n}" for v, n in a_keys - b_keys)
        evidence.append(Evidence(
            run_id=ctx.run_id, kind="scanner_output", source_tool="grype (patched copy)",
            facts={"new_vulns": new_vulns, "resolved_vulns": sorted(f"{v} in {n}" for v, n in b_keys - a_keys),
                   "matches_after": len(a_keys)}, artifact_path="grype.after.json"))
    except Exception as exc:  # noqa: BLE001  grype missing/offline: diff still stands
        evidence[0].facts = dict(diff)
        ctx.artifacts["grype_error"] = str(exc)[:200]
    return ToolOutput(evidence=evidence,
                      artifacts={"sbom_diff": diff, "new_vulns": new_vulns, "sbom_after": after_path},
                      summary=f"SBOM diff: +{len(diff['added'])} -{len(diff['removed'])} "
                              f"~{len(diff['changed'])}, {len(new_vulns)} new vulnerabilities")
