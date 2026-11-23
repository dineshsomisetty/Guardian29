"""Validation sandbox (D2-08, Dev2): apply-patch result -> build -> test -> rescan -> before/after -> verdict.

Per attempt (fresh container from a deps-installed base image, removed afterwards, G6.5):
  phase 1  network ON  (registry only in practice): `npm install` delta + dependency install scripts
           (`npm rebuild`, never the project's own postinstall) + `npm audit signatures` -> provenance evidence
  -------  `docker network disconnect` + proof that DNS no longer resolves (G6.3)
  phase 2  network OFF: build, unit tests, integration tests (commands taken from package.json scripts)
then, outside the container (orchestrator):
  optional `docker build` of the patched work copy (G6.7: network on, limits by timeout, .dockerignore for
  secrets, disclosed limitation) -> Syft SBOM of the built image -> Grype -> re-run detectors -> SBOM diff
  -> ValidationResult.

Container hardening: non-root `node` user (G6.1), --cpus/--memory/--pids-limit + per-phase timeouts (G6.2),
--cap-drop ALL + no-new-privileges, no host mounts and no env secrets (G6.4): the work copy is streamed in
with tar. Nothing is pushed or published.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
NODE_DOCKERFILE = ROOT / "sandbox" / "Dockerfile.node"
EXCLUDE_DIRS = {"node_modules", ".git", ".angular", "dist"}
EXCLUDE_FILE_RE = re.compile(r"^\.env(\..*)?$")  # never ship env files into the sandbox (G6.4)
DOCKERIGNORE_REQUIRED = [".env", ".env.*", "*.pem", ".git"]  # G6.7
_TEST_SUMMARY = re.compile(r"^\s*(?:#|ℹ)\s*(tests|pass|fail|skipped|todo|cancelled)\s+(\d+)\s*$", re.M)


@dataclass
class Limits:
    cpus: str = "2"
    memory: str = "4g"
    pids: int = 1024
    install_timeout: int = 900
    phase_timeout: int = 900
    image_build_timeout: int = 2400


DEFAULT_LIMITS = Limits()


@dataclass
class Step:
    name: str
    cmd: list[str]
    rc: int | None
    seconds: float
    log_file: str
    timed_out: bool = False
    tests: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out


# ---------------------------------------------------------------- docker helpers
def _docker(*args: str, timeout: int = 120, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    exe = shutil.which("docker")
    if not exe:
        raise RuntimeError("docker not found on PATH")
    return subprocess.run([exe, *args], capture_output=True, timeout=timeout, input=input_bytes)


def docker_available() -> bool:
    try:
        return _docker("info", "--format", "{{.ServerVersion}}", timeout=20).returncode == 0
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return False


def parse_test_counts(output: str) -> dict[str, int]:
    """node:test (TAP `# pass 3` or spec `ℹ pass 3`) summary -> {passed, failed, skipped}."""
    found: dict[str, int] = {}
    for key, n in _TEST_SUMMARY.findall(output):
        found[key] = int(n)  # last summary wins (one per run)
    if not found:
        return {}
    return {"passed": found.get("pass", 0), "failed": found.get("fail", 0) + found.get("cancelled", 0),
            "skipped": found.get("skipped", 0) + found.get("todo", 0)}


def scripts_profile(work: Path) -> dict[str, list[str] | None]:
    """Build/test commands from the target's package.json scripts (generic, not Juice-Shop-specific)."""
    scripts = json.loads((Path(work) / "package.json").read_text(encoding="utf-8")).get("scripts", {})

    def pick(*names):
        n = next((x for x in names if x in scripts), None)
        return ["npm", "run", n] if n else None

    return {"build": pick("build:server", "build"),
            "unit": pick("test:server", "test:unit", "test"),
            "integration": pick("test:api", "test:integration", "test:e2e")}


def base_image_tag(work: Path) -> str:
    lock = Path(work) / "package-lock.json"
    h = hashlib.sha256(lock.read_bytes() if lock.is_file() else b"no-lock").hexdigest()[:12]
    return f"guardian-sandbox-node:{h}"


def ensure_base_image(work: Path, limits: Limits = DEFAULT_LIMITS) -> tuple[str, bool]:
    """Build (once per lockfile) the deps-installed base image. Returns (tag, built_now)."""
    tag = base_image_tag(work)
    if _docker("image", "inspect", tag, timeout=30).returncode == 0:
        return tag, False
    with tempfile.TemporaryDirectory() as ctx_dir:
        for f in ("package.json", "package-lock.json"):
            shutil.copy(Path(work) / f, Path(ctx_dir) / f)
        r = _docker("build", "-q", "-t", tag, "-f", str(NODE_DOCKERFILE), ctx_dir, timeout=limits.install_timeout * 2)
    if r.returncode != 0:
        raise RuntimeError(f"sandbox base image build failed: {r.stderr.decode(errors='replace')[-800:]}")
    return tag, True


def _work_tar(work: Path) -> bytes:
    """tar of the work copy without node_modules/.git/env files, owned by uid 1000 (`node`)."""
    buf = io.BytesIO()
    work = Path(work)

    def filt(ti: tarfile.TarInfo):
        parts = Path(ti.name).parts
        if any(p in EXCLUDE_DIRS for p in parts) or EXCLUDE_FILE_RE.match(Path(ti.name).name):
            return None
        ti.uid = ti.gid = 1000
        ti.uname = ti.gname = "node"
        return ti

    with tarfile.open(fileobj=buf, mode="w") as tf:
        for child in sorted(work.iterdir()):
            tf.add(child, arcname=child.name, filter=filt)
    return buf.getvalue()


# ---------------------------------------------------------------- one attempt
class Sandbox:
    def __init__(self, image: str, name: str, limits: Limits, log_dir: Path):
        self.image, self.name, self.limits, self.log_dir = image, name, limits, Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def __enter__(self):
        total = self.limits.install_timeout + 4 * self.limits.phase_timeout
        r = _docker("run", "-d", "--name", self.name, "--user", "node", "--workdir", "/app",
                    "--cpus", self.limits.cpus, "--memory", self.limits.memory,
                    "--pids-limit", str(self.limits.pids), "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges", "--network", "bridge",
                    self.image, "sleep", str(total), timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"sandbox start failed: {r.stderr.decode(errors='replace')[-500:]}")
        return self

    def __exit__(self, *exc):
        _docker("rm", "-f", self.name, timeout=120)  # G6.5: always removed

    def removed(self) -> bool:
        return _docker("container", "inspect", self.name, timeout=30).returncode != 0

    def copy_in(self, work: Path) -> None:
        r = _docker("exec", "-i", self.name, "tar", "-x", "-C", "/app", input_bytes=_work_tar(work), timeout=600)
        if r.returncode != 0:
            raise RuntimeError(f"copy into sandbox failed: {r.stderr.decode(errors='replace')[-500:]}")

    def read_file(self, path: str) -> bytes | None:
        r = _docker("exec", self.name, "cat", path, timeout=60)
        return r.stdout if r.returncode == 0 else None

    def run(self, name: str, cmd: list[str], timeout: int) -> Step:
        t0 = time.monotonic()
        log = self.log_dir / f"{name}.log"
        # `timeout` inside the container too, so a hung test is killed even if docker exec lingers
        full = ["exec", self.name, "timeout", "--signal=KILL", str(timeout), *cmd]
        try:
            r = _docker(*full, timeout=timeout + 60)
            out = (r.stdout + b"\n" + r.stderr).decode("utf-8", errors="replace")
            rc, timed_out = r.returncode, r.returncode in (124, 137)
        except subprocess.TimeoutExpired as e:
            out = ((e.stdout or b"") + (e.stderr or b"")).decode("utf-8", errors="replace")
            rc, timed_out = None, True
        log.write_text(out, encoding="utf-8")
        return Step(name, cmd, rc, round(time.monotonic() - t0, 1), str(log), timed_out, parse_test_counts(out))

    def disconnect_network(self) -> bool:
        """Cut the network, then prove it: DNS lookup of the registry must fail inside the sandbox."""
        _docker("network", "disconnect", "bridge", self.name, timeout=60)
        probe = ["exec", self.name, "node", "-e",
                 "require('dns').lookup('registry.npmjs.org',e=>process.exit(e?0:1))"]
        return _docker(*probe, timeout=60).returncode == 0


def run_attempt(work: Path, out_dir: Path, attempt_id: str, limits: Limits = DEFAULT_LIMITS) -> dict:
    """Phases 1 + 2 for one attempt. Returns a plain dict (steps, provenance, network proof, removal proof).
    The updated lockfile from phase 1 is copied back into the work copy so the after-SBOM reflects it."""
    work, out_dir = Path(work), Path(out_dir)
    base, built_now = ensure_base_image(work, limits)
    prof = scripts_profile(work)
    res: dict[str, Any] = {"attempt_id": attempt_id, "base_image": base, "base_built_now": built_now,
                           "profile": prof, "steps": [], "network_isolated": False, "container_removed": False}
    sb = Sandbox(base, f"guardian-{attempt_id.lower()}", limits, out_dir)
    with sb:
        sb.copy_in(work)
        steps = [sb.run("install", ["npm", "install", "--ignore-scripts", "--package-lock=true", "--no-audit",
                                    "--no-fund"], limits.install_timeout)]
        if steps[-1].ok:
            steps.append(sb.run("install_scripts", ["npm", "rebuild"], limits.install_timeout))
            sig = sb.run("audit_signatures", ["npm", "audit", "signatures", "--json"], 300)
            res["provenance"] = _parse_signatures(Path(sig.log_file).read_text(encoding="utf-8"))
            res["provenance"]["rc"] = sig.rc
            steps.append(sig)
            lock = sb.read_file("/app/package-lock.json")
            if lock:
                (work / "package-lock.json").write_bytes(lock)
        res["network_isolated"] = sb.disconnect_network()
        install_ok = all(s.ok for s in steps if s.name in ("install", "install_scripts"))
        if install_ok and res["network_isolated"]:
            for phase in ("build", "unit", "integration"):
                if prof[phase]:
                    steps.append(sb.run(phase, prof[phase], limits.phase_timeout))
        res["steps"] = steps
    res["container_removed"] = sb.removed()
    return res


def _parse_signatures(text: str) -> dict:
    """`npm audit signatures --json` -> counts (⚠ output shape varies by npm version: parse defensively)."""
    m = re.search(r"\{.*\}", text, re.S)
    out = {"verified": None, "invalid": [], "missing": []}
    if not m:
        out["raw"] = text[-500:]
        return out
    try:
        d = json.loads(m.group(0))
    except json.JSONDecodeError:
        out["raw"] = text[-500:]
        return out
    out["invalid"] = [f"{x.get('name')}@{x.get('version')}" for x in d.get("invalid", [])]
    out["missing"] = [f"{x.get('name')}@{x.get('version')}" for x in d.get("missing", [])]
    out["verified"] = not out["invalid"]
    return out


# ---------------------------------------------------------------- image build (G6.7)
def ensure_dockerignore(work: Path) -> list[str]:
    p = Path(work) / ".dockerignore"
    lines = p.read_text(encoding="utf-8").splitlines() if p.is_file() else []
    added = [x for x in DOCKERIGNORE_REQUIRED if x not in lines]
    if added:
        p.write_text("\n".join(lines + added) + "\n", encoding="utf-8")
    return added


def build_image(work: Path, tag: str, log_file: Path, limits: Limits = DEFAULT_LIMITS) -> Step:
    """`docker build` of the patched work copy. G6.7 KNOWN LIMITATION: runs the target's Dockerfile with network
    (it installs deps itself); bounded by a timeout, no build secrets, .dockerignore excludes env/key files."""
    ensure_dockerignore(work)
    t0 = time.monotonic()
    try:
        r = _docker("build", "-t", tag, str(work), timeout=limits.image_build_timeout)
        out, rc, to = (r.stdout + r.stderr).decode("utf-8", errors="replace"), r.returncode, False
    except subprocess.TimeoutExpired as e:
        out, rc, to = ((e.stdout or b"") + (e.stderr or b"")).decode("utf-8", errors="replace"), None, True
    Path(log_file).write_text(out, encoding="utf-8")
    return Step("image_build", ["docker", "build", "-t", tag, "."], rc, round(time.monotonic() - t0, 1),
                str(log_file), to)


# ---------------------------------------------------------------- full validation
def _finding_key(f) -> set[tuple[str, str]]:
    g = (lambda k: f.get(k)) if isinstance(f, dict) else (lambda k: getattr(f, k, None))
    cat = getattr(g("category"), "value", g("category"))
    if cat == "cve":
        name = (g("component_purl") or "").rsplit("@", 1)[0]
        return {(name, i) for i in [g("vuln_id"), *(g("aliases") or [])] if i}
    return {(f"{cat}", g("component_purl") or g("file_path") or g("title"))}


def validate(work: Path, run_dir: Path, *, run_id: str, plan_id: str, finding: Any, attempt: int,
             before_findings: list, before_sbom: Path, risk_before: float,
             rescan: Callable[[Path, Path], tuple[list, list]] | None = None,
             detectors: list[Callable] | None = None, build_patched_image: bool = False,
             risk_of: Callable[[Any], float] | None = None, limits: Limits = DEFAULT_LIMITS):
    """Run one validation attempt for an approved, already-applied plan (G5.1 is enforced by the caller/graph).

    `rescan(sbom_or_image_sbom, out_dir) -> (findings, evidence)` defaults to Grype; `detectors` are tool
    functions `fn(ctx) -> ToolOutput` re-run on the patched work copy (C4). Returns (ValidationResult, evidence).
    """
    from types import SimpleNamespace

    from guardian.core.models import Confidence, Evidence, ValidationResult, new_id
    from guardian.tools.sbom import run_syft
    from guardian.tools.sbom_diff import sbom_diff
    from guardian.tools.scanners import parse_grype, run_grype, to_models

    attempt_id = new_id("va")
    out = Path(run_dir) / "validation" / attempt_id
    out.mkdir(parents=True, exist_ok=True)
    evidence: list = []
    res = run_attempt(work, out, attempt_id, limits)
    steps: list[Step] = res["steps"]
    by = {s.name: s for s in steps}
    for s in steps:
        evidence.append(Evidence(run_id=run_id, kind="test_result" if s.name in ("unit", "integration") else
                                 "build_log", source_tool=f"sandbox:{s.name}", artifact_path=s.log_file,
                                 facts={"cmd": s.cmd, "rc": s.rc, "seconds": s.seconds, "timed_out": s.timed_out,
                                        **({"tests": s.tests} if s.tests else {})}))
    log_ids = [e.evidence_id for e in evidence]
    if "provenance" in res and "audit_signatures" in by:
        evidence.append(Evidence(run_id=run_id, kind="provenance", source_tool="npm audit signatures",
                                 facts=res["provenance"], artifact_path=by["audit_signatures"].log_file))
    evidence.append(Evidence(run_id=run_id, kind="build_log", source_tool="sandbox:isolation",
                             facts={"network_isolated_for_build_and_tests": res["network_isolated"],
                                    "container_removed": res["container_removed"], "base_image": res["base_image"],
                                    "limits": limits.__dict__}))
    log_ids.append(evidence[-1].evidence_id)

    build_ok = all(by[n].ok for n in ("install", "install_scripts", "build") if n in by) and "install" in by \
        and by["install"].ok
    unit, integ = (by["unit"].tests if "unit" in by else {}), (by["integration"].tests if "integration" in by else {})
    tests_ok = all(by[n].ok for n in ("unit", "integration") if n in by)
    timed_out = any(s.timed_out for s in steps)

    # ---- rescan the resulting artifact
    after_findings, artifact = [], None
    after_sbom = out / "sbom.after.cdx.json"
    run_syft(f"dir:{work}", after_sbom)
    scan_target = after_sbom
    if build_ok and tests_ok and build_patched_image:
        tag = f"guardian-patched:{attempt_id.lower()}"
        img = build_image(work, tag, out / "image_build.log", limits)
        evidence.append(Evidence(run_id=run_id, kind="build_log", source_tool="docker build (G6.7)",
                                 artifact_path=img.log_file, facts={"rc": img.rc, "seconds": img.seconds,
                                                                    "timed_out": img.timed_out, "tag": tag}))
        log_ids.append(evidence[-1].evidence_id)
        if img.ok:
            artifact = tag
            scan_target = out / "sbom.image.after.cdx.json"
            run_syft(f"docker:{tag}", scan_target)
    if build_ok and tests_ok:
        if rescan:
            after_findings, ev = rescan(scan_target, out)
        else:
            doc = run_grype(scan_target, out / "grype.after.json")
            after_findings, ev = to_models(*parse_grype(doc, None, run_id, out / "grype.after.json"))
        evidence += ev
    diff = sbom_diff(Path(before_sbom), after_sbom)
    diff_ev = Evidence(run_id=run_id, kind="sbom_diff", source_tool="sbom_diff", facts=diff,
                       artifact_path=str(after_sbom))
    evidence.append(diff_ev)

    det_ids: list[str] = []
    if detectors and build_ok and tests_ok:
        ctx = SimpleNamespace(run_id=run_id, run_dir=out, repo=Path(work), work_dir=Path(work), graph=None,
                              settings=None, artifacts={}, sbom_path=after_sbom)
        for d in detectors:
            o = d(ctx)
            after_findings += list(o.findings)
            evidence += list(o.evidence)
            det_ids += [e.evidence_id for e in o.evidence]

    before_keys = set().union(*(_finding_key(f) for f in before_findings)) if before_findings else set()
    target_keys = _finding_key(finding)
    resolved = bool(build_ok and tests_ok) and not any(_finding_key(f) & target_keys for f in after_findings)
    new = [f for f in after_findings if not (_finding_key(f) & before_keys)]
    risk_of = risk_of or (lambda f: (getattr(f, "cvss", None) or 5.0) * 10)
    risk_after = (0.0 if resolved else risk_before) + sum(risk_of(f) for f in new)

    if timed_out:
        verdict = "timeout"
    elif not build_ok:
        verdict = "failed_build"
    elif not tests_ok:
        verdict = "failed_tests"
    elif new:
        verdict = "regressed"
    elif not resolved:
        verdict = "not_resolved"
    else:
        verdict = "verified"
    ran_tests = bool(unit.get("passed")) and bool(integ.get("passed"))
    conf = (Confidence.HIGH if verdict == "verified" and ran_tests and artifact else
            Confidence.MEDIUM if verdict == "verified" else Confidence.LOW)

    vr = ValidationResult(
        attempt_id=attempt_id, plan_id=plan_id, finding_id=getattr(finding, "finding_id", None) or finding["finding_id"],
        build_ok=build_ok, unit_tests=unit, integration_tests=integ, artifact_rescanned=artifact,
        target_finding_resolved=resolved, new_findings=[getattr(f, "finding_id", "") for f in new],
        sbom_diff_evidence_id=diff_ev.evidence_id, detector_evidence_ids=det_ids,
        risk_before=risk_before, risk_after=risk_after, verdict=verdict, final_confidence=conf,
        log_evidence_ids=log_ids)
    (out / "result.json").write_text(vr.model_dump_json(indent=2), encoding="utf-8")
    return vr, evidence, {"attempt": attempt, "steps": [s.__dict__ for s in steps], "sandbox": res}
