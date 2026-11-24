"""D2-08 Docker sandbox validation + rescan/diff for one patched attempt copy. Owner: Dev1.

Install phase (network on, registry only, no secrets): a deps image is built from the manifests only, tagged by
lockfile hash so retries are fast. Build/test phase: fresh container, `--network none` (G6.3), non-root (G6.1),
CPU/mem/pids/time limits (G6.2), only the work copy mounted (G6.4), `--rm` + explicit removal (G6.5).
All docker calls are argv lists through `tools.binaries.run` (never a shell).

Env: GUARDIAN_SANDBOX=auto|docker|off (default auto), GUARDIAN_SANDBOX_TIMEOUT seconds per phase (default 900).
Speed knobs (none weakens a G6 rule): GUARDIAN_SANDBOX_PARALLEL=0 runs unit and integration tests one after the other
(default 1: concurrently, each in its own copy of the built work tree and its own limited container),
GUARDIAN_SANDBOX_SHARDS (default 3, 1 = one integration container as before) splits the integration suite by test
FILE across that many parallel containers, each on its own private snapshot of the built tree (see shard_commands),
GUARDIAN_SANDBOX_MAX_CONTAINERS (default 6) caps test containers running at once in this process,
GUARDIAN_DEPS_CACHE_MOUNT=0 turns off the BuildKit npm/pip download cache of the deps image,
GUARDIAN_PREWARM_BASELINE=0 turns off the background baseline run started after discovery (see prewarm_baseline).

Test phases (all `--network none`): unit tests (`npm run test:server` / `test`, pytest), then integration tests when
the project has them: `npm run test:api` (the app's own harness) or `python manage.py test` for Django.

Optional built-artifact rescan (G6.7, `GUARDIAN_IMAGE_BUILD=1`, default off because it is slow): when the patched copy
has a Dockerfile it is `docker build`-built with CPU/memory/time limits, a generated .dockerignore (.env*, keys,
encryptionkeys/) and no build secrets, then `syft <image>` -> `grype`. The build runs the target's Dockerfile WITH
network access (e.g. `npm install`), which is the known limitation of this step. The image is removed afterwards.

Pipeline use: the validator agent calls `apply_plan` (patching.py), then `sandbox_validate` (does the patched copy
still build and pass its tests?) and `rescan_patched` (Syft + Grype of the patched copy, SBOM diff against the
original). Both are read-only with respect to the approved plan: they work only on runs/<id>/attempts/<at>/work.
Reads: the patched copy, runs/<id>/work (unpatched baseline), sbom.cdx.json, grype.json.
Writes: runs/<id>/sandbox_baseline.json (cache), sbom.after.cdx.json, grype.after.json, and, only with the image
build on, sbom.image.cdx.json + grype.image.json. Evidence: build_log, test_result, sbom_diff, scanner_output.
External processes: docker (build/run/rm/rmi/image inspect), syft, grype, all as argv lists via tools.binaries.
Failure/fallback: no Docker, GUARDIAN_SANDBOX=off or no package.json/requirements.txt -> the sandbox is skipped
and the reason is recorded (the validator reports "not run", never "passed"); a timeout or failed build/test
becomes the verdict (timeout | failed_build | failed_tests) instead of an exception. A test that already fails on
the UNPATCHED project is disclosed but not blamed on the fix (compare_with_baseline).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from guardian.core import activity
from guardian.core.models import Evidence
from guardian.guardrails.redact import redact
from guardian.tools import binaries
from guardian.tools.registry import ToolContext, ToolOutput

LOG_LINES = 200  # how many trailing lines of a phase's output are kept as evidence (the head is rarely useful)
NODE_IMAGE = "node:22-slim"  # default when package.json has no engines.node
PY_IMAGE = "python:3.11-slim"  # default when the target's Dockerfile names no python base
DEPS_RECIPE = "r5"  # bump when the deps-image recipe changes, so a stale cached image is not reused
# Shell snippet run inside the deps image after `npm ci --ignore-scripts`: rebuild ONLY native addons (top-level
# packages, incl. scoped, that ship a binding.gyp) because the app cannot start without them; failures are
# printed, not hidden. Install scripts of every other package never run.
NATIVE_REBUILD = (
    "native=$(find node_modules -mindepth 2 -maxdepth 3 -name binding.gyp -not -path '*/node_modules/*/node_modules/*' "
    "| sed -e 's#^node_modules/##' -e 's#/binding.gyp$##' | sort -u | tr '\\n' ' '); "
    "echo \"native addons: ${native:-none}\"; "
    "if [ -n \"$native\" ]; then npm rebuild $native --no-audit --no-fund || echo 'native rebuild failed'; fi"
)
LIMITS = ["--cpus", "2", "--memory", "4g", "--pids-limit", "512"]  # G6.2: CPU, memory and process-count caps
# G6.1: run as a non-root uid, no privilege escalation, no Linux capabilities at all
HARDEN = ["--user", "1000:1000", "--security-opt", "no-new-privileges", "--cap-drop", "ALL"]

# Test containers (unit / integration, patched and baseline) running at once in this process; each keeps its own
# LIMITS, this only bounds the host's total load so parallel phases cannot starve each other into false timeouts.
try:
    _MAX_CONTAINERS = max(1, int(os.environ.get("GUARDIAN_SANDBOX_MAX_CONTAINERS", "6")))
except ValueError:
    _MAX_CONTAINERS = 6
_slots = threading.BoundedSemaphore(_MAX_CONTAINERS)
_tag_locks: dict[str, threading.Lock] = {}  # deps-image tag -> lock: one build per tag at a time (baseline + patched)
_tag_locks_guard = threading.Lock()

Runner = Callable[[list[str], int], "subprocess.CompletedProcess"]  # (argv, timeout seconds) -> finished process
_runner: Runner | None = None  # tests inject a fake


def set_runner(fn: Runner | None) -> None:
    """Test hook: route every docker/syft/grype call through `fn` (None restores the real runner)."""
    global _runner
    _runner = fn


def default_runner(argv: list[str], timeout: int) -> subprocess.CompletedProcess:
    """The real runner: argv list, never a shell. Every exit code is accepted here; the caller judges it
    (a failing test run is data, not an error). TimeoutExpired still propagates and is handled by `_phase`."""
    return binaries.run(argv, timeout=timeout, ok_codes=tuple(range(256)))


def mode() -> str:
    """GUARDIAN_SANDBOX: "auto" (use Docker if available, the default), "docker" (same, but the skip message says
    Docker was demanded) or "off". Anything else counts as auto."""
    m = os.environ.get("GUARDIAN_SANDBOX", "auto").strip().lower()
    return m if m in {"auto", "docker", "off"} else "auto"


def phase_timeout() -> int:
    """Seconds allowed per sandbox phase (GUARDIAN_SANDBOX_TIMEOUT, default 900, at least 1). A real Angular
    build plus tests can take several minutes, so the default is generous."""
    try:
        return max(1, int(os.environ.get("GUARDIAN_SANDBOX_TIMEOUT", "900")))
    except ValueError:
        return 900


def docker_available(runner: Runner) -> tuple[bool, str]:
    """(usable, reason): `docker info` must answer within 10 s. Never raises; the reason goes into the evidence."""
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
    """Docker executable; with an injected test runner the bare name is used (no binary lookup needed)."""
    return binaries.find("docker") if _runner is None else "docker"


# ---------------------------------------------------------------- result types


@dataclass
class Phase:
    """One docker/syft/grype step: install, build, test, integration, image_build, image_syft, image_grype."""

    name: str
    argv: list[str]
    exit_code: int | None  # None when the phase timed out
    output: str  # stdout + stderr (redacted and trimmed to LOG_LINES only when turned into evidence)
    seconds: float
    timed_out: bool = False


@dataclass
class SandboxResult:
    """Everything one sandbox run learned; turned into evidence and into the validator's verdict."""

    ran: bool = False  # False = skipped, `reason` says why
    reason: str = ""
    kind: str | None = None  # npm | pip
    verdict: str | None = None  # None (ok) | failed_build | failed_tests | timeout
    build_ok: bool | None = None
    unit_tests: dict[str, int] = field(default_factory=dict)  # {"passed", "failed", "total"}
    integration_tests: dict[str, int] = field(default_factory=dict)
    phases: list[Phase] = field(default_factory=list)
    tests_ran: bool = False  # a unit-test phase actually produced a result
    failed_names: dict[str, list[str]] = field(default_factory=dict)  # phase -> failing tests
    baseline: dict | None = None  # the unpatched copy's test result, when compared
    image: str | None = None  # tag of the cached deps image used for the run
    artifact_image: str | None = None  # G6.7: tag of the built + rescanned image (removed afterwards)
    image_vulns: set[tuple[str, str]] = field(default_factory=set)  # (vuln id, package) found in that image
    extra_evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # disclosed limitations, e.g. "image build failed"
    shards: int = 1  # integration containers the suite was split over (1 = not split)
    shard_note: str = ""  # why the suite was NOT split, when sharding was wanted
    fast_path: bool = False  # True: the change cannot affect application code, install/build/tests were not run
    skipped: list[str] = field(default_factory=list)  # phases deliberately not run on the fast path


# ---------------------------------------------------------------- helpers


def tail(text: str, n: int = LOG_LINES) -> str:
    """Last `n` lines of `text`, secret-redacted: what is stored as the evidence excerpt."""
    return redact("\n".join(text.splitlines()[-n:]))


def detect_kind(work: Path) -> str | None:
    """"npm" if the copy has a package.json, "pip" if it has requirements.txt, else None (nothing to build)."""
    if (work / "package.json").exists():
        return "npm"
    if (work / "requirements.txt").exists():
        return "pip"
    return None


def _scripts(work: Path) -> dict:
    """The `scripts` map of work/package.json, or {} when missing or unparsable."""
    try:
        return json.loads((work / "package.json").read_text(encoding="utf-8")).get("scripts") or {}
    except (OSError, ValueError):
        return {}


def npm_projects(work: Path) -> list[str]:
    """Relative dirs of the npm projects to install ("" = root first), e.g. Juice Shop: ["", "frontend"]. Only
    projects with a lockfile (resolved by discovery or the validator) count, so the install is reproducible."""
    from guardian.adapters.npm import find_projects

    rels = [""] if (work / "package.json").is_file() else []  # the root always, even with no dependencies
    for proj in find_projects(work):
        if proj.lockfile.exists() or proj.name == "root":
            rel = proj.dir.relative_to(work).as_posix()
            rels.append("" if rel == "." else rel)
    return sorted(set(rels), key=lambda r: (r != "", r))


# folders ignored when hashing/copying a prebuilt subproject's sources (build output, caches, VCS data)
PREBUILD_SKIP = {"node_modules", "dist", ".angular", ".git", "coverage", ".cache"}


def prebuilt_subprojects(work: Path) -> list[str]:
    """npm subprojects the root `build` script builds (`cd frontend && ...`) and that have their own `build`
    script. They are built while the deps image is made (install step: registry network on, inside the
    container), because a production web build may fetch resources (Juice Shop's Angular build inlines web
    fonts); validation builds then stay --network none and copy the prebuilt dist/ in."""
    sc = _scripts(work)
    # the root build plus the scripts it calls with `npm run <name>` (one level, as Juice Shop's build does)
    chain = sc.get("build") or ""
    chain += " " + " ".join(sc.get(n, "") for n in re.findall(r"npm run ([\w:.-]+)", chain))
    return [rel for rel in npm_projects(work)
            if rel and "build" in _scripts(work / rel)
            and (f"cd {rel} " in chain + " " or f"cd {rel}&" in chain or f"--prefix {rel}" in chain)]


def _source_files(d: Path):
    """Yield the files under `d` in a stable order, skipping PREBUILD_SKIP folders."""
    for f in sorted(d.rglob("*")):
        if f.is_file() and not any(part in PREBUILD_SKIP for part in f.relative_to(d).parts):
            yield f


def lock_hash(work: Path, kind: str) -> str:
    """16-hex fingerprint of everything that decides what the deps image contains (manifests + lockfiles, and
    the sources of prebuilt subprojects). It tags the deps image and keys the baseline cache, so an unchanged
    dependency set reuses the image and a changed one rebuilds it."""
    h = hashlib.sha256(kind.encode())
    if kind == "npm":
        files = [f"{d}/{n}".lstrip("/") for d in npm_projects(work) for n in ("package.json", "package-lock.json")]
    else:
        files = ["requirements.txt"]
    for n in files:
        f = work / n
        h.update(n.encode() + b"\0" + (f.read_bytes() if f.is_file() else b"") + b"\0")
    if kind == "npm":  # a prebuilt subproject's sources are part of the deps image
        for rel in prebuilt_subprojects(work):
            for f in _source_files(work / rel):
                h.update(f.relative_to(work).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
    return h.hexdigest()[:16]


def parse_counts(text: str) -> dict[str, int]:
    """Best-effort pass/fail counts from jest, mocha or pytest output."""
    passed = failed = None
    node_pass, node_fail = re.findall(r"^# pass (\d+)$", text, re.M), re.findall(r"^# fail (\d+)$", text, re.M)
    if node_pass and node_fail:  # node --test (TAP): the last summary is the run's total
        passed, failed = int(node_pass[-1]), int(node_fail[-1])
    elif m := re.search(r"Tests:\s+(?:(\d+) failed,\s*)?(?:\d+ skipped,\s*)?(?:(\d+) passed)?", text):
        failed, passed = int(m.group(1) or 0), int(m.group(2) or 0)
    else:
        mp, mf = re.search(r"(\d+) passing", text), re.search(r"(\d+) failing", text)
        if mp or mf:
            passed, failed = int(mp.group(1)) if mp else 0, int(mf.group(1)) if mf else 0
        elif dj := re.search(r"Ran (\d+) tests?", text):  # Django / unittest
            bad = sum(int(n) for n in re.findall(r"(?:failures|errors)=(\d+)", text))
            passed, failed = max(0, int(dj.group(1)) - bad), bad
        else:
            pp, pf = re.search(r"(\d+) passed", text), re.search(r"(\d+) failed", text)
            if pp or pf:
                passed, failed = int(pp.group(1)) if pp else 0, int(pf.group(1)) if pf else 0
    # the formats are tried from most to least specific; the first that matches decides
    if passed is None:
        return {}
    return {"passed": passed, "failed": failed or 0, "total": passed + (failed or 0)}


def failing_tests(text: str) -> set[str]:
    """Names of failed tests (node TAP leaf `not ok`, Django/unittest FAIL:/ERROR:, pytest FAILED, jest/mocha),
    so a patched run can be compared with the unpatched baseline test by test."""
    names: set[str] = set()
    tap = re.findall(r"^( *)not ok \d+ - (.+)$", text, re.M)
    # node prints a suite's failed children before the suite itself: an entry right after a deeper one is a
    # parent that failed only because of them, so only the leaves are tests
    lines = [(len(indent), name.strip()) for indent, name in tap]
    names |= {name for k, (lvl, name) in enumerate(lines) if k == 0 or lines[k - 1][0] <= lvl}
    names |= {m.strip() for m in re.findall(r"^(?:FAIL|ERROR): (.+)$", text, re.M)}
    names |= {m.strip() for m in re.findall(r"^FAILED (\S+)", text, re.M)}
    names |= {m.strip() for m in re.findall(r"^\s*[✕✗×] (.+?)(?: \(\d+ ?ms\))?$", text, re.M)}
    return names


def _name(attempt_id: str, tag: str) -> str:
    """Container name `guardian-<last 10 chars of the attempt id>-<phase>`; fixed so it can be force-removed."""
    return f"guardian-{attempt_id[-10:].lower()}-{tag}"


def _run_args(name: str, image: str, work: Path, script: str, network: bool = False) -> list[str]:
    """`docker run` argv for one build/test phase: throwaway (--rm), resource-limited (G6.2), non-root with no
    capabilities (G6.1), read-only root fs with a 512 MB /tmp, no network unless asked (G6.3), and only the
    work copy bind-mounted at /work (G6.4). `script` is run with `sh -c`; it is built by this module, never
    taken from the target."""
    argv = [_docker(), "run", "--rm", "--name", name, *LIMITS, *HARDEN, "--read-only",
            "--tmpfs", "/tmp:rw,size=512m", "--env", "HOME=/tmp", "--env", "CI=true"]
    if not network:
        argv += ["--network", "none"]
    argv += ["--mount", f"type=bind,source={work},target=/work", "--workdir", "/work", image, "sh", "-c", script]
    return argv


def deps_tag(work: Path, kind: str) -> str:
    """Image tag for the deps image: kind + lockfile hash + base image + recipe version."""
    base = base_image(work, kind)
    return f"guardian-deps:{kind}-{lock_hash(work, kind)}-{re.sub(r'[^a-z0-9.]+', '-', base)}-{DEPS_RECIPE}"


def parse_signatures(text: str, data: dict | None) -> dict:
    """`npm audit signatures` text + --json output -> counts and the packages that failed."""
    # counts come from the human-readable text, failing packages from the JSON lists "invalid" / "missing"
    def num(pat):
        m = re.search(pat, text or "")
        return int(m.group(1)) if m else None

    def pkgs(key):
        return sorted({f"{p.get('name')}@{p.get('version')}" for p in (data or {}).get(key, []) if isinstance(p, dict)})

    return {"packages_audited": num(r"audited (\d+) packages?"),
            "verified_signatures": num(r"(\d+) packages? ha(?:s|ve) (?:a )?verified registry signatures?"),
            "verified_attestations": num(r"(\d+) packages? ha(?:s|ve) (?:a )?verified attestations?"),
            "invalid": pkgs("invalid"), "missing": pkgs("missing")}


def signature_audit(work: Path, runner: Runner | None = None) -> tuple[dict | None, str]:
    """(result, reason). Builds the deps image if needed (shared with validation) and reads the npm signature
    audit recorded in it, with --network none. None when the sandbox is off, Docker is missing or not npm.
    Used by the risk analyst's `npm_signatures` evidence (provenance of the installed tree)."""
    runner = runner or _runner or default_runner
    if mode() == "off":
        return None, "GUARDIAN_SANDBOX=off"
    if detect_kind(work) != "npm":
        return None, "not an npm project"
    ok, why = docker_available(runner)
    if not ok:
        return None, f"Docker not available ({why})"
    tag = deps_tag(work, "npm")
    res = SandboxResult()
    if not _build_deps_image(runner, work, "npm", tag, phase_timeout(), res):
        return None, "dependency image could not be built"
    out = {}
    for ext in ("txt", "json"):
        p = runner([_docker(), "run", "--rm", "--network", "none", *HARDEN, tag, "cat",
                    f"/deps/.guardian-signatures.{ext}"], 60)
        out[ext] = (p.stdout or "") if p.returncode == 0 else ""
    try:
        data = json.loads(out["json"]) if out["json"].strip() else {}
    except ValueError:
        data = {}
    parsed = parse_signatures(out["txt"], data if isinstance(data, dict) else {})
    if parsed["packages_audited"] is None and not parsed["invalid"]:
        return None, "npm audit signatures produced no result"
    return {**parsed, "image": tag}, "ok"


def _cache_mounts_enabled() -> bool:
    """GUARDIAN_DEPS_CACHE_MOUNT=0 disables the BuildKit download-cache mounts (default on)."""
    return os.environ.get("GUARDIAN_DEPS_CACHE_MOUNT", "1").strip() != "0"


def _npm_dockerfile(work: Path, ctx: Path, mounts: bool) -> str:
    """Dockerfile of the npm deps image. One project: a single stage. Several projects (e.g. Juice Shop's root +
    Angular frontend): one BuildKit stage per project, merged by COPY --from in a final stage, so a changed root
    lockfile does not invalidate the (slow) frontend install + production build layers, and the stages build in
    parallel. The image layout is identical either way: /deps/<project>/node_modules, /deps/<prebuilt>/dist and the
    signature records in /deps. `mounts` adds a registry-download cache (`--mount=type=cache`, never part of the
    image; npm re-verifies every tarball against the lockfile integrity)."""
    base = base_image(work, "npm")
    cache = "--mount=type=cache,id=guardian-npm,target=/root/.npm " if mounts else ""
    env = "ENV SCARF_ANALYTICS=false DO_NOT_TRACK=1 npm_config_update_notifier=false\n"
    projects, prebuilt = npm_projects(work), set(prebuilt_subprojects(work))
    audit = ("RUN " + cache + "cd /deps && (npm audit signatures --json > /deps/.guardian-signatures.json 2>/dev/null;"
             " npm audit signatures > /deps/.guardian-signatures.txt 2>&1; true)\n")

    def install(rel: str) -> str:
        lock = (work / rel / "package-lock.json").exists()
        cmd = "npm ci --ignore-scripts" if lock else "npm install --ignore-scripts"
        peer = " --legacy-peer-deps" if rel else ""  # as discovery resolved subprojects (D2-02)
        files = f"{rel}/package.json" + (f" {rel}/package-lock.json" if lock else "")
        files = files.lstrip("/")
        return (f"COPY {files} /deps/{rel}/\n"
                f"RUN {cache}cd /deps/{rel} && {cmd}{peer} --no-audit --no-fund && {NATIVE_REBUILD}\n")

    def build(rel: str) -> str:
        return (f"COPY {rel}/ /deps/{rel}/\n"
                f"RUN {cache}cd /deps/{rel} && NG_CLI_ANALYTICS=false npm run build\n")

    if len(projects) <= 1:  # nothing to split: the original single stage
        rel = projects[0] if projects else ""
        return (f"FROM {base}\nWORKDIR /deps\n{env}" + install(rel) + audit
                + (build(rel) if rel in prebuilt else ""))
    stages, finals = [], []
    for i, rel in enumerate(projects):
        body = f"FROM {base} AS p{i}\nWORKDIR /deps\n{env}" + install(rel)
        if rel == "":
            body += audit  # provenance of the root tree (what `npm audit signatures` checks in /deps)
        elif rel in prebuilt:
            body += build(rel)
        stages.append(body)
        finals.append(f"COPY --from=p{i} /deps/{rel}/ /deps/{rel}/\n" if rel else f"COPY --from=p{i} /deps/ /deps/\n")
    # the root stage first: its COPY of /deps/ must not overwrite the sub-project folders copied after it
    return "\n".join(stages) + f"\nFROM {base}\nWORKDIR /deps\n{env}" + "".join(finals)


def _deps_context(work: Path, ctx: Path, kind: str, mounts: bool) -> None:
    """Fill the temp build context `ctx` for the deps image: manifests/lockfiles (+ the sources of prebuilt
    subprojects), the Dockerfile and a .dockerignore for secrets. The target's other source never enters it."""
    if kind == "npm":
        for rel in npm_projects(work):
            src, dst = work / rel, ctx / rel
            dst.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src / "package.json", dst / "package.json")
            if (src / "package-lock.json").exists():
                shutil.copy2(src / "package-lock.json", dst / "package-lock.json")
        for rel in prebuilt_subprojects(work):
            for f in _source_files(work / rel):
                dst = ctx / f.relative_to(work)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dst)
        # Install with scripts off, then rebuild only native addons (packages that ship a binding.gyp, e.g.
        # sqlite3), inside this container: the app cannot start without them, and this is where untrusted install
        # code is allowed to run (never on the host). Telemetry postinstalls are off.
        (ctx / "Dockerfile").write_text(_npm_dockerfile(work, ctx, mounts), encoding="utf-8")
    else:
        shutil.copy2(work / "requirements.txt", ctx / "requirements.txt")
        cache = "--mount=type=cache,id=guardian-pip,target=/root/.cache/pip " if mounts else ""
        (ctx / "Dockerfile").write_text(
            f"FROM {base_image(work, kind)}\nRUN python -m venv /venv\nCOPY requirements.txt /tmp/\n"
            f"RUN {cache}/venv/bin/pip install {'' if mounts else '--no-cache-dir '}-r /tmp/requirements.txt\n",
            encoding="utf-8")
    (ctx / ".dockerignore").write_text(".env\n*.pem\n*.key\n.npmrc\n.git\n", encoding="utf-8")


def _tag_lock(tag: str) -> threading.Lock:
    with _tag_locks_guard:
        return _tag_locks.setdefault(tag, threading.Lock())


def _build_deps_image(runner: Runner, work: Path, kind: str, tag: str, timeout: int, res: SandboxResult) -> bool:
    """Build (or reuse) the dependency image `tag`; True when it exists afterwards.

    This is the only phase with network access (registry only, no secrets): a temp build context holds just the
    manifests/lockfiles (npm: `npm ci --ignore-scripts`, then a native-addon rebuild; pip: a venv + pip install)
    plus a .dockerignore for secrets, so the target's source never enters the install step. The context is
    removed afterwards. A cache hit (same lockfile hash) makes retries fast and is recorded as an install phase;
    the cache is checked BEFORE any context is assembled, and a per-tag lock makes a concurrent caller (the
    baseline run next to the patched run) wait for the first build instead of building the same image twice.
    If the daemon has no BuildKit (cache-mount syntax rejected) the build is retried once without mounts."""
    with _tag_lock(tag):
        if runner([_docker(), "image", "inspect", tag], 30).returncode == 0:
            res.phases.append(Phase("install", ["docker", "image", "inspect", tag], 0,
                                    f"deps image {tag} cached (lockfile hash match)", 0.0))
            return True
        mounts = _cache_mounts_enabled()
        while True:
            ctx = Path(tempfile.mkdtemp(prefix="guardian-deps-"))
            try:
                _deps_context(work, ctx, kind, mounts)
                argv = [_docker(), "build", "--memory", "4g", "--cpu-quota", "200000", "-t", tag, str(ctx)]
                ph = _phase(runner, res, "install", argv, timeout, None)
            finally:
                shutil.rmtree(ctx, ignore_errors=True)
            if ph.exit_code != 0 and mounts and re.search(r"--mount|requires buildkit|unknown flag", ph.output, re.I):
                res.phases.pop()  # the rejected attempt is not the install: retry without the cache mounts
                mounts = False
                continue
            return ph.exit_code == 0


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


def is_django(work: Path) -> bool:
    """A Django project: manage.py that mentions django, or django in requirements.txt."""
    # Django keeps tests inside each app, so it needs its own runner (`manage.py test`) besides pytest
    try:
        if (work / "manage.py").is_file() and "django" in (work / "manage.py").read_text(
                encoding="utf-8", errors="replace").lower():
            return True
        return bool(re.search(r"^\s*django\b", (work / "requirements.txt").read_text(
            encoding="utf-8", errors="replace"), re.I | re.M)) and (work / "manage.py").is_file()
    except OSError:
        return False


def _read_json(path: Path) -> dict:
    """A JSON object from `path`, or {} if the file is missing, unreadable or not an object."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _phase(runner: Runner, res: SandboxResult, name: str, argv: list[str], timeout: int,
           container: str | None) -> Phase:
    """Run one step through `runner`, time it, append the Phase to `res` and return it. A timeout becomes a
    Phase with exit_code None (and the named container is force-removed, because killing the docker client
    does not stop the container) instead of an exception."""
    t0 = time.monotonic()
    with activity.step(phase_label(name, container), kind="container",
                       detail=f"{container or 'docker'} (limit {timeout}s)") as act:
        try:
            p = runner(argv, timeout)
            ph = Phase(name, argv, p.returncode, (p.stdout or "") + (p.stderr or ""), time.monotonic() - t0)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace")
            ph = Phase(name, argv, None, out + f"\n[timeout after {timeout}s]", time.monotonic() - t0, True)
        if act is not None:
            act["outcome"] = "timeout" if ph.timed_out else ("ok" if ph.exit_code == 0 else f"exit {ph.exit_code}")
    if ph.timed_out and container:
        _cleanup(runner, container)
    res.phases.append(ph)
    return ph


_PHASE_TEXT = {"install": "Installing dependencies", "build": "Build", "test": "Unit tests",
               "integration": "Integration tests", "image": "Building the image"}


def phase_label(name: str, container: str | None = None) -> str:
    """Readable name of a sandbox phase for the live activity list: "integration-2" -> "Integration tests (shard
    2)"; phases of the unpatched baseline run (container name contains "at_baseline") are prefixed "Baseline"."""
    m = re.fullmatch(r"(.+?)-(\d+)", name)
    base, shard = (m.group(1), m.group(2)) if m else (name, None)
    text = _PHASE_TEXT.get(base, base.replace("_", " ").capitalize()) + (f" (shard {shard})" if shard else "")
    return f"Baseline (unpatched): {text}" if container and "at_baseline" in container else text


def _cleanup(runner: Runner, container: str) -> None:
    """`docker rm -f` a container, ignoring every error (it is usually already gone because of --rm)."""
    try:
        runner([_docker(), "rm", "-f", container], 30)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------- the pipeline


def parallel_enabled() -> bool:
    """GUARDIAN_SANDBOX_PARALLEL=0 runs the test phases strictly one after the other (default: concurrently)."""
    return os.environ.get("GUARDIAN_SANDBOX_PARALLEL", "1").strip() != "0"


def shard_count() -> int:
    """GUARDIAN_SANDBOX_SHARDS: integration containers to split the suite over (default 3; 1 = no split)."""
    try:
        return max(1, int(os.environ.get("GUARDIAN_SANDBOX_SHARDS", "3")))
    except ValueError:
        return 3


# a script is split only when it is one plain `node ... --test ... <glob>` command: anything the module cannot
# rewrite with certainty (shell syntax, pre/post hooks, another runner) keeps the single container
_SHELL_SYNTAX = re.compile(r"[$`()<>|&;\\\n]")


def test_files(work: Path, patterns: list[str]) -> list[str]:
    """Sorted relative test files matching the glob `patterns` under `work` (never inside node_modules)."""
    found: set[str] = set()
    for pat in patterns:
        if pat.startswith(("/", "..")) or ".." in pat.split("/"):
            return []  # a pattern that leaves the work copy is not ours to expand
        found |= {f.relative_to(work).as_posix() for f in work.glob(pat)
                  if f.is_file() and "node_modules" not in f.relative_to(work).parts}
    return sorted(found)


def split_files(work: Path, files: list[str], n: int) -> list[list[str]]:
    """Deterministic, size-balanced partition of `files` into at most `n` non-empty shards: largest file first,
    each to the currently lightest shard (ties: the lowest shard index), file name as the final tie-break.
    Every file lands in exactly one shard; the files inside a shard stay sorted."""
    n = max(1, min(n, len(files)))
    size = {f: (work / f).stat().st_size if (work / f).is_file() else 0 for f in files}
    shards: list[list[str]] = [[] for _ in range(n)]
    load = [0] * n
    for f in sorted(files, key=lambda f: (-size[f], f)):
        i = min(range(n), key=lambda k: (load[k], k))
        shards[i].append(f)
        load[i] += size[f] + 1  # +1: equal-size files still spread out
    return [sorted(sh) for sh in shards if sh]


def shard_commands(work: Path, script_name: str, n: int) -> tuple[list[str], str]:
    """([one shell command per shard], reason). The reason is "" when the suite was split, else why not (the list is
    then empty and the caller runs `npm run <script_name>` in one container).

    Splittable = package.json script that is a single `node [flags] --test [flags] "<glob>"` command (Juice Shop's
    `test:api`: node:test runs every file in its own process, with an in-memory database, so files are independent).
    The glob is expanded here and replaced by the shard's file list; everything else on the command line is kept."""
    import shlex

    sc = _scripts(work)
    script = sc.get(script_name) or ""
    if n <= 1:
        return [], "GUARDIAN_SANDBOX_SHARDS=1"
    if _SHELL_SYNTAX.search(script) or f"pre{script_name}" in sc or f"post{script_name}" in sc:
        return [], f"`{script_name}` is not a single plain command"
    try:
        tokens = shlex.split(script)
    except ValueError:
        return [], f"`{script_name}` could not be parsed"
    if not tokens or tokens[0] != "node" or "--test" not in tokens:
        return [], f"`{script_name}` is not a `node --test` run (cannot be split by file)"
    pats = [t for t in tokens[tokens.index("--test") + 1:] if not t.startswith("-") and re.search(r"[*?\[]", t)]
    if not pats:
        return [], f"`{script_name}` names no test-file glob"
    files = test_files(work, pats)
    if len(files) < 2:
        return [], f"{len(files)} test file(s): nothing to split"
    keep = [t for t in tokens if t not in pats]
    parts = split_files(work, files, n)
    return ([shlex.join(keep) + " " + " ".join(shlex.quote(f) for f in sh) for sh in parts], "")


def _snapshot(work: Path, dst: Path) -> None:
    """A private, writable copy of the built tree (node_modules are linked in per container; VCS data and caches
    are not needed to run tests)."""
    shutil.copytree(work, dst, ignore=shutil.ignore_patterns("node_modules", ".git", ".angular", "coverage", ".cache"),
                    symlinks=True)


def _run_test_steps(runner: Runner, work: Path, attempt_id: str, tag: str, steps: list[tuple[str, str]],
                    timeout: int, containers: list[str], copies: list[Path]) -> list[tuple[str, Phase]]:
    """Run the test phases and return [(name, Phase)] in `steps` order.

    One step, or GUARDIAN_SANDBOX_PARALLEL=0: sequential in `work`, stopping at the first timeout (as before). Several
    steps (the unit suite and every integration shard): they run concurrently, each in a fresh container with the
    full G6 limits (non-root, caps dropped, --network none, CPU/mem/pids, --rm). The first uses `work`; every other
    one gets a private snapshot of the built tree (all taken in parallel before anything starts, node_modules
    excluded) mounted as its /work, so two containers never write into the same directory (files, sqlite
    databases, uploads) or remove each other's node_modules links. A phase that fails or times out cannot stop its
    sibling (each container is force-removed by the caller's cleanup); the caller judges the outcomes in order, so
    the verdict is the same as the sequential one except that a later phase may also have completed."""
    for n, _ in steps:
        containers.append(_name(attempt_id, n))
    if not steps:
        return []

    def one(n: str, script: str, where: Path) -> Phase:
        scratch = SandboxResult()
        with _slots:  # bound the host load across baseline + patched runs; never held while waiting for another slot
            _phase(runner, scratch, n, _run_args(_name(attempt_id, n), tag, where, script), timeout, _name(attempt_id, n))
        return scratch.phases[0]

    if len(steps) == 1 or not parallel_enabled():
        out = []
        for n, script in steps:
            ph = one(n, script, work)
            out.append((n, ph))
            if ph.timed_out:
                break
        return out
    wheres = [work]
    snaps = []
    for n, _ in steps[1:]:
        snap = work.parent / f".par-{n}" / "work"
        shutil.rmtree(snap.parent, ignore_errors=True)
        copies.append(snap.parent)
        snaps.append(snap)
        wheres.append(snap)
    with ThreadPoolExecutor(max_workers=len(steps)) as pool:
        for f in [pool.submit(_snapshot, work, snap) for snap in snaps]:
            f.result()  # every snapshot exists before the first container writes into `work`
        # activity.bound: each worker thread reports its container under the same run / parent step
        futs = [pool.submit(activity.bound(one), n, script, w) for (n, script), w in zip(steps, wheres, strict=True)]
        return [(n, f.result()) for (n, _), f in zip(steps, futs, strict=True)]


def _phase_kind(name: str) -> str:
    """"integration-2" -> "integration": shard phases are judged and reported as the one suite they are part of."""
    return re.sub(r"-\d+$", "", name)


def _merge_integration(phases: list[Phase]) -> tuple[dict[str, int], set[str], bool]:
    """(summed counts, union of failing test names, any shard failed) over the shards of the integration suite.
    A shard with no recognisable summary counts as one pseudo-test whose result is its exit code."""
    total = {"passed": 0, "failed": 0, "total": 0}
    names: set[str] = set()
    bad = False
    for ph in phases:
        c = parse_counts(ph.output) or {"passed": int(ph.exit_code == 0), "failed": int(ph.exit_code != 0), "total": 1}
        for k in total:
            total[k] += c[k]
        names |= failing_tests(ph.output)
        bad = bad or ph.exit_code != 0
    return total, names, bad


def run_sandbox(work: Path, attempt_id: str, runner: Runner, timeout: int) -> SandboxResult:
    """Build the deps image, then run build and test phases of `work` in fresh `--network none` containers.

    Verdict: failed_build / timeout stop immediately; a failing test phase sets "failed_tests" but later phases
    still run, so the caller sees every failure. `build_ok` stays None when there is no build script. The
    node_modules of the deps image is symlinked into /work for the run and removed again (also on error), and
    every container is force-removed at the end (G6.5). Returns the SandboxResult; never raises for a failing
    build or test."""
    res = SandboxResult()
    kind = detect_kind(work)
    if kind is None:
        res.reason = "no package.json or requirements.txt: nothing to build"
        return res
    res.kind, res.ran = kind, True
    tag = deps_tag(work, kind)
    res.image = tag
    containers: list[str] = []
    copies: list[Path] = []  # throwaway work copies of parallel test phases, removed in `finally`
    links = [work / r / "node_modules" for r in (npm_projects(work) if kind == "npm" else [])]
    try:
        if not _build_deps_image(runner, work, kind, tag, timeout, res):
            res.verdict = "timeout" if res.phases[-1].timed_out else "failed_build"
            res.build_ok = False if res.verdict == "failed_build" else None
            return res
        steps: list[tuple[str, str]] = []  # (phase name, shell script run with `sh -c` in the container)
        if kind == "npm":
            sc = _scripts(work)
            projs = npm_projects(work)
            links = [f"/work/{r}/node_modules".replace("//", "/") for r in projs]
            # `pre` = shell prefix of every phase: link each project's node_modules from the deps image (removed on
            # exit so nothing is left in the bind-mounted copy), then export the Angular no-analytics flag
            pre = (f"trap 'rm -f {' '.join(links)}' EXIT; "
                   + " && ".join(f"ln -s /deps/{r}/node_modules {ln}".replace("//", "/") for r, ln in zip(projs, links, strict=True))
                   + " && export NG_CLI_ANALYTICS=false && ")
            # subprojects the root build builds (e.g. Juice Shop's Angular frontend) were built in the deps image:
            # copy their dist/ in (the app's integration tests need it), then build the server part offline
            pre_light = pre  # links + env only: the build phase already put the prebuilt dist/ into the tree
            pre_built = prebuilt_subprojects(work)
            for rel in pre_built:
                pre += f"rm -rf /work/{rel}/dist && cp -r /deps/{rel}/dist /work/{rel}/dist && "
            # a multi-project repo with no prebuilt subproject runs the root's full `build`; otherwise only the
            # server part is built here (the frontend was built in the deps image)
            full = len(projs) > 1 and "build" in sc and not pre_built
            build = "build" if full else ("build:server" if "build:server" in sc else ("build" if "build" in sc else None))
            if build:
                steps.append(("build", pre + f"npm run {build}"))
            test = "test:server" if "test:server" in sc else (
                "test" if "test" in sc and "no test specified" not in sc["test"] else None)
            tpre = pre_light if build else pre  # a build phase runs first and leaves dist/ in the tree: no second copy
            if test:
                steps.append(("test", tpre + f"npm run {test}"))
            if "test:api" in sc:  # D2-08: the app's own integration harness, still --network none
                cmds, res.shard_note = shard_commands(work, "test:api", shard_count())
                if cmds:  # split by test file over parallel containers, each on its own snapshot of the built tree
                    res.shards = len(cmds)
                    bins = "export PATH=/work/node_modules/.bin:$PATH && "  # what `npm run` would put on PATH
                    steps += [(f"integration-{i}", tpre + bins + c) for i, c in enumerate(cmds, 1)]
                else:
                    steps.append(("integration", tpre + "npm run test:api"))
        else:
            py = "/venv/bin/python"
            steps.append(("build", f"{py} -m compileall -q /work" +
                          (f" && {py} manage.py check" if (work / "manage.py").exists() else "")))
            if (work / "tests").is_dir() or list(work.glob("test_*.py")):
                steps.append(("test", f"{py} -m pytest -q -p no:cacheprovider"))
            # Django keeps tests in each app's tests.py (or tests/ package): its own runner covers them
            if is_django(work) and ((work / "tests").is_dir() or list(work.glob("*/tests.py"))
                                    or list(work.glob("*/tests/__init__.py"))):
                steps.append(("integration", f"{py} manage.py test --noinput"))
        build_ran = False
        # the build runs first and alone (it produces what the tests read); the test phases after it are
        # independent of each other, so they may run side by side (see _run_test_steps)
        post = [(n, sc_) for n, sc_ in steps if n != "build"]
        for phase_name, script in steps:
            if phase_name != "build":
                continue
            cname = _name(attempt_id, phase_name)
            containers.append(cname)
            ph = _phase(runner, res, phase_name, _run_args(cname, tag, work, script), timeout, cname)
            if ph.timed_out:
                res.verdict = "timeout"
                return res
            build_ran = True
            res.build_ok = ph.exit_code == 0
            if not res.build_ok:
                res.verdict = "failed_build"
                return res
        outcomes = _run_test_steps(runner, work, attempt_id, tag, post, timeout, containers, copies)
        res.phases += [ph for _, ph in outcomes]  # step order (unit, integration shard 1..N), whatever finished first
        if any(ph.timed_out for _, ph in outcomes):
            res.verdict = "timeout"
            return res
        shard_phases = [ph for n, ph in outcomes if _phase_kind(n) == "integration"]
        for phase_name, ph in outcomes:
            if _phase_kind(phase_name) == "integration":
                continue  # judged below, all shards together
            counts = parse_counts(ph.output)
            if phase_name == "test" and kind == "pip" and "No module named pytest" in ph.output:
                continue  # no test runner in the project's requirements: tests not run
            # no recognisable summary: fall back to one pseudo-test whose result is the exit code
            parsed = counts or {"passed": int(ph.exit_code == 0), "failed": int(ph.exit_code != 0), "total": 1}
            res.tests_ran = True
            res.unit_tests = parsed
            if ph.exit_code != 0:
                res.verdict = "failed_tests"  # decided after every test phase ran (see sandbox_validate)
                res.failed_names[phase_name] = sorted(failing_tests(ph.output))
        if shard_phases:  # one result for the suite: counts summed, failing names unioned, failed if any shard failed
            res.integration_tests, names, bad = _merge_integration(shard_phases)
            if bad:
                res.verdict = "failed_tests"
                res.failed_names["integration"] = sorted(names)
        if not build_ran:
            res.build_ok = None  # install ok, no build script to run
        return res
    finally:
        for c in containers:
            _cleanup(runner, c)  # G6.5 even after --rm
        for c in copies:
            shutil.rmtree(c, ignore_errors=True)
        for link in links:
            try:
                if os.path.lexists(link):
                    link.unlink()
            except OSError:
                pass  # a Linux symlink created through the bind mount may be unreadable on Windows hosts


# ---------------------------------------------------------------- tool: sandbox_validate


# network mode recorded per phase in the evidence; any phase not listed ran with `--network none` (G6.3)
NETWORK = {"install": "registry-only", "image_build": "bridge (G6.7: runs the target's Dockerfile)"}


PHASE_TAIL = 40  # output lines kept per phase in the evidence facts (the report shows them; the full log is a file)


def _phase_facts(ctx: ToolContext, attempt_id: str, p: Phase) -> dict:
    """What the report shows for one phase / container: the command run inside it (`sh -c` script, redacted), its
    network mode, time, exit code, test counts and failing test names parsed from ITS output, the last PHASE_TAIL
    output lines, and the run-relative path of the full redacted log (attempts/<id>/logs/<phase>.log)."""
    script = p.argv[-1] if len(p.argv) >= 3 and p.argv[-3:-1] == ["sh", "-c"] else " ".join(p.argv[:2])
    log = None
    try:
        d = ctx.run_dir / "attempts" / attempt_id / "logs"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{p.name}.log").write_text(redact(p.output), encoding="utf-8")
        log = f"attempts/{attempt_id}/logs/{p.name}.log"
    except OSError:
        pass
    is_test = _phase_kind(p.name) in ("test", "integration")
    return {"name": p.name, "label": phase_label(p.name), "exit_code": p.exit_code, "timed_out": p.timed_out,
            "seconds": round(p.seconds, 1), "network": NETWORK.get(p.name, "none"),
            "command": redact(script)[:2000],
            **({"tests": parse_counts(p.output) or None, "failing": sorted(failing_tests(p.output))[:200]}
               if is_test else {}),
            "output_tail": tail(p.output, PHASE_TAIL), "log": log}


def _evidence(ctx: ToolContext, res: SandboxResult, attempt_id: str) -> list[Evidence]:
    """Turn the phases into evidence: one `build_log` (install, build, image_build) and one `test_result` (test,
    integration). Facts hold exit codes, timing, network mode and test counts; the excerpt is the redacted tail
    of the combined output. Phases that did not run produce no evidence."""
    out = []
    for kind, names in (("build_log", ("install", "build", "image_build")), ("test_result", ("test", "integration"))):
        phs = [p for p in res.phases if _phase_kind(p.name) in names]
        if not phs:
            continue
        text = "\n".join(f"$ {' '.join(p.argv[:2])} [{p.name}] exit={p.exit_code}\n{p.output}" for p in phs)
        out.append(Evidence(
            run_id=ctx.run_id, kind=kind, source_tool="sandbox:docker",
            facts={"attempt_id": attempt_id, "ecosystem": res.kind, "image": res.image,
                   "phases": [_phase_facts(ctx, attempt_id, p) for p in phs],
                   **({"unit_tests": res.unit_tests, "integration_tests": res.integration_tests or "not run",
                       "failing_tests": res.failed_names,
                       "integration_shards": res.shards, "shard_note": res.shard_note or None,
                       "notes": res.notes,
                       "baseline": ({k: res.baseline.get(k) for k in ("unit_tests", "integration_tests", "failed_names")}
                                    if res.baseline else None)}
                      if kind == "test_result" else {})},
            excerpt=tail(text)))
    return out


_inflight: dict[str, Future] = {}  # baseline key -> the computation already running (prewarm or a parallel caller)
_inflight_guard = threading.Lock()


def _read_cached_baseline(ctx: ToolContext, key: str) -> dict | None:
    """The baseline for `key` from this run's cache or the shared one (copied into the run), else None."""
    cache = ctx.run_dir / "sandbox_baseline.json"
    shared = _shared_baseline_path(ctx, key)
    for path in (cache, shared):
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
            if cached.get("lock_hash") == key:
                if path is shared:
                    cache.write_text(json.dumps(cached, indent=1), encoding="utf-8")
                return cached
        except (OSError, ValueError, AttributeError):
            pass
    return None


def _baseline(ctx: ToolContext, runner: Runner) -> dict | None:
    """Test result of the *unpatched* project (discovery's work copy, lockfiles resolved), cached per lockfile
    hash in runs/<id>/sandbox_baseline.json and, across runs, in data/cache/sandbox_baseline. Run on a scratch copy
    so the work copy is never modified. The cache key is the lockfile hash (manifests, lockfiles, prebuilt
    sources) + deps recipe, exactly what decides the deps image, so a changed lockfile never reuses a result.
    If the same baseline is already being computed (background prewarm, or the parallel start in
    sandbox_validate) this call waits for that result instead of running the sandbox a second time."""
    src = ctx.run_dir / "work"
    kind = detect_kind(src) if src.is_dir() else None
    if kind is None:
        return None
    key = lock_hash(src, kind)
    # Shared across runs: the baseline depends only on the unpatched project's exact lockfiles (and the deps-image
    # recipe), so a new scan of an unchanged project reuses it instead of spending ~7 minutes re-running it.
    cached = _read_cached_baseline(ctx, key)
    if cached is not None:
        return cached
    with _inflight_guard:
        fut = _inflight.get(key)
        mine = fut is None
        if mine:
            fut = _inflight[key] = Future()
    if not mine:
        out = fut.result()  # raises what the owner raised: the caller falls back to its own attempt
        try:
            (ctx.run_dir / "sandbox_baseline.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
        except OSError:
            pass
        return out
    try:
        out = _compute_baseline(ctx, runner, src, key)
        fut.set_result(out)
        return out
    except BaseException as exc:
        fut.set_exception(exc)
        raise
    finally:
        with _inflight_guard:
            _inflight.pop(key, None)


def _compute_baseline(ctx: ToolContext, runner: Runner, src: Path, key: str) -> dict:
    """Run the sandbox on a scratch copy of the unpatched project and write the run + shared caches."""
    cache = ctx.run_dir / "sandbox_baseline.json"
    shared = _shared_baseline_path(ctx, key)
    copy = ctx.run_dir / "baseline" / "work"
    shutil.rmtree(copy.parent, ignore_errors=True)
    from guardian.core.workspace import IGNORE

    shutil.copytree(src, copy, ignore=IGNORE)
    try:
        with activity.step("Baseline: unpatched project build + tests", kind="baseline",
                           detail="compared test by test with the patched run"):
            b = run_sandbox(copy, "at_baseline" + key[:16], runner, phase_timeout())
    finally:
        shutil.rmtree(copy.parent, ignore_errors=True)
    out = {"lock_hash": key, "verdict": b.verdict, "build_ok": b.build_ok, "unit_tests": b.unit_tests,
           "integration_tests": b.integration_tests, "failed_names": b.failed_names}
    cache.write_text(json.dumps(out, indent=1), encoding="utf-8")
    if shared is not None and b.ran and b.verdict != "timeout":  # never share a run that did not complete
        try:
            shared.parent.mkdir(parents=True, exist_ok=True)
            tmp = shared.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")  # atomic: no half-written cache
            tmp.write_text(json.dumps(out, indent=1), encoding="utf-8")
            tmp.replace(shared)
        except OSError:
            pass
    return out


def prewarm_baseline(ctx: ToolContext, runner: Runner | None = None) -> threading.Thread | None:
    """Start the unpatched baseline in a daemon thread (right after discovery, while the human is still reading
    findings) so approval -> verdict does not pay for it. Returns the thread, or None when nothing was started:
    sandbox off, GUARDIAN_PREWARM_BASELINE=0, no npm/pip project, or the baseline is already cached. Never raises
    and never blocks the caller; a failure inside the thread is swallowed (the validation then runs the baseline
    itself, as before). It writes only the baseline caches (under runs/<id>/ and data/cache/sandbox_baseline)."""
    if mode() == "off" or os.environ.get("GUARDIAN_PREWARM_BASELINE", "1").strip() == "0":
        return None
    try:
        if baseline_is_cached(ctx):
            return None
    except Exception:  # noqa: BLE001
        return None
    run = runner or _runner or default_runner

    def work() -> None:
        try:
            if docker_available(run)[0]:
                _baseline(ctx, run)
        except Exception:  # noqa: BLE001 - best effort; the validation recomputes it if needed
            pass

    def work_in_run() -> None:
        with activity.scope(ctx.run_dir):
            work()

    t = threading.Thread(target=work_in_run, name="guardian-baseline-prewarm", daemon=True)
    t.start()
    return t


def _shared_baseline_path(ctx: ToolContext, key: str) -> Path | None:
    """data/cache/sandbox_baseline/<recipe>-<lockfile hash>.json next to the LLM cache, or None without settings."""
    try:
        root = ctx.settings.llm_cache_dir.parent / "sandbox_baseline"
    except AttributeError:
        return None
    return root / f"{DEPS_RECIPE}-{key}.json"


def baseline_is_cached(ctx: ToolContext) -> bool:
    """True when the unpatched baseline for this run's lockfiles is already known (run or shared cache)."""
    src = ctx.run_dir / "work"
    kind = detect_kind(src) if src.is_dir() else None
    if kind is None:
        return True  # nothing to run, so nothing to wait for
    key = lock_hash(src, kind)
    for path in (ctx.run_dir / "sandbox_baseline.json", _shared_baseline_path(ctx, key)):
        try:
            if path is not None and json.loads(path.read_text(encoding="utf-8")).get("lock_hash") == key:
                return True
        except (OSError, ValueError):
            pass
    return False


def compare_with_baseline(ctx: ToolContext, res: SandboxResult, runner: Runner, base: dict | None = None) -> None:
    """A test that already fails on the unpatched project is not caused by the fix. The patched run fails only
    if a test fails that passed before (by name), or, when names cannot be parsed, if more tests fail.
    `base` is a baseline already computed (e.g. in parallel with the patched run); else it is fetched here."""
    base = base if base is not None else _baseline(ctx, runner)
    res.baseline = base
    if not base or base.get("verdict") not in ("failed_tests", None):
        return
    new: dict[str, list[str]] = {}
    for phase, names in res.failed_names.items():
        before = set((base.get("failed_names") or {}).get(phase, []))
        counts_after = res.integration_tests if phase == "integration" else res.unit_tests
        counts_before = base.get("integration_tests" if phase == "integration" else "unit_tests") or {}
        if names and before:
            extra = sorted(set(names) - before)
        else:
            fa, fb = counts_after.get("failed", 1), counts_before.get("failed", 0)
            # names unknown on one side: judge by counts, and say so (never an empty list for a real increase)
            extra = (names or [f"{phase}: {fa} failing after the patch vs {fb} before"]) if fa > fb else []
        if extra:
            new[phase] = extra
    res.failed_names = {**res.failed_names, "new_vs_baseline": sorted({n for v in new.values() for n in v})}
    for phase, key in (("test", "unit_tests"), ("integration", "integration_tests")):
        b = base.get(key) or {}
        if b.get("total") and not b.get("passed"):
            # nothing passes even on the unpatched project: the suite cannot run in this sandbox (e.g. Juice
            # Shop's API tests need its built Angular frontend), so it says nothing about the fix either way
            res.notes.append(f"{phase} suite not runnable in the sandbox: 0 of {b['total']} pass on the unpatched "
                             f"project too, so it is not used to judge the fix")
    if not new:
        res.verdict = None  # every failure was already there before the patch: disclosed, not blamed on the fix


def timing_summary(res: SandboxResult) -> str:
    """"install 0s, build 15s, test 51s, integration 380s": where a validation's wall-clock went (from the Phases)."""
    return ", ".join(f"{p.name} {p.seconds:.0f}s" for p in res.phases) or "no phases"


def sandbox_validate(ctx: ToolContext) -> ToolOutput:
    """Tool called by the validator: does the patched copy (ctx.work_dir) still build and pass its tests?

    Skips with a recorded reason when the sandbox is off or Docker is unavailable. After a "failed_tests" run
    it is compared with the unpatched baseline; if everything else is fine and GUARDIAN_IMAGE_BUILD=1 with a
    Dockerfile, the built image is rescanned too (G6.7). Returns build_log/test_result evidence plus the
    `sandbox_result` artifact (the SandboxResult object) that the validator turns into its verdict."""
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
            # With real Docker and no cached baseline, run the unpatched baseline at the same time as the patched
            # project: the two are independent, so the first validation of a run takes ~half as long. Fake
            # runners (tests) keep the original one-after-the-other order.
            pre = None
            if _runner is None and not baseline_is_cached(ctx):
                from concurrent.futures import ThreadPoolExecutor

                pool = ThreadPoolExecutor(max_workers=1)
                pre = pool.submit(activity.bound(_baseline), ctx, runner)
                pool.shutdown(wait=False)
            res = run_sandbox(work, attempt_id, runner, phase_timeout())
            if res.verdict == "failed_tests":
                base = None
                if pre is not None:
                    try:
                        base = pre.result()
                    except Exception:  # noqa: BLE001 - the sequential path below retries it
                        base = None
                compare_with_baseline(ctx, res, runner, base)
            if res.verdict is None and image_build_enabled() and (work / "Dockerfile").is_file():
                build_artifact(work, ctx.run_dir, ctx.run_id, attempt_id, runner, phase_timeout(), res)
    return ToolOutput(evidence=[*_evidence(ctx, res, attempt_id), *res.extra_evidence] if res.ran or res.phases else [],
                      artifacts={"sandbox_result": res},
                      summary=(f"sandbox {res.verdict or 'ok'} ({timing_summary(res)})") if res.ran
                      else f"sandbox skipped: {res.reason}")


# ---------------------------------------------------------------- fast path: changes that cannot affect app code

# ops that only edit CI / container definitions, and the only files they may touch (anything else: full validation)
FAST_OPS = {"pin_action_sha", "pin_image_digest", "update_base_image"}
_FAST_FILE = re.compile(r"(?:\.github/.+|\.gitlab-ci\.ya?ml|docker-compose[^/]*\.ya?ml|(?:.+/)?Dockerfile(?:\.[\w.-]+)?)")
FAST_SKIPPED = ["install", "build", "unit_tests", "integration_tests"]


def fast_path_enabled() -> bool:
    """GUARDIAN_SANDBOX_FAST_PATH=0 turns the fast path off (every plan then gets the full sandbox run)."""
    return os.environ.get("GUARDIAN_SANDBOX_FAST_PATH", "1").strip() != "0"


def fast_path_files(plans: list) -> list[str] | None:
    """The files `plans` touch when the whole set qualifies for the fast path, else None (full validation).

    Strict allow-list: EVERY op of EVERY plan must be one of FAST_OPS and EVERY file must be a CI / container
    definition (.github/**, .gitlab-ci.yml, docker-compose*.yml, Dockerfile*); a relative path with `..`, an
    absolute path, a manifest, a lockfile, a source file or any other op makes the whole set ineligible."""
    import posixpath

    if not plans or not fast_path_enabled():
        return None
    files: set[str] = set()
    for plan in plans:
        if not plan.ops:
            return None
        for op in plan.ops:
            rel = posixpath.normpath(op.file_path.replace("\\", "/"))
            if op.op not in FAST_OPS or rel.startswith(("/", "..")) or not _FAST_FILE.fullmatch(rel):
                return None
            files.add(rel)
    return sorted(files)


def fast_path_validate(work: Path, run_dir: Path, run_id: str, attempt_id: str, runner: Runner,
                       files: list[str]) -> SandboxResult:
    """The sandbox half of a fast-path validation: no dependency install, build or tests (they cannot be affected
    by `files`), and it SAYS so: `reason` and `notes` name what was not run, and no skipped test is ever counted as
    passed (build_ok stays None, tests_ran False, no counts). The one check that is meaningful for an image change,
    the image build + rescan, still runs when GUARDIAN_IMAGE_BUILD=1 and a changed file is a Dockerfile."""
    res = SandboxResult(fast_path=True, skipped=list(FAST_SKIPPED))
    shown = ", ".join(files[:4]) + (f" (+{len(files) - 4} more)" if len(files) > 4 else "")
    res.reason = (f"not run: this change does not touch application code (only {shown}); dependency install, build, "
                  f"unit tests and integration tests were skipped")
    res.notes.append(res.reason)
    if (image_build_enabled() and (work / "Dockerfile").is_file()
            and any(posixpath_name(f).startswith("Dockerfile") for f in files)):
        ok, _ = docker_available(runner)
        if ok:
            build_artifact(work, run_dir, run_id, attempt_id, runner, phase_timeout(), res)
            res.ran = bool(res.phases)
    return res


def posixpath_name(rel: str) -> str:
    """Last path component of a posix-style relative path."""
    return rel.rsplit("/", 1)[-1]


# ---------------------------------------------------------------- built-artifact rescan (G6.7)

# .dockerignore lines prepended for the image build (G6.7): secrets, VCS data and host node_modules never enter it
BUILD_IGNORE = [".env*", "**/.env*", "*.pem", "**/*.pem", "*.key", "**/*.key", "encryptionkeys/", "**/encryptionkeys/",
                ".git", "node_modules", ".npmrc"]


def image_build_enabled() -> bool:
    """GUARDIAN_IMAGE_BUILD=1 turns the slow, network-using image build + rescan on (default off)."""
    return os.environ.get("GUARDIAN_IMAGE_BUILD", "0").strip() == "1"


def known_limitations(res: SandboxResult, work: Path) -> list[str]:
    """What the validation did NOT cover, recorded in the ValidationResult's summary evidence."""
    if res.artifact_image:
        return ["the image build executed the target's Dockerfile with network access (G6.7); the rescan covers "
                "that image, which may differ from what CI would build"]
    out = []
    if not image_build_enabled():
        out.append("built image not rescanned: GUARDIAN_IMAGE_BUILD is off (docker build runs the target's "
                   "Dockerfile with network, G6.7); the rescan covers the patched source tree only")
    elif not (work / "Dockerfile").is_file():
        out.append("built image not rescanned: no Dockerfile in the patched copy")
    return [*out, *res.notes]


def _bin(name: str) -> str:
    """Binary path for syft/grype; the bare name when a test runner is injected."""
    return name if _runner is not None else binaries.find(name)


def build_artifact(work: Path, run_dir: Path, run_id: str, attempt_id: str, runner: Runner, timeout: int,
                   res: SandboxResult) -> None:
    """docker build the patched copy (network on, CPU/memory/time limited, keys/.env excluded via a generated
    .dockerignore, no build secrets), syft the image, grype the SBOM, remove the image. Never raises: a failed
    build is recorded in `res.notes` and does not change the verdict.

    On success sets res.image_vulns (set of (vulnerability id, package)) and res.artifact_image and adds a
    `scanner_output` Evidence. A temporary .dockerignore is written in the copy and the original (if any) is
    restored afterwards; the image is removed even on failure (G6.5)."""
    tag = f"guardian-built:{attempt_id[-10:].lower()}"
    ignore = work / ".dockerignore"
    original = ignore.read_bytes() if ignore.exists() else None
    sbom = run_dir / "sbom.image.cdx.json"
    sbom.unlink(missing_ok=True)
    try:
        ignore.write_text("\n".join(BUILD_IGNORE) + "\n" + (original.decode("utf-8", "replace") if original else ""),
                          encoding="utf-8")
        ph = _phase(runner, res, "image_build",
                    [_docker(), "build", "--memory", "4g", "--cpu-quota", "200000", "-t", tag, str(work)],
                    timeout, None)
        if ph.exit_code != 0:
            res.notes.append("built image not rescanned: docker build " + ("timed out" if ph.timed_out else
                             f"failed (exit {ph.exit_code}); see the build_log evidence"))
            return
        sy = _phase(runner, res, "image_syft", [_bin("syft"), tag, "-o", f"cyclonedx-json={sbom}", "-q"], timeout, None)
        if sy.exit_code != 0 or not sbom.exists():
            res.notes.append(f"built image not rescanned: syft failed (exit {sy.exit_code})")
            return
        gr = _phase(runner, res, "image_grype", [_bin("grype"), f"sbom:{sbom}", "-o", "json", "-q"], timeout, None)
        if gr.exit_code != 0:
            res.notes.append(f"built image SBOM written but grype failed (exit {gr.exit_code})")
            return
        data = json.loads(gr.output[gr.output.index("{"):])  # skip any log noise printed before the JSON
        (run_dir / "grype.image.json").write_text(json.dumps(data), encoding="utf-8")
        res.image_vulns = _grype_keys(data)
        res.artifact_image = tag
        comps = len(json.loads(sbom.read_text(encoding="utf-8")).get("components", []))
        res.extra_evidence.append(Evidence(
            run_id=run_id, kind="scanner_output", source_tool="syft+grype (built image)",
            facts={"attempt_id": attempt_id, "image": tag, "components": comps, "matches": len(res.image_vulns),
                   "base_image_vulns_not_diffed": True}, artifact_path="grype.image.json"))
    except (OSError, ValueError, binaries.BinaryMissing, subprocess.SubprocessError) as exc:
        res.notes.append(f"built image not rescanned: {type(exc).__name__}: {str(exc)[:120]}")
    finally:
        try:
            runner([_docker(), "rmi", "-f", tag], 60)  # G6.5: the image does not outlive the attempt
        except Exception:  # noqa: BLE001
            pass
        if original is None:
            ignore.unlink(missing_ok=True)
        else:
            ignore.write_bytes(original)


# ---------------------------------------------------------------- rescan + SBOM diff


def _components(bom: dict) -> dict[str, list[dict]]:
    """Group the SBOM components by package name (one name can appear with several versions)."""
    by_name: dict[str, list[dict]] = {}
    for c in bom.get("components", []):
        by_name.setdefault(c.get("name") or c.get("purl", ""), []).append(c)
    return by_name


def _label(c: dict) -> str:
    """Human label of a component: its purl, else name@version."""
    return c.get("purl") or f"{c.get('name')}@{c.get('version')}"


def sbom_diff(before: dict, after: dict) -> dict:
    """Compare two CycloneDX SBOMs by package name. A name whose version set differs is paired up into
    `changed` ({name, from, to}); leftover versions are `added` / `removed`. The five keys are the sbom_diff
    evidence contract the validator and UI read."""
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
    """(vulnerability id, package name) for every Grype match: the identity used to diff two scans."""
    return {(m.get("vulnerability", {}).get("id", ""), m.get("artifact", {}).get("name", ""))
            for m in data.get("matches", [])}


def rescan_patched(ctx: ToolContext) -> ToolOutput:
    """Syft the patched copy, Grype it, diff against the original SBOM. Facts of the sbom_diff Evidence are
    exactly the contract's; new/resolved vulnerabilities go into a separate scanner_output Evidence.

    Runs syft/grype on the patched copy (offline-capable: Grype uses its local DB when GUARDIAN_OFFLINE=1).
    If Grype fails the SBOM diff is still returned and the error is kept in ctx.artifacts["grype_error"]."""
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
