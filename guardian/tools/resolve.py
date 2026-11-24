"""D2-02 lockfile resolution without executing anything from the target. Owner: Dev2.

For each npm project: reuse a committed fixture lockfile when its package.json is byte-identical (C3: stable
results between rehearsal and demo); otherwise run
    npm install --package-lock-only --ignore-scripts --package-lock=true
(`--package-lock=true` overrides the target's `.npmrc package-lock=false`; `--ignore-scripts` = no install
scripts run, C2). The frontend needs `--legacy-peer-deps` (verified on Juice Shop, 2026-11-23).

Pipeline use: the discovery agent runs `resolve_lockfiles` right after the workspace is copied and before the SBOM,
so Syft/Grype see exact versions even for targets that do not commit a lockfile. The validator re-runs it on a
patched attempt copy so the rescan sees the upgraded versions.
Reads: package.json / package-lock.json / requirements*.txt in the work copy and tests/fixtures/<target>/.
Writes: package-lock.json files into the WORK COPY only (never the original target).
Evidence: one `detector_result` per npm project (source_tool resolve:npm) and per pip project (resolve:pip),
recording where the lockfile came from and `install_scripts_executed: False`.
Network: only the `npm install --package-lock-only` call talks to the npm registry (no package code runs).
Pip is never resolved or installed: the requirements pins are the lock. If npm fails, `run` raises and the
registry's call_tool logs the failure; with nothing to resolve the tool returns a summary only.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from guardian.adapters import pypi
from guardian.adapters.npm import find_projects
from guardian.core.config import REPO_ROOT
from guardian.core.models import Evidence
from guardian.tools.binaries import run, sha256_file
from guardian.tools.registry import ToolContext, ToolOutput


def _npm() -> str:
    """Path of the npm launcher (npm.cmd on Windows), falling back to plain "npm"."""
    return shutil.which("npm.cmd") or shutil.which("npm") or "npm"


def resolve_lockfiles(ctx: ToolContext) -> ToolOutput:
    """Make sure every npm project in the work copy has a lockfile and list pip requirements, running no
    install scripts. Returns one detector_result Evidence per project plus artifacts `npm_projects` and
    `pip_projects` (project names). Lockfile source, in priority order: seeded from the baseline copy and
    updated minimally (validator), already committed in the target, a hash-matching committed fixture, or a
    fresh `npm install --package-lock-only`."""
    work = ctx.work_dir or ctx.repo
    evidence, projects = [], []
    # a patched attempt copy lives in runs/<id>/attempts/<at>/work: the validator passes the target's name
    fixtures = REPO_ROOT / "tests" / "fixtures" / (ctx.artifacts.get("target_name") or ctx.repo.name)
    # validator: start from the lockfiles discovery resolved (runs/<id>/work), so npm only changes what the
    # patch requires; resolving from scratch let unrelated packages drift and show up as "new" in the diff
    base = ctx.artifacts.get("baseline_lock_root")
    for proj in find_projects(work):
        fixture_dir = fixtures / ("root" if proj.name == "root" else proj.name)
        seeded = None
        if base is not None and not proj.lockfile.exists():
            src = Path(base) / proj.lockfile.relative_to(work)
            if src.is_file():
                shutil.copyfile(src, proj.lockfile)
                seeded = src
        had_lock = proj.lockfile.exists()  # True only when the TARGET itself committed the lockfile
        base_manifest = Path(base) / proj.manifest.relative_to(work) if base is not None else None
        if seeded is not None and base_manifest is not None and base_manifest.is_file() and (
                base_manifest.read_bytes() == proj.manifest.read_bytes()):
            # the patch did not touch this manifest: discovery's lockfile already matches it, npm has nothing to change
            source = "discovery's lockfile (manifest unchanged by the patch, no npm call)"
            had_lock = False
        elif seeded is not None:
            args = [_npm(), "install", "--package-lock-only", "--ignore-scripts", "--package-lock=true",
                    "--no-audit", "--no-fund"]
            if proj.name != "root":
                args.append("--legacy-peer-deps")
            run(args, cwd=proj.dir, timeout=900)  # updates the seeded lock minimally to the patched manifest
            source = "discovery's lockfile, updated with npm install --package-lock-only --ignore-scripts"
            had_lock = False
        elif had_lock:
            source = "committed in target"
        elif (fixture_dir / "package-lock.json").exists() and (fixture_dir / "package.json").exists() and \
                sha256_file(fixture_dir / "package.json") == sha256_file(proj.manifest):
            shutil.copyfile(fixture_dir / "package-lock.json", proj.lockfile)
            source = f"fixture tests/fixtures/{fixtures.name}/{fixture_dir.name} (manifest hash match)"
        else:
            args = [_npm(), "install", "--package-lock-only", "--ignore-scripts", "--package-lock=true",
                    "--no-audit", "--no-fund"]
            if proj.name != "root":
                args.append("--legacy-peer-deps")
            run(args, cwd=proj.dir, timeout=900)
            source = "npm install --package-lock-only --ignore-scripts"
        projects.append(proj.name)
        evidence.append(Evidence(
            run_id=ctx.run_id, kind="detector_result", source_tool="resolve:npm",
            facts={"project": proj.name, "lockfile": proj.lockfile.relative_to(work).as_posix(),
                   "lockfile_in_target": had_lock, "source": source, "install_scripts_executed": False},
            file_path=proj.lockfile.relative_to(work).as_posix(), sha256=sha256_file(proj.lockfile)))
    pip_projects = []
    for proj in pypi.find_projects(work):  # pip: requirements pins are the lock; nothing is installed (C2)
        pins = [p for r in proj.requirements for p in pypi.requirement_pins(r)]
        pip_projects.append(proj.name)
        evidence.append(Evidence(
            run_id=ctx.run_id, kind="detector_result", source_tool="resolve:pip",
            facts={"project": proj.name, "requirements": [r.relative_to(work).as_posix() for r in proj.requirements],
                   "pinned": sum(1 for p in pins if p[1]), "unpinned": sum(1 for p in pins if not p[1]),
                   "source": "requirements pins (not resolved, not installed)", "install_scripts_executed": False},
            file_path=proj.requirements[0].relative_to(work).as_posix(), sha256=sha256_file(proj.requirements[0])))
    if not projects and not pip_projects:
        return ToolOutput(summary="no npm or pip project found: nothing to resolve")
    return ToolOutput(evidence=evidence, artifacts={"npm_projects": projects, "pip_projects": pip_projects},
                      summary=f"lockfiles for {projects}, pip requirements for {pip_projects} "
                              f"(no install scripts executed)")
