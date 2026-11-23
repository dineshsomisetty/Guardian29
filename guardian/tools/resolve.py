"""Lockfile resolution without executing untrusted code (D2-02, Dev2; decision C2).

`npm install --package-lock-only --ignore-scripts` builds the full tree from the registry metadata only.
`--package-lock=true` overrides targets whose .npmrc sets `package-lock=false` (Juice Shop).
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

NPM_ARGS = ["install", "--package-lock-only", "--ignore-scripts", "--package-lock=true",
            "--no-audit", "--no-fund"]


def _npm() -> str:
    exe = shutil.which("npm")
    if not exe:
        raise RuntimeError("npm not found on PATH")
    return exe


def resolve_npm_project(project_dir: Path, legacy_peer_deps: bool = False, timeout: int = 600) -> dict:
    """Generate package-lock.json in `project_dir`. Returns {lockfile, seconds, flags}. No shell, no scripts."""
    project_dir = Path(project_dir)
    if not (project_dir / "package.json").is_file():
        raise FileNotFoundError(f"no package.json in {project_dir}")
    args = list(NPM_ARGS) + (["--legacy-peer-deps"] if legacy_peer_deps else [])
    t0 = time.time()
    proc = subprocess.run([_npm(), *args], cwd=project_dir, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"npm resolve failed in {project_dir} (rc={proc.returncode}): {proc.stderr[-800:]}")
    lock = project_dir / "package-lock.json"
    if not lock.is_file():
        raise RuntimeError(f"npm succeeded but wrote no lockfile in {project_dir}")
    return {"lockfile": str(lock), "seconds": round(time.time() - t0, 1), "flags": args}


def _fixture_lock(fixtures: Path | None, name: str, rel: str) -> Path | None:
    """Committed fallback lockfile. Accepts `<fx>/<rel>/package-lock.json` or Dev5's `<fx>/<name>.package-lock.json`
    (root project: `<fx>/package-lock.json`)."""
    if not fixtures:
        return None
    fixtures = Path(fixtures)
    for cand in (fixtures / ("" if rel in (".", "") else rel) / "package-lock.json",
                 fixtures / f"{name}.package-lock.json"):
        if cand.is_file():
            return cand
    return None


def resolve_all(work: Path, projects: dict[str, str] | None = None, fixtures: Path | None = None) -> dict:
    """Resolve each npm project (default: root + frontend). Falls back to committed fixture lockfiles."""
    work = Path(work)
    projects = projects or {"root": ".", "frontend": "frontend"}
    out = {}
    for name, rel in projects.items():
        d = work / rel
        if not (d / "package.json").is_file():
            continue
        try:
            out[name] = resolve_npm_project(d)
        except Exception:
            try:  # frontend often needs this
                out[name] = resolve_npm_project(d, legacy_peer_deps=True)
            except Exception as e:
                fx = _fixture_lock(fixtures, name, rel)
                if fx:
                    shutil.copy(fx, d / "package-lock.json")
                    out[name] = {"lockfile": str(d / "package-lock.json"), "seconds": 0, "flags": ["fixture-fallback"]}
                else:
                    raise e
    return out


def resolve_lockfiles(ctx):
    """Tool entry point (registry binding `resolve_lockfiles`). Never executes install scripts (C2, rule 6)."""
    from guardian.tools.registry import ToolOutput

    root = Path(__file__).resolve().parents[2]
    work = Path(ctx.work_dir or ctx.repo)
    res = resolve_all(work, fixtures=root / "tests" / "fixtures" / Path(ctx.repo).name)
    detail = ", ".join(f"{k}: {v['seconds']}s{' (fixture)' if 'fixture-fallback' in v['flags'] else ''}"
                       for k, v in res.items())
    return ToolOutput(artifacts={"lockfiles": res}, summary=f"lockfiles resolved ({detail}); --ignore-scripts")
