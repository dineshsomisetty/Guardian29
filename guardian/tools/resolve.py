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
                fx = Path(fixtures) / rel / "package-lock.json" if fixtures else None
                if fx and fx.is_file():
                    shutil.copy(fx, d / "package-lock.json")
                    out[name] = {"lockfile": str(d / "package-lock.json"), "seconds": 0, "flags": ["fixture-fallback"]}
                else:
                    raise e
    return out
