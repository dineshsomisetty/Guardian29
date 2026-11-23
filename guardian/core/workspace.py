"""Work-copy handling (D2-02, Dev2). Targets are never modified in place: every run works on a copy."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

_IGNORE = shutil.ignore_patterns("node_modules", "dist", "build", ".angular")


def run_dir(runs_root: Path, run_id: str) -> Path:
    d = Path(runs_root) / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def create_workspace(target: Path, run_path: Path) -> Path:
    """Copy `target` to `<run>/work/` (no node_modules) and strip git remotes so nothing can be pushed."""
    target, run_path = Path(target).resolve(), Path(run_path).resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"target not found: {target}")
    work = run_path / "work"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(target, work, ignore=_IGNORE, symlinks=True)
    if (work / ".git").exists():
        remotes = subprocess.run(["git", "-C", str(work), "remote"], capture_output=True, text=True).stdout.split()
        for r in remotes:
            subprocess.run(["git", "-C", str(work), "remote", "remove", r], check=True, capture_output=True)
    return work


def safe_path(work: Path, rel: str | Path) -> Path:
    """Resolve `rel` inside `work`; refuse anything that escapes it (G6.6)."""
    work = Path(work).resolve()
    p = (work / rel).resolve()
    if p != work and work not in p.parents:
        raise PermissionError(f"path escapes work copy: {rel}")
    return p
