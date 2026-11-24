"""Locate pinned scanner binaries (tools/bin first, then PATH) and run them safely. Owner: Dev2."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from guardian.core.config import REPO_ROOT

BIN_DIR = REPO_ROOT / "tools" / "bin"


class BinaryMissing(RuntimeError):
    pass


def find(name: str) -> str:
    for cand in (BIN_DIR / f"{name}.exe", BIN_DIR / name):
        if cand.exists():
            return str(cand)
    found = shutil.which(name)
    if not found:
        raise BinaryMissing(f"{name} not found (run scripts/install_tools.ps1)")
    return found


def scanner_env(env: dict[str, str] | None = None) -> dict[str, str]:
    out = dict(os.environ if env is None else env)
    out.setdefault("SYFT_CHECK_FOR_APP_UPDATE", "false")
    out.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")
    if out.get("GUARDIAN_OFFLINE") == "1":
        out["GRYPE_DB_AUTO_UPDATE"] = "false"
        out["GRYPE_DB_VALIDATE_AGE"] = "false"  # an older local DB is fine offline; the run records its age
    return out


def run(args: list[str], cwd: Path | None = None, timeout: int = 900, ok_codes=(0,),
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """argv list only, never a shell (§0 rule 5). Scanner self-update checks are always off, and with
    GUARDIAN_OFFLINE=1 Grype never refreshes its database (G7.3: an offline run makes no network call)."""
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env=scanner_env(env))
    if proc.returncode not in ok_codes:
        raise RuntimeError(f"{Path(args[0]).name} exited {proc.returncode}: {proc.stderr.strip()[-400:]}")
    return proc


def version(name: str) -> str:
    try:
        out = run([find(name), "version"], timeout=30).stdout
    except Exception:  # noqa: BLE001
        return "unknown"
    for line in out.splitlines():
        if line.lower().startswith("version"):
            return line.split(":", 1)[1].strip()
    return out.strip().split()[-1] if out.strip() else "unknown"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
