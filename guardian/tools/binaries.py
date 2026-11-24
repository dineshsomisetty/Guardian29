"""Locate pinned scanner binaries (tools/bin first, then PATH) and run them safely. Owner: Dev2.

Used by nearly every tool that shells out: syft (sbom.py, sandbox.py), grype (scanners.py, sandbox.py), git
(local_pr.py, patching.py), docker (sandbox.py) and npm launchers. Nothing here reads or writes the target.
Rules enforced for all callers: commands are argv lists and never go through a shell (§0 rule 5); scanner
self-update checks are always disabled; with GUARDIAN_OFFLINE=1 Grype never refreshes its vulnerability DB, so
an offline run makes no network call from the scanners (G7.3).
Failure behaviour: a missing binary raises BinaryMissing (callers turn it into "tool unavailable" or a skipped
check); a non-zero exit raises RuntimeError with the tail of stderr unless the code is in `ok_codes`.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from guardian.core.config import REPO_ROOT

BIN_DIR = REPO_ROOT / "tools" / "bin"  # pinned binaries installed by scripts/install_tools.ps1


class BinaryMissing(RuntimeError):
    """A required external program is neither in tools/bin nor on PATH."""

    pass


def find(name: str) -> str:
    """Absolute path of binary `name`: the pinned copy in tools/bin wins over whatever is on PATH, so results
    do not depend on the developer's machine. Raises BinaryMissing when neither exists."""
    for cand in (BIN_DIR / f"{name}.exe", BIN_DIR / name):
        if cand.exists():
            return str(cand)
    found = shutil.which(name)
    if not found:
        raise BinaryMissing(f"{name} not found (run scripts/install_tools.ps1)")
    return found


def scanner_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """Environment for a scanner subprocess: `env` (or os.environ) plus update checks off and, when
    GUARDIAN_OFFLINE=1, Grype's DB auto-update and age validation off. Never mutates the input."""
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
    """Version string reported by `<name> version` (for evidence provenance), or "unknown" on any failure."""
    try:
        out = run([find(name), "version"], timeout=30).stdout
    except Exception:  # noqa: BLE001
        return "unknown"
    for line in out.splitlines():
        if line.lower().startswith("version"):
            return line.split(":", 1)[1].strip()
    return out.strip().split()[-1] if out.strip() else "unknown"


def sha256_file(path: Path) -> str:
    """Hex SHA-256 of a file, read in 1 MiB chunks (used to fingerprint artifacts stored as evidence)."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
