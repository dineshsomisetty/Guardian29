"""G1.1 file_read: the only way agents read target files. Denies sensitive paths. Owner: Dev1."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from guardian.guardrails.redact import redact

DENY_DIRS = {"encryptionkeys"}
DENY_GLOBS = ["ctf.key", ".env", ".env.*", "*.pem", "*.key", "id_rsa*", "*.p12", "*.pfx"]
MAX_BYTES = 64_000


class FileReadDenied(PermissionError):
    pass


def is_denied(rel: Path) -> bool:
    if any(part.lower() in DENY_DIRS for part in rel.parts):
        return True
    return any(fnmatch.fnmatch(rel.name.lower(), g) for g in DENY_GLOBS)


def file_read(root: Path, rel_path: str, start: int = 1, end: int | None = None) -> str:
    """Read lines [start, end] of a file inside `root`. Refuses paths outside root and sensitive files."""
    root = root.resolve()
    target = (root / rel_path).resolve()
    if not target.is_relative_to(root):
        raise FileReadDenied(f"{rel_path} is outside the work copy")
    rel = target.relative_to(root)
    if is_denied(rel):
        raise FileReadDenied(f"{rel} is a sensitive file (G1.1)")
    data = target.read_bytes()[:MAX_BYTES].decode("utf-8", errors="replace")
    lines = data.splitlines()
    return redact("\n".join(lines[start - 1:end]))
