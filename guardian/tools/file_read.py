"""G1.1 file_read: the only way agents read target files. Denies sensitive paths. Owner: Dev1.

Used by the investigator (file_excerpt) and other agents that quote target code in evidence. Reads one file from
the sandboxed work copy, never writes, makes no network or subprocess call. Guardrail G1.1: a path that escapes
the root (`..`, symlink) or names a secret (keys, .env, encryption key folders) raises FileReadDenied, and
whatever is returned is passed through `redact` so tokens that slip in are masked before they reach a prompt
or the audit log. Output is capped at MAX_BYTES so one call cannot flood a model's context.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from guardian.guardrails.redact import redact

DENY_DIRS = {"encryptionkeys"}  # any path component with this name (Juice Shop's key folder), case-insensitive
# file-name patterns (matched against the lower-cased name only): credentials and private keys
DENY_GLOBS = ["ctf.key", ".env", ".env.*", "*.pem", "*.key", "id_rsa*", "*.p12", "*.pfx"]
MAX_BYTES = 64_000  # ~64 KB read limit per call: enough for any source file, small enough for a prompt


class FileReadDenied(PermissionError):
    """The requested path is outside the work copy or matches the sensitive-file deny list (G1.1)."""

    pass


def is_denied(rel: Path) -> bool:
    """True if a path relative to the root is sensitive: in a denied directory or matching a denied name."""
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
