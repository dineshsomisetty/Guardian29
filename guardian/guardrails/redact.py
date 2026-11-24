"""G1.2 secret-pattern redaction before text reaches an LLM, a log or a report. Owner: Dev1.

Called from `untrusted.wrap` (everything put into a prompt), `AuditLog` (every event/audit entry) and the
report writer. It is a safety net, not the primary control: `file_read` (G1.1) already refuses to open sensitive
files, so secrets should rarely reach here; redaction catches the ones that slip into excerpts, logs or scanner
output. Matching is pattern based (well-known token shapes plus `password = ...` style assignments), so it can
miss an unusual secret and may redact a harmless look-alike; it errs on the side of redacting.
Each replacement names the kind of secret (`[REDACTED:github_token]`) so a reader knows what was removed.
"""

from __future__ import annotations

import re
from typing import Any

# Order matters: specific token shapes first, the generic `key = value` assignment last (it would otherwise
# hide the more informative placeholder). Each entry is (name used in the placeholder, compiled regex).
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("npm_token", re.compile(r"npm_[A-Za-z0-9]{30,}")),
    (
        "assignment",
        re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token|auth)\b(\s*[:=]\s*)(['\"]?)([^\s'\"]{6,})\3"),
    ),
]


def redact(text: str) -> str:
    """Return `text` with every secret-looking span replaced by a placeholder. Empty input is returned as is.

    For assignments (`password: hunter22`) the key and quotes are kept and only the value is replaced, so the
    surrounding config line stays readable."""
    if not text:
        return text
    for name, pat in _PATTERNS:
        if name == "assignment":
            text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED]{m.group(3)}", text)
        else:
            text = pat.sub(f"[REDACTED:{name}]", text)
    return text


def redact_obj(obj: Any) -> Any:
    """Redact every string inside a nested dict / list / tuple (tuples come back as lists); other values pass
    through. Used on event `data` and audit payloads, which are arbitrary JSON-like structures."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [redact_obj(v) for v in obj]
    return obj
