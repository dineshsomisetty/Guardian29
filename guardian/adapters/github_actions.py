"""D4-12 GitHub Actions adapter: every `uses:` reference with its line. Owner: Dev4."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"#\s]+)['\"]?\s*(#.*)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class ActionRef:
    file: str
    line: int
    raw: str
    action: str
    ref: str | None
    pinned: bool
    local: bool


def workflows(root: Path) -> list[Path]:
    d = root / ".github" / "workflows"
    return sorted([*d.glob("*.yml"), *d.glob("*.yaml")]) if d.is_dir() else []


def parse(root: Path) -> list[ActionRef]:
    out = []
    for wf in workflows(root):
        rel = wf.relative_to(root).as_posix()
        for i, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = USES.match(line)
            if not m:
                continue
            target = m.group(1)
            local = target.startswith("./") or target.startswith("docker://")
            action, _, ref = target.partition("@")
            out.append(ActionRef(rel, i, line.strip(), action, ref or None,
                                 pinned=bool(ref and SHA.match(ref)), local=local))
    return out
