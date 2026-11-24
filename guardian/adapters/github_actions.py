"""D4-12 GitHub Actions adapter: every `uses:` reference with its line. Owner: Dev4.

Scans .github/workflows/*.yml|yaml line by line for `uses: owner/repo@ref` (no YAML parsing, so it also works on
slightly broken files). Used by the CI supply-chain detectors: an action referenced by a tag or branch can be
silently changed by its owner, only a full 40-hex commit SHA is immutable. `parse(root)` returns a list of
`ActionRef` (file, line, action name, ref, whether it is SHA-pinned, whether it is local or a docker:// image).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# matches `uses: x/y@ref` (optionally a list item, quoted, with a trailing comment); group 1 = x/y@ref
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"#\s]+)['\"]?\s*(#.*)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class ActionRef:
    """One `uses:` line. `ref` is the part after "@" (None if absent); `local` references need no pinning."""

    file: str
    line: int
    raw: str
    action: str
    ref: str | None
    pinned: bool
    local: bool


def workflows(root: Path) -> list[Path]:
    """Workflow files under root/.github/workflows (.yml and .yaml), sorted; empty if the folder is missing."""
    d = root / ".github" / "workflows"
    return sorted([*d.glob("*.yml"), *d.glob("*.yaml")]) if d.is_dir() else []


def parse(root: Path) -> list[ActionRef]:
    """All action references of all workflows of the repo at `root`, in file and line order."""
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
