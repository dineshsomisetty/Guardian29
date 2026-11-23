"""D4-11 "what changed" mini-diff for CP1: legacy backup manifest vs current. Owner: Dev4 (Dev2 generalises in D2-06).

Compares `ftp/package.json.bak` (shipped legacy manifest) with the current `package.json`:
added / removed / changed dependencies (with major-version jump flag), and integrity hashes in
`ftp/package-lock.json.bak` vs the freshly resolved lockfile for identical name@version.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from guardian.adapters.npm import purl
from guardian.core.models import Evidence
from guardian.tools.registry import ToolContext, ToolOutput

BASE_MANIFEST = "ftp/package.json.bak"
BASE_LOCK = "ftp/package-lock.json.bak"
_VER = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _deps(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {**data.get("dependencies", {}), **data.get("devDependencies", {})}


def _base(rng: str) -> str:
    m = _VER.search(rng)
    return ".".join(g for g in m.groups() if g is not None) if m else rng


def _major(rng: str) -> int | None:
    m = _VER.search(rng)
    return int(m.group(1)) if m else None


def _lock_integrity(path: Path) -> dict[str, str]:
    """name@version -> integrity, for lockfile v1 (nested `dependencies`) and v2/v3 (`packages`)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for key, e in (data.get("packages") or {}).items():
        if key and e.get("version") and e.get("integrity"):
            out[f"{e.get('name') or key.rsplit('node_modules/', 1)[-1]}@{e['version']}"] = e["integrity"]

    def walk(deps: dict) -> None:
        for name, e in (deps or {}).items():
            if e.get("version") and e.get("integrity"):
                out.setdefault(f"{name}@{e['version']}", e["integrity"])
            walk(e.get("dependencies"))

    walk(data.get("dependencies"))
    return out


def mini_diff(ctx: ToolContext) -> ToolOutput:
    root = ctx.work_dir or ctx.repo
    base, head = root / BASE_MANIFEST, root / "package.json"
    if not base.exists() or not head.exists():
        return ToolOutput(summary="no legacy manifest to compare")
    b, h = _deps(base), _deps(head)
    added = sorted(purl(n, _base(h[n])) for n in h.keys() - b.keys())
    removed = sorted(purl(n, _base(b[n])) for n in b.keys() - h.keys())
    changed = []
    for n in sorted(b.keys() & h.keys()):
        if b[n] != h[n]:
            mb, mh = _major(b[n]), _major(h[n])
            changed.append({"name": n, "from": _base(b[n]), "to": _base(h[n]), "from_range": b[n], "to_range": h[n],
                            "major_jump": mb is not None and mh is not None and mh - mb >= 1})

    integrity_changed = []
    base_lock, head_lock = root / BASE_LOCK, root / "package-lock.json"
    if base_lock.exists() and head_lock.exists():
        bi, hi = _lock_integrity(base_lock), _lock_integrity(head_lock)
        for key in sorted(bi.keys() & hi.keys()):
            if bi[key] != hi[key] and bi[key].split("-")[0] == hi[key].split("-")[0]:
                name, _, ver = key.rpartition("@")
                integrity_changed.append({"purl": purl(name, ver), "from": bi[key], "to": hi[key]})

    facts = {"base": BASE_MANIFEST, "head": "package.json", "added": len(added), "removed": len(removed),
             "changed": len(changed), "major_jumps": sum(c["major_jump"] for c in changed),
             "integrity_changed": len(integrity_changed),
             "removed_names": [r.split("/")[-1] for r in removed][:50]}
    ev = Evidence(run_id=ctx.run_id, kind="changes", source_tool="detector:mini_diff", facts=facts,
                  file_path=BASE_MANIFEST)
    changes = {"base": BASE_MANIFEST, "head": "package.json", "added": added, "removed": removed,
               "changed": changed, "integrity_changed": integrity_changed, "install_scripts_added": [],
               "evidence_ids": [ev.evidence_id]}
    return ToolOutput(evidence=[ev], artifacts={"changes": changes},
                      summary=f"+{len(added)} / -{len(removed)} / ~{len(changed)} deps "
                              f"({facts['major_jumps']} major jumps) vs legacy manifest")
