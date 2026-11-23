"""'What changed' diff between two npm manifests/lockfiles (D4-11 -> changes.json, section 4).

CP1 use: ftp/package.json.bak (legacy) vs package.json. Dev2 generalises this in D2-06
(lockfile-aware comparison, --compare-ref); the output shape is the same.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def _purl(name: str, version: str) -> str:
    n = name.replace("@", "%40", 1) if name.startswith("@") else name
    return f"pkg:npm/{n}@{version}"


def _major(spec: str) -> int | None:
    m = re.search(r"(\d+)", spec or "")
    return int(m.group(1)) if m else None


def _load_manifest(path: Path) -> dict:
    # `.bak` suffix: always parse as JSON text, never rely on the extension.
    return json.loads(path.read_text(encoding="utf-8"))


def _deps(manifest: dict) -> dict[str, str]:
    out: dict[str, str] = {}
    for sec in SECTIONS:
        out.update(manifest.get(sec) or {})
    return out


def _lock_packages(lock: dict) -> dict[str, dict]:
    """name -> {version, integrity, hasInstallScript} from a v2/v3 lockfile (top-level copy)."""
    out: dict[str, dict] = {}
    for key, meta in (lock.get("packages") or {}).items():
        if not key:
            continue
        name = key.split("node_modules/")[-1]
        if "node_modules/" in key[: key.rfind("node_modules/")]:
            continue  # nested copy; keep the hoisted one only
        out[name] = meta
    return out


def compute_changes(
    base: Path | str,
    head: Path | str,
    base_lock: Path | str | None = None,
    head_lock: Path | str | None = None,
    add_evidence: Callable[[dict], str] | None = None,
) -> dict:
    """Return the changes.json document. `add_evidence(fact_dict) -> evidence_id` is optional."""
    base, head = Path(base), Path(head)
    bm, hm = _load_manifest(base), _load_manifest(head)
    bd, hd = _deps(bm), _deps(hm)

    added = sorted(_purl(n, v) for n, v in hd.items() if n not in bd)
    removed = sorted(_purl(n, v) for n, v in bd.items() if n not in hd)
    changed = []
    for n in sorted(set(bd) & set(hd)):
        if bd[n] != hd[n]:
            bmaj, hmaj = _major(bd[n]), _major(hd[n])
            changed.append({
                "name": n, "from": bd[n], "to": hd[n],
                "major_jump": bmaj is not None and hmaj is not None and bmaj != hmaj,
            })

    integrity_changed: list[dict] = []
    scripts_added: list[str] = []
    if base_lock and head_lock:
        bl = _lock_packages(json.loads(Path(base_lock).read_text(encoding="utf-8")))
        hl = _lock_packages(json.loads(Path(head_lock).read_text(encoding="utf-8")))
        for n in sorted(set(bl) & set(hl)):
            b, h = bl[n], hl[n]
            if b.get("version") == h.get("version") and b.get("integrity") and h.get("integrity") \
                    and b["integrity"] != h["integrity"]:
                integrity_changed.append({
                    "purl": _purl(n, h["version"]), "from": b["integrity"], "to": h["integrity"],
                })
            if h.get("hasInstallScript") and not b.get("hasInstallScript"):
                scripts_added.append(_purl(n, h.get("version", "")))

    # install scripts in the project's own manifest (own scripts, reported as a fact only)
    for s in ("preinstall", "install", "postinstall"):
        if s in (hm.get("scripts") or {}) and s not in (bm.get("scripts") or {}):
            scripts_added.append(f"project:{s}")

    doc = {
        "base": str(base).replace("\\", "/"), "head": str(head).replace("\\", "/"),
        "added": added, "removed": removed, "changed": changed,
        "integrity_changed": integrity_changed, "install_scripts_added": scripts_added,
        "evidence_ids": [],
    }
    if add_evidence:
        doc["evidence_ids"] = [add_evidence({
            "kind": "manifest_diff", "base": doc["base"], "head": doc["head"],
            "counts": {"added": len(added), "removed": len(removed), "changed": len(changed),
                       "major_jumps": sum(c["major_jump"] for c in changed)},
        })]
    return doc


def write_changes(run_dir: Path | str, doc: dict) -> Path:
    out = Path(run_dir) / "changes.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return out
