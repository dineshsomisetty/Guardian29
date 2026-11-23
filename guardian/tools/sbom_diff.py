"""Before/after SBOM diff (D2-08, Dev2): what the patch actually changed in the shipped component set.

Compares two CycloneDX SBOMs by package identity (ecosystem + name, purl without version/qualifiers):
added, removed, and version changes. Pure function; the validator stores the result as Evidence(kind="sbom_diff").
"""
from __future__ import annotations

import json
from pathlib import Path


def _key_and_version(purl: str) -> tuple[str, str]:
    base = purl.split("?", 1)[0].split("#", 1)[0]
    name, _, ver = base.rpartition("@")
    if not name or "/" not in name:  # purl without version
        return base, ""
    return name, ver


def components(sbom: dict | Path | str) -> dict[str, set[str]]:
    """package key (e.g. `pkg:npm/express`) -> set of versions present."""
    doc = sbom if isinstance(sbom, dict) else json.loads(Path(sbom).read_text(encoding="utf-8"))
    out: dict[str, set[str]] = {}
    for c in doc.get("components", []):
        purl = c.get("purl")
        if not purl or c.get("type") not in (None, "library", "framework", "application"):
            continue
        k, v = _key_and_version(purl)
        out.setdefault(k, set()).add(v)
    return out


def sbom_diff(before: dict | Path | str, after: dict | Path | str) -> dict:
    b, a = components(before), components(after)
    added = sorted(f"{k}@{v}" for k in a.keys() - b.keys() for v in a[k])
    removed = sorted(f"{k}@{v}" for k in b.keys() - a.keys() for v in b[k])
    changed = []
    for k in sorted(a.keys() & b.keys()):
        if a[k] != b[k]:
            changed.append({"package": k, "from": sorted(b[k] - a[k]), "to": sorted(a[k] - b[k]),
                            "unchanged": sorted(a[k] & b[k])})
    return {"before_components": sum(len(v) for v in b.values()),
            "after_components": sum(len(v) for v in a.values()),
            "added": added, "removed": removed, "changed": changed,
            "summary": f"+{len(added)} -{len(removed)} ~{len(changed)}"}


def has_version(sbom: dict | Path | str, purl: str) -> bool:
    """Is exactly this name@version still in the SBOM? (used to check the target component is gone)."""
    k, v = _key_and_version(purl)
    return v in components(sbom).get(k, set())
