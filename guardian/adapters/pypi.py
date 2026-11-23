"""pip / PyPI ecosystem adapter (D2-09, Dev2): requirements files + dependency edges from PyPI metadata.

No resolver is run: `pip install --dry-run` may build sdists (= execute setup.py). Instead the pinned
requirements are read as-is and edges come from each pinned release's `requires_dist` in the PyPI JSON API
(pypi.org is on the §14 allowlist). Responses are cached on disk; GUARDIAN_OFFLINE=1 uses the cache only.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import InvalidRequirement, Requirement

ROOT = Path(__file__).resolve().parents[2]
CACHE_DIR = ROOT / "data" / "cache" / "intel" / "pypi"
# Environment used to evaluate markers: the target's container (PyGoat: python:3.11-slim, linux x86_64).
TARGET_ENV = {**default_environment(), "python_version": "3.11", "python_full_version": "3.11.0",
              "sys_platform": "linux", "platform_system": "Linux", "os_name": "posix",
              "platform_machine": "x86_64", "implementation_name": "cpython"}


def normalize(name: str) -> str:
    """PEP 503 name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Requirement_:
    name: str  # normalised
    raw_name: str
    spec: str  # e.g. "==4.2"
    pinned_version: str | None
    has_hash: bool
    line: int
    excerpt: str


def parse_requirements(path: Path) -> list[Requirement_]:
    """Requirement lines with line numbers; skips comments, options (-r, -e, --index-url) and URLs."""
    out: list[Requirement_] = []
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    for i, raw in enumerate(lines, 1):
        s = raw.split(" #", 1)[0].strip()
        if not s or s.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        try:
            req = Requirement(s.split(" --hash", 1)[0].rstrip("\\ ").strip())
        except InvalidRequirement:
            continue
        pins = [sp.version for sp in req.specifier if sp.operator in ("==", "===")]
        has_hash = "--hash" in raw or (i < len(lines) and lines[i].strip().startswith("--hash"))
        out.append(Requirement_(normalize(req.name), req.name, str(req.specifier), pins[0] if pins else None,
                                has_hash, i, raw.strip()))
    return out


def release_metadata(name: str, version: str, timeout: float = 20.0) -> dict:
    """PyPI JSON `info` for name==version (cached; offline -> cache only, {} if missing)."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    f = CACHE_DIR / f"{normalize(name)}-{version}.json"
    if f.is_file():
        return json.loads(f.read_text(encoding="utf-8"))
    if os.environ.get("GUARDIAN_OFFLINE") == "1":
        return {}
    import httpx

    r = httpx.get(f"https://pypi.org/pypi/{normalize(name)}/{version}/json", timeout=timeout,
                  headers={"User-Agent": "guardian-supply-chain-scanner"})
    if r.status_code != 200:
        return {}
    info = r.json().get("info", {})
    keep = {k: info.get(k) for k in ("name", "version", "requires_dist", "requires_python", "project_urls",
                                     "home_page", "yanked", "yanked_reason")}
    f.write_text(json.dumps(keep), encoding="utf-8")
    return keep


def runtime_dependencies(info: dict) -> list[str]:
    """Normalised names of requirements that apply in TARGET_ENV without extras."""
    out = []
    for rd in info.get("requires_dist") or []:
        try:
            req = Requirement(rd)
        except InvalidRequirement:
            continue
        if req.marker is not None and not req.marker.evaluate({**TARGET_ENV, "extra": ""}):
            continue
        out.append(normalize(req.name))
    return out


def pypi_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{normalize(name)}@{version}"
