"""npm ecosystem adapter (D2-05, Dev2): manifests, dependency sections with line numbers, .npmrc, lockfile presence.

Pure file parsing, no network and no process execution. Paths are returned relative to the base dir (posix).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PROJECTS = {"root": ".", "frontend": "frontend"}
SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
_SECTION_START = re.compile(r'^\s*"(dependencies|devDependencies|optionalDependencies|peerDependencies)"\s*:\s*\{')
_ENTRY = re.compile(r'^\s*"([^"]+)"\s*:\s*"([^"]*)"')


@dataclass(frozen=True)
class ManifestDep:
    name: str
    spec: str
    section: str
    line: int  # 1-based line in package.json
    excerpt: str

    @property
    def scope(self) -> str:
        return "prod" if self.section in ("dependencies", "optionalDependencies") else "dev"


@dataclass
class NpmProject:
    name: str  # "root" | "frontend"
    rel: str  # directory relative to base ("." or "frontend")
    dir: Path
    manifest: Path
    deps: list[ManifestDep] = field(default_factory=list)

    def relpath(self, filename: str) -> str:
        return filename if self.rel in (".", "") else f"{self.rel}/{filename}"


def parse_manifest(manifest: Path) -> list[ManifestDep]:
    """Dependencies from package.json with the line each one is declared on."""
    text = Path(manifest).read_text(encoding="utf-8")
    parsed = json.loads(text)
    declared = {s: parsed.get(s, {}) for s in SECTIONS}
    out: list[ManifestDep] = []
    section = None
    for i, line in enumerate(text.splitlines(), 1):
        m = _SECTION_START.match(line)
        if m:
            section = m.group(1)
            continue
        if section and re.match(r"^\s*\},?\s*$", line):
            section = None
            continue
        e = _ENTRY.match(line) if section else None
        if e and e.group(1) in declared[section]:
            out.append(ManifestDep(e.group(1), e.group(2), section, i, line.strip()))
    return out


def find_projects(base: Path, projects: dict[str, str] | None = None) -> list[NpmProject]:
    base = Path(base)
    found = []
    for name, rel in (projects or DEFAULT_PROJECTS).items():
        d = base / ("" if rel in (".", "") else rel)
        mf = d / "package.json"
        if mf.is_file():
            found.append(NpmProject(name, rel, d, mf, parse_manifest(mf)))
    return found


def has_lockfile(project_dir: Path) -> bool:
    return any((Path(project_dir) / f).is_file() for f in LOCKFILES)


def read_npmrc(project_dir: Path) -> list[tuple[int, str, str, str]]:
    """`.npmrc` entries as (line, key, value, raw_line); comments/blank lines skipped."""
    p = Path(project_dir) / ".npmrc"
    if not p.is_file():
        return []
    out = []
    for i, raw in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith(("#", ";")) or "=" not in s:
            continue
        k, v = s.split("=", 1)
        out.append((i, k.strip(), v.strip(), s))
    return out


_LOCK_KEY = re.compile(r'^\s*"((?:[^"]*/)?node_modules/[^"]+)"\s*:\s*\{')


def lock_entries(lock_path: Path) -> dict[str, dict]:
    """Lockfile v2/v3 `packages` entries keyed by path, each with `_line` (1-based line of its key) and `_name`."""
    text = Path(lock_path).read_text(encoding="utf-8")
    pk = json.loads(text).get("packages", {})
    lines = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = _LOCK_KEY.match(line)
        if m and m.group(1) not in lines:
            lines[m.group(1)] = i
    out = {}
    for key, ent in pk.items():
        if not key or "node_modules/" not in key:
            continue
        out[key] = {**ent, "_line": lines.get(key), "_name": ent.get("name") or key.rsplit("node_modules/", 1)[1]}
    return out


def npm_purl(name: str, version: str) -> str:
    return f"pkg:npm/{name.replace('@', '%40', 1) if name.startswith('@') else name}@{version}"
