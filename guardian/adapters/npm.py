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
