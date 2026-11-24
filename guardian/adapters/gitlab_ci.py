"""GitLab CI adapter: container images used by pipeline jobs, and remote includes. Owner: Dev4.

`.gitlab-ci.yml` (and any `*.gitlab-ci.yml` / `.gitlab/**/*.yml` it splits into) is the GitLab counterpart of
`.github/workflows`: job `image:` / `services:` are third-party containers that run with the repository's CI
credentials, and `include: project/ref` or `include: remote` pulls pipeline code from elsewhere. Both are
supply-chain components; a tag or branch can be moved by whoever controls the source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

SHA = re.compile(r"^[0-9a-f]{40}$")
_RESERVED = {"stages", "variables", "include", "default", "workflow", "image", "services", "before_script",
             "after_script", "cache", "pages"}


@dataclass
class CiImage:
    file: str
    line: int
    raw: str
    image: str
    tag: str | None
    digest: str | None
    role: str  # "image" | "service"


@dataclass
class CiInclude:
    file: str
    line: int
    raw: str
    source: str  # project path or remote URL
    ref: str | None
    pinned: bool


def pipeline_files(root: Path) -> list[Path]:
    files = {*root.glob("*.gitlab-ci.yml"), *root.glob(".gitlab-ci.yml")}
    g = root / ".gitlab"
    if g.is_dir():
        files |= {*g.rglob("*.yml"), *g.rglob("*.yaml")}
    return sorted(f for f in files if f.is_file())[:30]


def split_ref(ref: str) -> tuple[str, str | None, str | None]:
    """'docker:19.03.1-dind' -> ('docker', '19.03.1-dind', None); digest kept apart."""
    name, _, digest = ref.partition("@")
    last = name.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else None
    image = name[: len(name) - len(tag) - 1] if tag else name
    return image, tag, digest or None


def _line_of(lines: list[str], needle: str, start: int = 0) -> tuple[int, str]:
    """First line holding `needle` as a whole token ("docker:19.03.1" must not match "docker:19.03.1-dind")."""
    pat = re.compile(r"(?<![\w./:@-])" + re.escape(needle) + r"(?![\w.:@-])")
    for i in range(start, len(lines)):
        if pat.search(lines[i]):
            return i + 1, lines[i].strip()
    return 1, needle


def _image_name(v) -> str | None:
    if isinstance(v, str):
        return v.strip() or None
    if isinstance(v, dict) and isinstance(v.get("name"), str):
        return v["name"].strip() or None
    return None


def parse(root: Path) -> tuple[list[CiImage], list[CiInclude]]:
    images: list[CiImage] = []
    includes: list[CiInclude] = []
    for f in pipeline_files(root):
        rel = f.relative_to(root).as_posix()
        text = f.read_text(encoding="utf-8", errors="replace")
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        lines = text.splitlines()
        jobs = [doc, doc.get("default") or {}, *(v for k, v in doc.items() if k not in _RESERVED and isinstance(v, dict))]
        seen: set[tuple[str, str]] = set()
        for job in jobs:
            if not isinstance(job, dict):
                continue
            refs = [("image", _image_name(job.get("image")))]
            refs += [("service", _image_name(s)) for s in (job.get("services") or []) if isinstance(job.get("services"), list)]
            for role, ref in refs:
                if not ref or ref.startswith("$") or (role, ref) in seen:
                    continue  # variables are resolved at pipeline time: nothing to pin here
                seen.add((role, ref))
                image, tag, digest = split_ref(ref)
                line, raw = _line_of(lines, ref)
                images.append(CiImage(rel, line, raw, image, tag, digest, role))
        inc = doc.get("include")
        for item in inc if isinstance(inc, list) else [inc] if inc else []:
            if isinstance(item, dict) and item.get("project"):
                ref = str(item.get("ref")) if item.get("ref") else None
                line, raw = _line_of(lines, str(item["project"]))
                includes.append(CiInclude(rel, line, raw, str(item["project"]), ref, bool(ref and SHA.match(ref))))
            elif isinstance(item, dict) and item.get("remote") or isinstance(item, str) and item.startswith("http"):
                url = item["remote"] if isinstance(item, dict) else item
                line, raw = _line_of(lines, url)
                includes.append(CiInclude(rel, line, raw, url, None, False))  # a URL's content can change any time
    return images, includes
