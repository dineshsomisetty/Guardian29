"""D4-12 Dockerfile adapter: FROM images with tag/digest and line, EXPOSE ports. Owner: Dev4."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
EXPOSE = re.compile(r"^\s*EXPOSE\s+(.+)$", re.I)


@dataclass
class BaseImage:
    file: str
    line: int
    raw: str
    image: str
    tag: str | None
    digest: str | None
    stage: str | None


def dockerfiles(root: Path) -> list[Path]:
    return sorted(p for p in root.glob("**/Dockerfile*") if "node_modules" not in p.parts and p.is_file())[:10]


def parse(root: Path) -> tuple[list[BaseImage], list[str]]:
    images, ports, stages = [], [], set()
    for df in dockerfiles(root):
        rel = df.relative_to(root).as_posix()
        for i, line in enumerate(df.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if m := FROM.match(line):
                ref, stage = m.group(1), m.group(2)
                if ref.lower() in stages or ref.lower() == "scratch":
                    continue  # FROM <earlier stage>
                if stage:
                    stages.add(stage.lower())
                name, _, digest = ref.partition("@")
                last = name.rsplit("/", 1)[-1]
                tag = last.split(":", 1)[1] if ":" in last else None
                image = name[: len(name) - len(tag) - 1] if tag else name
                images.append(BaseImage(rel, i, line.strip(), image, tag, digest or None, stage))
            elif m := EXPOSE.match(line):
                ports.extend(m.group(1).split())
    return images, ports
