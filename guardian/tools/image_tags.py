"""Newer explicit releases of a tag-only base image (D2-07b `update_base_image` evidence). Owner: Dev2.

Called by: tools/detectors/image_pin.py, once per Dockerfile / GitLab CI image that has no digest. The result is
stored in the Evidence facts `newer_tags` (list of tags, newest first) and `source` (see below) and later used by
the remediation agent to pin an explicit release.

`FROM node:24` follows whatever the maintainers push to the moving tag `24`. The safe update keeps the same line
and pins an explicit release: the newest stable tag on that line (`24` -> `24.13.0`, `3.9-alpine` ->
`3.9.25-alpine`), then its digest. Only Docker Hub repositories are looked up (the public tag-list API needs no
credentials); other registries return no candidates.

Network/cache: the Hub tag list is fetched with a G3.5 check_url (extra allowed host hub.docker.com) and cached in
data/cache/intel/image_tags.json (or $GUARDIAN_INTEL_CACHE) keyed `<repo>:<line>`, so offline and replay runs see
the same tags (G7.3, G7.4). Offline with a cache miss, a blocked host or a failed request give [] and a `source`
string explaining why: never an exception. `source` is "cache", "hub.docker.com" or "unavailable/not applicable ...".
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import httpx

from guardian.core.config import REPO_ROOT
from guardian.guardrails.network import NetworkBlocked, check_url

# Hosts the G3.5 network guard must allow for this lookup (the Docker Hub tag-list API).
HUB_HOSTS = frozenset({"hub.docker.com"})
# Tag shapes we know how to advance: a version (1-3 numeric parts) with an optional "-variant" suffix:
# "24", "3.9", "24-alpine", "3.9-slim-bookworm", and full releases "20.19.2-bookworm-slim"
_LINE = re.compile(r"^(\d+(?:\.\d+){0,2})(-[a-z][a-z0-9.-]*)?$")


def _line_of(version: str) -> str:
    """The release line a tag follows: a full x.y.z release moves only within x.y (patch updates)."""
    parts = version.split(".")
    return ".".join(parts[:2]) if len(parts) >= 3 else version


def _cache_path() -> Path:
    """File holding the cached tag lists ({"<repo>:<line>": [tags]})."""
    root = Path(os.environ.get("GUARDIAN_INTEL_CACHE") or REPO_ROOT / "data" / "cache" / "intel")
    return root / "image_tags.json"


def hub_repo(image: str) -> str | None:
    """Docker Hub `namespace/repo` for an image reference, None for other registries."""
    parts = image.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        return None if parts[0] not in ("docker.io", "registry-1.docker.io", "index.docker.io") else \
            "/".join(parts[1:]) if len(parts) > 2 else f"library/{parts[1]}"
    return image if len(parts) > 1 else f"library/{image}"


def _vkey(v: str) -> tuple[int, ...]:
    """Numeric sort key for a dotted version such as 3.9.25 (compared as integers, not strings)."""
    return tuple(int(x) for x in v.split("."))


def pick_newer(tag: str, tags: list[str], limit: int = 2) -> list[str]:
    """Newest explicit releases on the same line as `tag`, keeping its variant suffix, newest first.

    `tags` is the Hub tag list. Returns at most `limit` entries; [] when `tag` is not a version tag. A moving
    tag (24, 3.9) gets only the single newest release because anything older would be a downgrade."""
    m = _LINE.match(tag or "")
    if not m:
        return []
    current, suffix = m.group(1), m.group(2) or ""
    line = _line_of(current)
    # a tag on the same line with at least one more numeric part and the same suffix: 3.9 -> 3.9.25-alpine
    pat = re.compile(rf"^{re.escape(line)}(?:\.\d+)+{re.escape(suffix)}$")
    # strip the suffix to compare plain versions; it is re-attached on return
    found = {t[: len(t) - len(suffix)] if suffix else t for t in tags if pat.match(t)}
    if current.count(".") >= 2:  # already an explicit release: only strictly newer patches are an update
        found = {v for v in found if _vkey(v) > _vkey(current)}
    ranked = sorted(found, key=_vkey, reverse=True)
    # prefer full x.y.z releases over x.y aliases when both exist
    full = [v for v in ranked if v.count(".") >= 2] or ranked
    if current.count(".") < 2:
        # a moving tag (24) already points at its newest release: anything older would be a downgrade
        limit = 1
    return [f"{v}{suffix}" for v in full[:limit]]


def newer_tags(image: str, tag: str, *, offline: bool, ctx=None, transport: httpx.BaseTransport | None = None
               ) -> tuple[list[str], str]:
    """(newer explicit tags, source). Source: "cache", "hub.docker.com", or why nothing was looked up.

    image/tag: as written in the Dockerfile (tag may be empty = implicit latest, which is not a version tag so
    nothing is looked up). offline: use only the cache. ctx: ToolContext for guardrail tracing. transport: httpx
    transport for tests. Side effect: updates the on-disk tag cache after a successful Hub request."""
    repo = hub_repo(image)
    if repo is None or not _LINE.match(tag or ""):
        return [], "not applicable (not a Docker Hub version tag)"
    line = _line_of(_LINE.match(tag).group(1))
    key = f"{repo}:{line}"  # one cache entry per release line, e.g. "library/node:24"
    path = _cache_path()
    try:
        cache = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cache = {}
    if key in cache:
        return pick_newer(tag, cache[key]), "cache"
    if offline:
        return [], "unavailable (offline, cache miss)"
    url = f"https://hub.docker.com/v2/repositories/{repo}/tags"
    try:
        check_url(url, ctx=ctx, extra_hosts=HUB_HOSTS, agent="detection")  # G3.5
        with httpx.Client(transport=transport, timeout=20.0, headers={"User-Agent": "guardian-supply-chain"}) as c:
            # name=<line>. filters server-side to tags starting with the line (e.g. "3.9."); newest-updated first
            r = c.get(url, params={"page_size": 100, "name": f"{line}.", "ordering": "last_updated"})
            r.raise_for_status()
            tags = [t["name"] for t in r.json().get("results", []) if isinstance(t, dict) and t.get("name")]
    except (NetworkBlocked, httpx.HTTPError, ValueError, KeyError):
        return [], "unavailable (lookup failed)"
    cache[key] = sorted(set(tags))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")
    return pick_newer(tag, cache[key]), "hub.docker.com"
