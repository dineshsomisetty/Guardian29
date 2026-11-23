"""D4-01 name similarity for typosquat detection. Owner: Dev4.

A name is a suspect when it is NOT itself popular and is close to a popular name:
  - Damerau-Levenshtein distance 1 (names >= 5 chars) or 2 (names >= 10 chars), incl. swapped neighbours
  - popular name + "-js" / "js" / ".js" suffix, or "node-" prefix (e.g. epilogue-js -> epilogue)
Scoped names are compared on the part after the scope as well.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from guardian.core.config import REPO_ROOT

LIST = REPO_ROOT / "data" / "popular_packages" / "npm.txt"
MIN_LEN = 5
AFFIXES = ("-js", "js", ".js", "-node", "-npm")


@dataclass(frozen=True)
class Match:
    name: str
    popular: str
    distance: int
    reason: str


@lru_cache(maxsize=1)
def popular(path: Path = LIST) -> frozenset[str]:
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line.lower())
    return frozenset(names)


def damerau_levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Optimal string alignment distance; early exit above `cap`."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


def _bare(name: str) -> str:
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def check_name(name: str, pop: frozenset[str] | None = None) -> Match | None:
    pop = pop if pop is not None else popular()
    n = name.lower()
    if n in pop or len(_bare(n)) < MIN_LEN:
        return None
    for affix in AFFIXES:
        if n.endswith(affix) and n[: -len(affix)] in pop:
            return Match(name, n[: -len(affix)], len(affix), f"popular name + '{affix}' suffix")
    if n.startswith("node-") and n[5:] in pop:
        return Match(name, n[5:], 5, "popular name + 'node-' prefix")
    limit = 2 if len(n) >= 10 else 1
    best: Match | None = None
    for p in pop:
        if p.startswith("@") != n.startswith("@") or abs(len(p) - len(n)) > limit:
            continue
        d = damerau_levenshtein(n, p, cap=limit)
        if d <= limit and (best is None or d < best.distance):
            best = Match(name, p, d, f"edit distance {d} from popular '{p}'")
    return best
