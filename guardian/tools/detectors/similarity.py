"""D4-01 name similarity for typosquat detection. Owner: Dev4.

Called by: detectors/typosquat.py (every direct dependency name) and tools/policy.py (typosquat_package rule).
A pure library: no network, no findings of its own; it returns a `Match` or None.
A name is a suspect when it is NOT itself popular and is close to a popular name:
  - Damerau-Levenshtein distance 1 (names >= 5 chars) or 2 (names >= 10 chars), incl. swapped neighbours
  - popular name + "-js" / "js" / ".js" suffix, or "node-" prefix (e.g. epilogue-js -> epilogue)
Scoped names are compared on the part after the scope as well.
Why these limits: typosquats are one or two keystrokes away from a popular name. Short names are skipped (MIN_LEN)
and the allowed distance grows with length, because short names are all close to each other by chance and would
bury real findings in noise. The reference set is data/popular_packages/npm.txt (one lowercase name per line,
`#` comments); edit that file to tune what counts as "popular".
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from guardian.core.config import REPO_ROOT

# Reference list of popular npm package names (the things attackers imitate).
LIST = REPO_ROOT / "data" / "popular_packages" / "npm.txt"
MIN_LEN = 5  # names shorter than this (after removing a scope) are never flagged: too many chance near-matches
# Decorations that make an impostor look official: popular name + one of these suffixes (checked on the full name).
AFFIXES = ("-js", "js", ".js", "-node", "-npm")


@dataclass(frozen=True)
class Match:
    """A suspected imitation: `name` resembles the popular package `popular`, `distance` is the edit distance
    (or the affix length for affix matches), `reason` is the human-readable explanation shown in the finding."""

    name: str
    popular: str
    distance: int
    reason: str


@lru_cache(maxsize=1)
def popular(path: Path = LIST) -> frozenset[str]:
    """Load the popular-package names (lowercased, comments and blanks skipped); cached after the first call."""
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line.lower())
    return frozenset(names)


def damerau_levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Optimal string alignment distance (edit distance where swapping two adjacent characters costs 1).

    Returns cap + 1 as soon as the result is known to exceed `cap`, which keeps comparing against thousands of
    popular names cheap: callers only care whether the distance is within their small limit."""
    if abs(len(a) - len(b)) > cap:  # length difference alone already exceeds the cap
        return cap + 1
    # DP rows: prev = previous row, prev2 = the row before that (needed for the adjacent-swap case)
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            # transposition ("lodsah" vs "lodash"): swapped neighbours cost one edit, not two
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:  # every cell already above the cap: the final distance cannot come back down
            return cap + 1
        prev2, prev = prev, cur
    return prev[-1]


def _bare(name: str) -> str:
    """The package name without its @scope/ prefix."""
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def check_name(name: str, pop: frozenset[str] | None = None) -> Match | None:
    """Return the closest popular package `name` imitates, or None if it looks fine.

    `pop` overrides the popular set (tests). A name that is itself popular, or whose bare part is shorter than
    MIN_LEN, is never a suspect. Checks run in order: popular + affix, "node-" + popular, then edit distance
    (<= 1, or <= 2 for names of 10+ characters) among popular names with the same scoped/unscoped shape."""
    pop = pop if pop is not None else popular()
    n = name.lower()
    if n in pop or len(_bare(n)) < MIN_LEN:
        return None
    for affix in AFFIXES:
        if n.endswith(affix) and n[: -len(affix)] in pop:
            return Match(name, n[: -len(affix)], len(affix), f"popular name + '{affix}' suffix")
    if n.startswith("node-") and n[5:] in pop:
        return Match(name, n[5:], 5, "popular name + 'node-' prefix")
    limit = 2 if len(n) >= 10 else 1  # longer names tolerate one more typo before they stop looking alike
    best: Match | None = None
    for p in pop:
        # a scoped name is only compared with scoped ones, and vice versa; the length gate skips hopeless pairs fast
        if p.startswith("@") != n.startswith("@") or abs(len(p) - len(n)) > limit:
            continue
        d = damerau_levenshtein(n, p, cap=limit)
        if d <= limit and (best is None or d < best.distance):
            best = Match(name, p, d, f"edit distance {d} from popular '{p}'")
    return best
