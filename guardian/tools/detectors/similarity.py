# Document the contract for the surrounding module or callable.
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

# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Import dataclass from dataclasses.
from dataclasses import dataclass
# Import lru_cache from functools.
from functools import lru_cache
# Import Path from pathlib.
from pathlib import Path

# Import REPO_ROOT from guardian.core.config.
from guardian.core.config import REPO_ROOT

# Reference list of popular npm package names (the things attackers imitate).
# Store REPO_ROOT / 'data' / 'popular_packages' / 'npm.txt' in LIST.
LIST = REPO_ROOT / "data" / "popular_packages" / "npm.txt"
# Give MIN_LEN its starting value.
# The initial value is 5.
MIN_LEN = 5  # names shorter than this (after removing a scope) are never flagged: too many chance near-matches
# Decorations that make an impostor look official: popular name + one of these suffixes (checked on the full name).
# Store ('-js', 'js', '.js', '-node', '-npm') in AFFIXES.
AFFIXES = ("-js", "js", ".js", "-node", "-npm")


# Apply the dataclass decorator to the declaration below.
@dataclass(frozen=True)
# Define Match for package name comparison.
# Group the related fields or methods under this type.
class Match:
    # Document the contract for the surrounding module or callable.
    """A suspected imitation: `name` resembles the popular package `popular`, `distance` is the edit distance
    (or the affix length for affix matches), `reason` is the human-readable explanation shown in the finding."""

    # Declare name with type str.
    # The caller or container supplies the value.
    name: str
    # Declare popular with type str.
    # The caller or container supplies the value.
    popular: str
    # Declare distance with type int.
    # The caller or container supplies the value.
    distance: int
    # Declare reason with type str.
    # The caller or container supplies the value.
    reason: str


# Apply the lru_cache decorator to the declaration below.
@lru_cache(maxsize=1)
# Define popular for package name comparison.
# Inputs include path.
def popular(path: Path = LIST) -> frozenset[str]:
    # Document the contract for the surrounding module or callable.
    """Load the popular-package names (lowercased, comments and blanks skipped); cached after the first call."""
    # Store an ordered collection in names.
    names = []
    # Iterate over path.read_text(encoding='utf-8').splitlines().
    # Bind each item to line before processing it.
    for line in path.read_text(encoding="utf-8").splitlines():
        # Store the result of line.strip in line.
        line = line.strip()
        # Check whether line and (not line.startswith('#')).
        if line and not line.startswith("#"):
            # Call names.append at this point.
            names.append(line.lower())
    # Return the result of frozenset to the caller.
    return frozenset(names)


# Measure edits between prefixes, including adjacent transpositions.
# Inputs include a, b, cap.
def damerau_levenshtein(a: str, b: str, cap: int = 3) -> int:
    # Document the contract for the surrounding module or callable.
    """Optimal string alignment distance (edit distance where swapping two adjacent characters costs 1).

    Returns cap + 1 as soon as the result is known to exceed `cap`, which keeps comparing against thousands of
    popular names cheap: callers only care whether the distance is within their small limit."""
    # Check whether abs(len(a) - len(b)) > cap.
    if abs(len(a) - len(b)) > cap:  # length difference alone already exceeds the cap
        # Return cap + 1 to the caller.
        return cap + 1
    # DP rows: prev = previous row, prev2 = the row before that (needed for the adjacent-swap case)
    # Declare prev2 with type list[int] | None.
    # Use None to represent an absent value as its initial value.
    prev2: list[int] | None = None
    # Store the result of list in prev.
    prev = list(range(len(b) + 1))
    # Iterate over range(1, len(a) + 1).
    # Bind each item to i before processing it.
    for i in range(1, len(a) + 1):
        # Store [i] + [0] * len(b) in cur.
        cur = [i] + [0] * len(b)
        # Iterate over range(1, len(b) + 1).
        # Bind each item to j before processing it.
        for j in range(1, len(b) + 1):
            # Store 0 if a[i - 1] == b[j - 1] else 1 in cost.
            cost = 0 if a[i - 1] == b[j - 1] else 1
            # Store the result of min in cur[j].
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            # transposition ("lodsah" vs "lodash"): swapped neighbours cost one edit, not two
            # Check whether the expression on this line.
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                # Store the result of min in cur[j].
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        # Check whether min(cur) > cap.
        if min(cur) > cap:  # every cell already above the cap: the final distance cannot come back down
            # Return cap + 1 to the caller.
            return cap + 1
        # Store (prev, cur) in (prev2, prev).
        prev2, prev = prev, cur
    # Return prev[-1] to the caller.
    return prev[-1]


# Define _bare for package name comparison.
# Inputs include name.
def _bare(name: str) -> str:
    # Document the contract for the surrounding module or callable.
    """The package name without its @scope/ prefix."""
    # Return the expression on this line to the caller.
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


# Compare a package name with the configured popular-package list.
# Inputs include name, pop.
def check_name(name: str, pop: frozenset[str] | None = None) -> Match | None:
    # Document the contract for the surrounding module or callable.
    """Return the closest popular package `name` imitates, or None if it looks fine.

    `pop` overrides the popular set (tests). A name that is itself popular, or whose bare part is shorter than
    MIN_LEN, is never a suspect. Checks run in order: popular + affix, "node-" + popular, then edit distance
    (<= 1, or <= 2 for names of 10+ characters) among popular names with the same scoped/unscoped shape."""
    # Store pop if pop is not None else popular() in pop.
    pop = pop if pop is not None else popular()
    # Store the result of name.lower in n.
    n = name.lower()
    # Check whether n in pop or len(_bare(n)) < MIN_LEN.
    if n in pop or len(_bare(n)) < MIN_LEN:
        # Return None to represent an absent value to the caller.
        return None
    # Iterate over AFFIXES.
    # Bind each item to affix before processing it.
    for affix in AFFIXES:
        # Check whether n.endswith(affix) and n[:-len(affix)] in pop.
        if n.endswith(affix) and n[: -len(affix)] in pop:
            # Return the result of Match to the caller.
            return Match(name, n[: -len(affix)], len(affix), f"popular name + '{affix}' suffix")
    # Check whether n.startswith('node-') and n[5:] in pop.
    if n.startswith("node-") and n[5:] in pop:
        # Return the result of Match to the caller.
        return Match(name, n[5:], 5, "popular name + 'node-' prefix")
    # Store 2 if len(n) >= 10 else 1 in limit.
    limit = 2 if len(n) >= 10 else 1  # longer names tolerate one more typo before they stop looking alike
    # Declare best with type Match | None.
    # Use None to represent an absent value as its initial value.
    best: Match | None = None
    # Iterate over pop.
    # Bind each item to p before processing it.
    for p in pop:
        # a scoped name is only compared with scoped ones, and vice versa; the length gate skips hopeless pairs fast
        # Check whether the expression on this line.
        if p.startswith("@") != n.startswith("@") or abs(len(p) - len(n)) > limit:
            # Skip the remaining work for this item.
            continue
        # Store the result of damerau_levenshtein in d.
        d = damerau_levenshtein(n, p, cap=limit)
        # Check whether d <= limit and (best is None or d < best.distance).
        if d <= limit and (best is None or d < best.distance):
            # Store the result of Match in best.
            best = Match(name, p, d, f"edit distance {d} from popular '{p}'")
    # Return best to the caller.
    return best
