"""Typosquat similarity against a list of popular package names (D4-01).

Pure functions, no network. A candidate is flagged when it is NOT itself a popular
package but is very close to one (edit distance, swapped characters, `-js` suffix).
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT_LIST = Path(__file__).resolve().parents[3] / "data" / "popular_packages" / "npm.txt"
MIN_NAME_LEN = 5
SUFFIXES = ("-js", ".js", "js")
# Scopes owned by well-known publishers; `@types/lodash` is not scope confusion.
TRUSTED_SCOPES = frozenset(
    {"@types", "@angular", "@babel", "@nestjs", "@testing-library", "@typescript-eslint",
     "@eslint", "@jest", "@vue", "@sentry", "@aws-sdk", "@google-cloud", "@mui", "@emotion"}
)


@dataclass(frozen=True)
class SimilarityHit:
    candidate: str
    popular: str
    distance: int
    reason: str  # "edit_distance" | "swapped_chars" | "js_suffix" | "scope_confusion"


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (insert, delete, substitute, adjacent swap)."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def load_popular(path: Path | str | None = None) -> list[str]:
    p = Path(path) if path else DEFAULT_LIST
    names: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line.lower())
    return names


@lru_cache(maxsize=4)
def _popular_set(path: str | None) -> tuple[frozenset[str], tuple[str, ...]]:
    names = load_popular(path)
    return frozenset(names), tuple(names)


def _max_distance(name: str) -> int:
    # Short names have many legitimate neighbours, so stay strict there.
    return 1 if len(name) < 9 else 2


def check_name(
    name: str, popular_path: Path | str | None = None
) -> SimilarityHit | None:
    """Return the closest popular package this name looks like, else None."""
    cand = name.strip().lower()
    pop_set, pop_list = _popular_set(str(popular_path) if popular_path else None)
    if cand in pop_set or len(cand) < MIN_NAME_LEN:
        return None

    # `epilogue-js` vs `epilogue`: popular name plus a js-style suffix.
    for suf in SUFFIXES:
        if cand.endswith(suf) and cand[: -len(suf)] in pop_set and len(cand) - len(suf) >= MIN_NAME_LEN:
            return SimilarityHit(name, cand[: -len(suf)], len(suf), "js_suffix")

    # `@evil/lodash` mimicking an unscoped popular name.
    if cand.startswith("@") and "/" in cand:
        scope, bare = cand.split("/", 1)
        if scope not in TRUSTED_SCOPES and bare in pop_set and len(bare) >= MIN_NAME_LEN:
            return SimilarityHit(name, bare, 1, "scope_confusion")
        return None

    best: SimilarityHit | None = None
    for pop in pop_list:
        if len(pop) < MIN_NAME_LEN or abs(len(pop) - len(cand)) > 2:
            continue
        dist = damerau_levenshtein(cand, pop)
        if dist == 0 or dist > _max_distance(min(cand, pop, key=len)):
            continue
        reason = "swapped_chars" if dist == 1 and sorted(cand) == sorted(pop) else "edit_distance"
        if best is None or dist < best.distance:
            best = SimilarityHit(name, pop, dist, reason)
            if dist == 1:
                break
    return best


def scan_names(
    names: list[str], popular_path: Path | str | None = None
) -> list[SimilarityHit]:
    hits = []
    for n in names:
        h = check_name(n, popular_path)
        if h:
            hits.append(h)
    return hits
