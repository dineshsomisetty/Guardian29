import json
from pathlib import Path

from guardian.tools.detectors.similarity import (
    check_name,
    damerau_levenshtein,
    load_popular,
    scan_names,
)

FX = Path(__file__).resolve().parents[1] / "fixtures" / "juice-shop"


def test_ngy_cookie_flagged():
    h = check_name("ngy-cookie")
    assert h and h.popular == "ngx-cookie" and h.distance == 1


def test_legacy_epilogue_js_flagged():
    h = check_name("epilogue-js")
    assert h and h.popular == "epilogue" and h.reason == "js_suffix"


def test_popular_names_not_flagged():
    for n in load_popular():
        assert check_name(n) is None, n


def test_required_names_in_list():
    pop = load_popular()
    assert "ngx-cookie" in pop and "epilogue" in pop


def test_swap_and_short_names():
    assert check_name("lodahs").reason == "swapped_chars"
    assert check_name("abc") is None  # below min length


def test_scopes():
    assert check_name("@types/lodash") is None
    assert check_name("@evil/lodash").reason == "scope_confusion"


def test_distance():
    assert damerau_levenshtein("ab", "ba") == 1
    assert damerau_levenshtein("kitten", "sitting") == 3


def test_juice_shop_false_positives_are_only_the_two_typosquats():
    names = set()
    for f in ["package.json", "frontend/package.json", "ftp/package.json.bak"]:
        j = json.loads((FX / f).read_text(encoding="utf-8"))
        for k in ("dependencies", "devDependencies"):
            names |= set(j.get(k, {}))
    assert {h.candidate for h in scan_names(sorted(names))} == {"ngy-cookie", "epilogue-js"}
