import pytest

from guardian.core.scoring import (
    Confidence,
    Priority,
    RiskFactors,
    band,
    compute,
    initial_risk,
)


@pytest.mark.parametrize("cvss,exp", [(9.8, Priority.CRITICAL), (9.0, Priority.CRITICAL), (7.5, Priority.HIGH),
                                      (4.0, Priority.MEDIUM), (3.9, Priority.LOW)])
def test_initial_risk_cvss_bands(cvss, exp):
    assert initial_risk("cve", cvss=cvss) == exp


def test_initial_risk_categories_and_fallbacks():
    assert initial_risk("typosquat") == Priority.HIGH
    assert initial_risk("outdated") == Priority.LOW
    assert initial_risk("cve", severity="High") == Priority.HIGH
    assert initial_risk("cve") == Priority.MEDIUM
    assert initial_risk("something_new") == Priority.MEDIUM


def test_bands():
    assert [band(x) for x in (80, 79.9, 60, 59.9, 40, 39.9)] == [
        Priority.CRITICAL, Priority.HIGH, Priority.HIGH, Priority.MEDIUM, Priority.MEDIUM, Priority.LOW]


def test_known_cve_score_and_recompute():
    r = compute(RiskFactors(cvss=9.0, epss_percentile=0.9, reachability="called", scope="prod", exposure="network"))
    # 30*.9 + 25*.9 + 20*1 + 15*1 + 10*1 = 27+22.5+20+15+10
    assert r.score == 94.5 and r.priority == Priority.CRITICAL and r.confidence == Confidence.HIGH
    assert round(sum(x.contribution for x in r.rows), 2) == r.score


def test_kev_override_to_high():
    r = compute(RiskFactors(cvss=0.0, on_kev=True, reachability="imported", scope="prod"))
    assert r.override_applied and r.priority == Priority.HIGH
    r2 = compute(RiskFactors(cvss=2.0, on_kev=True, reachability="not_imported", scope="prod"))
    assert not r2.override_applied


def test_dev_scope_lowers_score():
    prod = compute(RiskFactors(cvss=7.0, epss_percentile=0.5, reachability="imported", scope="prod"))
    dev = compute(RiskFactors(cvss=7.0, epss_percentile=0.5, reachability="imported", scope="dev"))
    assert dev.score < prod.score


def test_confidence_drops_per_unknown_not_for_x():
    r = compute(RiskFactors(cvss=7.0, epss_percentile=0.5, reachability="called", scope="prod", exposure="unknown"))
    assert r.confidence == Confidence.HIGH
    r = compute(RiskFactors(cvss=None, epss_percentile=None, reachability="unknown", scope="unknown"))
    assert r.confidence == Confidence.LOW and set(r.unknown_factors) == {"S", "E", "R", "P"}
    r = compute(RiskFactors(cvss=7.0, epss_percentile=0.5, reachability="unknown", scope="prod"))
    assert r.confidence == Confidence.MEDIUM


def test_not_applicable_moves_weight_to_severity():
    r = compute(RiskFactors(category="unpinned_ci", reachability="not_applicable", scope="prod"))
    weights = {x.name: x.weight for x in r.rows}
    assert weights["R"] == 0 and weights["S"] == 0.5
    assert r.confidence == Confidence.HIGH


def test_non_cve_typosquat_and_provenance_bonus():
    base = compute(RiskFactors(category="typosquat", reachability="imported", scope="prod"))
    bumped = compute(RiskFactors(category="typosquat", reachability="imported", scope="prod", provenance_failed=True))
    assert bumped.score == min(100, base.score + 5) and bumped.provenance_bonus == 5
    assert compute(RiskFactors(category="typosquat", malicious_evidence=True, reachability="called",
                               scope="prod", exposure="network", provenance_failed=True)).score <= 100
