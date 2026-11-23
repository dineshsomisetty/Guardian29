"""G4 grounding tests (D1-02 acceptance): unknown evidence rejected, invented CVE rejected, every claim labelled."""

import pytest

from guardian.core.models import ClaimLabel, Evidence
from guardian.guardrails.grounding import RawAssessment, RawClaim, SchemaError, ground_assessment, parse_batch

EV = Evidence(evidence_id="ev_A", run_id="r", kind="scanner_output", source_tool="grype@0.1",
              facts={"vuln_id": "GHSA-c7qv-q95q-8v27", "aliases": ["CVE-2022-23539"], "fixed_versions": ["9.0.0"],
                     "cvss": 8.1, "purl": "pkg:npm/jsonwebtoken@0.4.0"})
LOOKUP = {"ev_A": EV}


def assess(claims, explanation="jsonwebtoken 0.4.0 is vulnerable (CVE-2022-23539)."):
    return RawAssessment(finding_id="fd_1", initial_risk="high", explanation=explanation, claims=claims)


def test_unknown_evidence_id_rejected():
    g = ground_assessment(assess([RawClaim(text="Fixed in 9.0.0", field="fixed_versions", value="9.0.0",
                                           evidence_ids=["ev_NOPE"])]), [EV], LOOKUP)
    assert g.claims == []
    assert g.rejected and g.rejected[0][1].rule == "G4.2"


def test_invented_cve_rejected():
    g = ground_assessment(assess([RawClaim(text="Also affected by CVE-2099-0001", evidence_ids=["ev_A"])]), [EV], LOOKUP)
    assert g.claims == []
    assert g.rejected[0][1].rule == "G4.4"


def test_invented_cve_in_explanation_removed():
    g = ground_assessment(assess([], explanation="See CVE-2099-12345."), [EV], LOOKUP)
    assert g.explanation is None
    assert any(i.rule == "G4.4" for i in g.issues)


def test_every_claim_labelled_verified_or_inferred():
    g = ground_assessment(assess([
        RawClaim(text="A fix is available in 9.0.0", field="fixed_versions", value="9.0.0", evidence_ids=["ev_A"]),
        RawClaim(text="CVSS is 8.1", field="cvss", value="8.1", evidence_ids=["ev_A"]),
        RawClaim(text="Likely reachable from the login route", evidence_ids=["ev_A"]),
        RawClaim(text="Fixed in 9.0.0", field="fixed_versions", value="9.9.9", evidence_ids=["ev_A"]),
    ]), [EV], LOOKUP)
    labels = [c.label for c in g.claims]
    assert labels == [ClaimLabel.VERIFIED, ClaimLabel.VERIFIED, ClaimLabel.INFERRED, ClaimLabel.INFERRED]
    assert all(c.label in ClaimLabel for c in g.claims)


def test_claim_without_evidence_is_unsupported_and_removed():
    g = ground_assessment(assess([RawClaim(text="This package is abandoned")]), [EV], LOOKUP)
    assert g.claims == [] and g.rejected[0][1].rule == "G4.6"


def test_stray_version_downgrades_to_inferred():
    g = ground_assessment(assess([RawClaim(text="Upgrade to 10.1.0 which is fixed", field="fixed_versions",
                                           value="9.0.0", evidence_ids=["ev_A"])]), [EV], LOOKUP)
    assert g.claims[0].label is ClaimLabel.INFERRED


def test_ids_from_finding_fields_are_not_invented():
    g = ground_assessment(assess([], explanation="Affects GHSA-c7qv-q95q-8v27 and CVE-2022-23539."), [EV], LOOKUP,
                          finding_facts={"vuln_id": "GHSA-c7qv-q95q-8v27"})
    assert g.explanation is not None


def test_schema_parse_errors():
    with pytest.raises(SchemaError):
        parse_batch("not json")
    with pytest.raises(SchemaError):
        parse_batch('{"assessments": [{"finding_id": "x", "initial_risk": "severe", "explanation": "", "claims": []}]}')
