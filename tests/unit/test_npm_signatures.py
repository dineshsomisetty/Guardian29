"""Stretch goal 3: npm registry signatures + Sigstore attestations feed provenance (and the section 7 modifier)."""

from types import SimpleNamespace

from guardian.tools import risk_tools, sandbox

NPM_TEXT = """audited 1235 packages in 4s

1201 packages have verified registry signatures

87 packages have verified attestations

1 package has an invalid registry signature:

evil-pkg@1.0.0 (https://registry.npmjs.org/)
"""
NPM_JSON = {"invalid": [{"name": "evil-pkg", "version": "1.0.0"}], "missing": [{"name": "old-pkg", "version": "0.1.0"}]}


def test_parse_signatures_counts_and_failures():
    got = sandbox.parse_signatures(NPM_TEXT, NPM_JSON)
    assert got == {"packages_audited": 1235, "verified_signatures": 1201, "verified_attestations": 87,
                   "invalid": ["evil-pkg@1.0.0"], "missing": ["old-pkg@0.1.0"]}


def test_signature_audit_is_skipped_without_sandbox(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text("{}")
    monkeypatch.setenv("GUARDIAN_SANDBOX", "off")
    assert sandbox.signature_audit(tmp_path) == (None, "GUARDIAN_SANDBOX=off")


def test_invalid_signature_fails_provenance_and_valid_one_verifies():
    ctx = SimpleNamespace(artifacts={"npm_signatures": sandbox.parse_signatures(NPM_TEXT, NPM_JSON)})
    assert risk_tools._audit_for(ctx, "pkg:npm/evil-pkg@1.0.0") == {"signature_verified": False}
    assert risk_tools._audit_for(ctx, "pkg:npm/old-pkg@0.1.0") == {"signature_verified": None}
    assert risk_tools._audit_for(ctx, "pkg:npm/express@4.21.2") == {"signature_verified": True}
    from guardian.tools.provenance import provenance_for

    failed = provenance_for({"repository": "x"}, {"signature_verified": False})
    assert failed["status"] == "failed" and failed["score_modifier"] is True  # section 7: +5 points
    assert provenance_for({"repository": "x"}, {"signature_verified": True})["status"] == "verified"
