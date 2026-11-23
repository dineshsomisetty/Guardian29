from guardian.tools.sbom_diff import has_version, sbom_diff


def bom(*purls):
    return {"components": [{"type": "library", "purl": p} for p in purls]}


BEFORE = bom("pkg:npm/jsonwebtoken@0.4.0", "pkg:npm/jsonwebtoken@0.1.0", "pkg:npm/express@4.21.2",
             "pkg:npm/ngy-cookie@6.0.1000", "pkg:deb/debian/libc6@2.41-12?arch=amd64")
AFTER = bom("pkg:npm/jsonwebtoken@9.0.2", "pkg:npm/jsonwebtoken@0.1.0", "pkg:npm/express@4.21.2",
            "pkg:npm/jws@4.0.0", "pkg:deb/debian/libc6@2.41-12?arch=amd64")


def test_added_removed_changed():
    d = sbom_diff(BEFORE, AFTER)
    assert d["added"] == ["pkg:npm/jws@4.0.0"]
    assert d["removed"] == ["pkg:npm/ngy-cookie@6.0.1000"]
    assert d["changed"] == [{"package": "pkg:npm/jsonwebtoken", "from": ["0.4.0"], "to": ["9.0.2"],
                             "unchanged": ["0.1.0"]}]
    assert d["before_components"] == 5 and d["after_components"] == 5 and d["summary"] == "+1 -1 ~1"


def test_identical_and_has_version():
    assert sbom_diff(BEFORE, BEFORE)["summary"] == "+0 -0 ~0"
    assert has_version(AFTER, "pkg:npm/jsonwebtoken@0.1.0") and not has_version(AFTER, "pkg:npm/jsonwebtoken@0.4.0")
    assert has_version(AFTER, "pkg:deb/debian/libc6@2.41-12")
