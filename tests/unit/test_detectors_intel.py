from datetime import UTC, datetime

from guardian.tools.detectors.outdated import detect_outdated
from guardian.tools.package_risk import (
    dependency_confusion,
    package_risks,
    release_activity,
)
from guardian.tools.provenance import provenance_for
from guardian.tools.reachability import reachability_import

NOW = datetime(2026, 11, 23, tzinfo=UTC)


class FakeIntel:
    def __init__(self, metas):
        self.metas = metas

    def registry_metadata(self, purl):
        name = purl.split("/", 1)[1].rsplit("@", 1)[0].replace("%40", "@")
        return self.metas.get(name)


def test_outdated_rules():
    intel = FakeIntel({
        "old": {"latest": "1.0.0", "time": {"1.0.0": "2020-01-01T00:00:00Z"}, "deprecated_versions": {}},
        "dep": {"latest": "2.0.0", "time": {"2.0.0": "2026-06-01T00:00:00Z"}, "deprecated_versions": {"1.0.0": "use 2"}},
        "far": {"latest": "9.0.0", "time": {"9.0.0": "2026-06-01T00:00:00Z"}, "deprecated_versions": {}},
        "fine": {"latest": "1.2.0", "time": {"1.2.0": "2026-06-01T00:00:00Z"}, "deprecated_versions": {}},
    })
    comps = [{"purl": f"pkg:npm/{n}@{v}"} for n, v in [("old", "1.0.0"), ("dep", "1.0.0"), ("far", "5.1.0"), ("fine", "1.2.0"),
                                                       ("missing", "1.0.0")]]
    out = {f["component_purl"].split("/")[1].split("@")[0]: f for f in detect_outdated(comps, intel, now=NOW)}
    assert set(out) == {"old", "dep", "far"}
    assert out["old"]["facts"]["reasons"][0]["rule"] == "unmaintained"
    assert out["dep"]["facts"]["reasons"][0]["rule"] == "deprecated"
    assert out["far"]["facts"]["reasons"][0]["majors_behind"] == 4


def test_reachability(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "login.ts").write_text("import x from 'y'\nconst jwt = require('jsonwebtoken')\n")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "a.test.ts").write_text("import 'sanitize-html'\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "z.js").write_text("require('express-jwt')")
    r = reachability_import(tmp_path, "jsonwebtoken")
    assert r.tier == "imported" and r.hits[0]["file"] == "routes/login.ts" and r.hits[0]["line"] == 2
    assert reachability_import(tmp_path, "sanitize-html").tier == "not_imported"  # only in tests
    assert reachability_import(tmp_path, "sanitize-html", include_tests=True).tier == "imported"
    assert reachability_import(tmp_path, "express-jwt").tier == "not_imported"  # node_modules skipped
    assert reachability_import(tmp_path / "routes" / "nope", "x").tier == "unknown"


def test_reachability_python(tmp_path):
    (tmp_path / "app.py").write_text("import yaml\nfrom flask_cors import CORS\n")
    assert reachability_import(tmp_path, "flask-cors", "pypi").tier == "imported"
    assert reachability_import(tmp_path, "django", "pypi").tier == "not_imported"


def test_provenance():
    meta = {"repository": None, "latest_maintainers": [{"name": "eve"}], "previous_maintainers": [{"name": "bob"}]}
    p = provenance_for(meta)
    assert p["score_modifier"] and p["provenance_gap"] and p["status"] == "unknown"
    ok = provenance_for({"repository": {"url": "git+https://x"}, "latest_maintainers": [{"name": "a"}],
                         "previous_maintainers": [{"name": "a"}]}, {"signature_verified": True})
    assert ok["status"] == "verified" and not ok["score_modifier"] and not ok["provenance_gap"]
    assert provenance_for({"repository": {"url": "u"}}, {"signature_verified": False})["score_modifier"]


def test_package_risk_rules():
    burst = {"name": "p", "time": {f"1.0.{i}": f"2026-11-0{i + 1}T00:00:00Z" for i in range(6)},
             "latest_maintainers": [{"name": "a"}], "previous_maintainers": [{"name": "b"}]}
    kinds = [f["title"] for f in package_risks("pkg:npm/p@1", burst, now=NOW)]
    assert any("maintainer" in t for t in kinds) and any("release activity" in t for t in kinds)
    assert release_activity({"time": {"1.0.0": "2026-11-22T00:00:00Z"}}, now=NOW)[0]["rule"] == "very_recent_release"
    assert package_risks("pkg:npm/p@1", None) == []


def test_dependency_confusion():
    intel = FakeIntel({"@acme/internal-lib": {"latest": "99.0.0", "maintainers": [{"name": "attacker"}]}})
    f = dependency_confusion(["@acme/internal-lib", "@acme/private-only", "lodash"], ["@acme"], intel)
    assert [x["component_purl"] for x in f] == ["pkg:npm/%40acme/internal-lib"]
