from pathlib import Path

from guardian.tools.changes import compute_changes

FX = Path(__file__).resolve().parents[1] / "fixtures" / "juice-shop"


def test_bak_vs_current():
    doc = compute_changes(FX / "ftp/package.json.bak", FX / "package.json")
    assert any("epilogue-js" in p for p in doc["removed"])
    assert any(c["name"] == "express" and c["major_jump"] is False for c in doc["changed"])
    assert any(c["major_jump"] for c in doc["changed"])
    assert doc["added"] and "project:postinstall" not in doc["install_scripts_added"]  # bak already had postinstall


def test_lockfile_integrity_and_scripts(tmp_path):
    import json
    m = {"name": "x", "dependencies": {"a": "1.0.0"}}
    (tmp_path / "b.json").write_text(json.dumps(m)); (tmp_path / "h.json").write_text(json.dumps(m))
    lock = lambda integ, scr: {"packages": {"": {}, "node_modules/a": {"version": "1.0.0", "integrity": integ, "hasInstallScript": scr}}}
    (tmp_path / "bl.json").write_text(json.dumps(lock("sha512-A", False)))
    (tmp_path / "hl.json").write_text(json.dumps(lock("sha512-B", True)))
    doc = compute_changes(tmp_path / "b.json", tmp_path / "h.json", tmp_path / "bl.json", tmp_path / "hl.json",
                          add_evidence=lambda f: "ev_1")
    assert doc["integrity_changed"][0]["purl"] == "pkg:npm/a@1.0.0"
    assert doc["install_scripts_added"] == ["pkg:npm/a@1.0.0"] and doc["evidence_ids"] == ["ev_1"]
