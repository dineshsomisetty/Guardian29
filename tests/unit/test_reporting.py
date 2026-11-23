import json

from guardian.reporting.build import build_report
from guardian.reporting.render import write_reports
from guardian.reporting.schema import Report


def make_run(tmp_path, full=True):
    run = tmp_path / "run_1"
    (run / "evidence").mkdir(parents=True)
    (run / "findings.json").write_text(json.dumps([
        {"finding_id": "fd_1", "category": "cve", "title": "jsonwebtoken <8.5.1 <script>x</script>", "component_purl": "pkg:npm/jsonwebtoken@0.4.0",
         "vuln_id": "GHSA-8cf7-32gw-wr33", "cvss": 7.6, "scope": "prod", "initial_risk": "high",
         "fixed_versions": ["9.0.0"], "dependency_paths": [["root", "jsonwebtoken"]], "evidence_ids": ["ev_1"]},
        {"finding_id": "fd_2", "category": "unpinned_ci", "title": "coveralls unpinned", "initial_risk": "medium", "evidence_ids": ["ev_2"]},
    ]))
    (run / "evidence" / "ev_1.json").write_text(json.dumps({"evidence_id": "ev_1", "tool": "grype"}))
    (run / "graph.json").write_text(json.dumps({"nodes": [{"id": "a", "direct": True, "ecosystem": "npm"},
                                                          {"id": "b", "direct": False, "ecosystem": "npm"}], "edges": [], "roots": ["root"]}))
    if full:
        (run / "scores.json").write_text(json.dumps([{"finding_id": "fd_1", "score": 80.5, "priority": "critical", "confidence": "high",
                                                      "factors": [{"name": "S", "raw": "CVSS 7.6", "weight": 0.3, "contribution": 22.8}]}]))
        (run / "actions.json").write_text(json.dumps([{"finding_id": "fd_1", "action": "set_dependency_version", "target_version": "9.0.0"}]))
        (run / "approvals.json").write_text(json.dumps([{"finding_id": "fd_1", "decision": "approve", "by": "dev", "at": "t"}]))
        (run / "validations.json").write_text(json.dumps([{"finding_id": "fd_1", "verdict": "verified", "risk_before": 80.5, "risk_after": 0,
                                                           "final_confidence": "high"}]))
        (run / "claims.json").write_text(json.dumps({"fd_1": [{"text": "fixed in 9.0.0", "label": "VERIFIED", "evidence_ids": ["ev_1"]}]}))
        (run / "audit.jsonl").write_text(json.dumps({"event": "approve"}) + "\n")
    return run


def test_report_full_and_schema_roundtrip(tmp_path):
    rep = build_report(make_run(tmp_path))
    Report.model_validate_json(rep.model_dump_json())
    assert rep.inventory.component_count == 2 and rep.inventory.transitive_count == 1
    assert rep.summary["verified"] == 1 and [r["finding_id"] for r in rep.remaining_risk] == ["fd_2"]
    assert rep.findings[0].evidence[0]["tool"] == "grype" and rep.actions[0].approval["by"] == "dev"
    assert rep.inventory.vulnerable_paths[0]["paths"] == [["root", "jsonwebtoken"]]


def test_report_day1_only_and_html_escapes(tmp_path):
    run = make_run(tmp_path, full=False)
    j, h = write_reports(run, target="juice-shop")
    assert Report.model_validate_json(j.read_text()).summary["findings_total"] == 2
    html = h.read_text()
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert "No scores recorded" in html and "Known limitations" in html


def test_missing_findings_raises(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        build_report(tmp_path)
