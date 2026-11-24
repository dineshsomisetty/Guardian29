"""D1-11 continuous monitoring and D1-12 batch runs, fully offline (cached OSV/EPSS/KEV fixtures)."""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import httpx
import pytest

from guardian.cli import main
from guardian.core.models import Evidence, Finding, FindingCategory, RiskAssessment, RiskFactors, Scope
from guardian.core.plans import load_risks, save_risks
from guardian.core.scoring import compute, factor
from guardian.core.store import JsonStore
from guardian.tools.threat_intel import IntelClient
from guardian.watch import WatchError, parse_interval, watch_once

LODASH = "pkg:npm/lodash@4.17.20"
EXPRESS = "pkg:npm/express@4.0.0"


def osv_vuln(vid, cve, name="lodash", fixed="4.17.21"):
    return {"id": vid, "aliases": [cve] if cve else [], "summary": f"{vid} summary",
            "database_specific": {"severity": "HIGH"}, "published": "2026-11-20T00:00:00Z",
            "affected": [{"package": {"name": name, "ecosystem": "npm"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def make_run(settings, run_id="run_w"):
    run_dir = settings.runs_dir / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "run_summary.json").write_text(json.dumps({"run_id": run_id, "status": "done"}), encoding="utf-8")
    comps = [{"name": "lodash", "version": "4.17.20", "purl": LODASH}, {"name": "express", "version": "4.0.0", "purl": EXPRESS}]
    (run_dir / "sbom.cdx.json").write_text(json.dumps({"components": comps}), encoding="utf-8")
    (run_dir / "graph.json").write_text(json.dumps({"nodes": [
        {"id": LODASH, "kind": "package", "scope": "prod", "direct": True, "project": "root"},
        {"id": EXPRESS, "kind": "package", "scope": "prod", "direct": True, "project": "root"}]}), encoding="utf-8")
    store = JsonStore(run_dir)
    ev = store.add_evidence(Evidence(run_id=run_id, kind="scanner_output", source_tool="grype@x", facts={"vuln_id": "CVE-2021-23337"}))
    f = store.add_finding(Finding(run_id=run_id, category=FindingCategory.CVE, title="CVE-2021-23337 in lodash@4.17.20",
                                  detector="grype@x", component_purl=LODASH, scope=Scope.PROD, vuln_id="CVE-2021-23337",
                                  aliases=["GHSA-35jh-r3h4-6jhm"], cvss=7.2, evidence_ids=[ev.evidence_id]))
    fx = RiskFactors(S=factor(0.72, "cvss", [ev.evidence_id]), E=factor(0.5, "unknown", [], unknown=True),
                     R=factor(0.6, "imported", ["e1"]), P=factor(1.0, "prod", ["e2"]), X=factor(0.5, "unknown", [], unknown=True))
    c = compute(fx)
    save_risks(run_dir, [RiskAssessment(finding_id=f.finding_id, score=c.score, band=c.band, confidence=c.confidence,
                                        factors=fx, summary="old")])
    # cached "new advisory": OSV now reports a second vulnerability for lodash
    client = IntelClient(offline=True)
    client._store(f"osv:{LODASH}", {"vulns": [osv_vuln("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"),
                                              osv_vuln("GHSA-new1-new1-new1", "CVE-2099-0001")]})
    client._store(f"osv:{EXPRESS}", {})
    return run_dir, f, c.score


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network call in an offline test")

    monkeypatch.setattr(httpx.Client, "request", boom)


def test_watch_adds_new_advisory_and_rescores_without_discovery(settings, monkeypatch):
    run_dir, old_f, old_score = make_run(settings)
    monkeypatch.setattr(IntelClient, "epss_lookup", lambda self, cves: {
        c: {"epss": 0.9, "percentile": 0.97, "date": "2026-11-23"} for c in cves})
    monkeypatch.setattr(IntelClient, "kev_lookup", lambda self, cves: {
        c: ({"dateAdded": "2026-11-22"} if c == "CVE-2021-23337" else None) for c in cves})

    r = watch_once("run_w", settings)

    assert [n["vuln_id"] for n in r["new_findings"]] == ["CVE-2099-0001"]
    store = JsonStore(run_dir)
    new = next(f for f in store.list_findings() if f.detector == "watch:osv")
    assert new.category is FindingCategory.CVE and new.component_purl == LODASH and new.fixed_versions == ["4.17.21"]
    assert store.get_evidence(new.evidence_ids[0]).kind == "osv"
    assert new.initial_risk is not None
    assert len(store.list_findings()) == 2  # the already-known advisory was not duplicated

    esc = {e["finding_id"]: e for e in r["escalated"]}
    assert old_f.finding_id in esc and esc[old_f.finding_id]["after"]["score"] > esc[old_f.finding_id]["before"]["score"]
    risks = load_risks(run_dir)
    assert set(risks) == {old_f.finding_id, new.finding_id}  # priority recomputed and persisted
    assert risks[old_f.finding_id].factors.E.tier == "kev" and risks[old_f.finding_id].score > old_score

    watch_file = json.loads(Path(r["path"]).read_text(encoding="utf-8"))
    assert {"checked_at", "new_findings", "escalated", "unchanged"} <= set(watch_file)
    history = [json.loads(x) for x in (run_dir / "risk.history.jsonl").read_text(encoding="utf-8").splitlines()]
    assert {h["reason"] for h in history} == {"baseline", "new_advisory", "rescored"}
    events = [json.loads(x) for x in (run_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    watch_events = [e for e in events if e["data"].get("watch")]
    assert len(watch_events) == 2 and {e["agent"] for e in watch_events} == {"supervisor"}
    assert {e["type"] for e in watch_events} == {"decision"}
    assert not [e for e in events if e["type"] == "tool_call" and e["data"].get("tool") in ("grype", "sbom")]

    again = watch_once("run_w", settings)  # idempotent: nothing new, nothing moved
    assert again["new_findings"] == [] and again["escalated"] == [] and again["unchanged"] == 2
    assert Path(again["path"]) != Path(r["path"])


def test_watch_requires_a_finished_run_and_parses_intervals(settings):
    run_dir = settings.runs_dir / "run_busy"
    run_dir.mkdir(parents=True)
    (run_dir / "run_summary.json").write_text(json.dumps({"status": "running"}), encoding="utf-8")
    with pytest.raises(WatchError):
        watch_once("run_busy", settings)
    with pytest.raises(WatchError):
        watch_once("nope", settings)
    assert parse_interval("1h") == 3600 and parse_interval("15m") == 900 and parse_interval("30") == 30
    with pytest.raises(ValueError):
        parse_interval("soon")


def test_cli_watch_once(settings, monkeypatch, capsys):
    make_run(settings)
    monkeypatch.setenv("GUARDIAN_RUNS_DIR", str(settings.runs_dir))
    assert main(["watch", "--run", "run_w", "--once"]) == 0
    assert "1 new" in capsys.readouterr().out


def test_batch_runs_each_target_and_writes_summary(settings, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("GUARDIAN_RUNS_DIR", str(settings.runs_dir))
    seen = []

    def fake_run(repo, run_id=None, settings=None, **kw):
        if repo.name == "boom":
            raise RuntimeError("scanner exploded")
        d = settings.runs_dir / f"run_{repo.name}"
        d.mkdir(parents=True)
        seen.append(repo.name)
        (d / "run_summary.json").write_text(json.dumps({
            "status": "done", "sbom": {"components": 12}, "findings": {"total": 3, "by_risk": {"critical": 1, "low": 2}}}),
            encoding="utf-8")
        (d / "findings.json").write_text(json.dumps([{"finding_id": "fd_1", "title": f"bad thing in {repo.name}"}]), encoding="utf-8")
        (d / "risk.json").write_text(json.dumps([{"finding_id": "fd_1", "score": 91.5, "band": "critical"}]), encoding="utf-8")
        return d

    monkeypatch.setitem(sys.modules, "guardian.graph.workflow", types.SimpleNamespace(run=fake_run))
    repos = []
    for n in ("a", "b", "boom"):
        (tmp_path / n).mkdir()
        repos.append(str(tmp_path / n))
    assert main(["run", "--repos", *repos]) == 1  # one target failed
    out = capsys.readouterr().out
    assert seen == ["a", "b"] and "bad thing in a" in out and "failed" in out
    batch = json.loads(next(settings.runs_dir.glob("batch_*.json")).read_text(encoding="utf-8"))
    rows = {r["target"]: r for r in batch["runs"]}
    assert rows["a"]["components"] == 12 and rows["a"]["findings"]["by_risk"]["critical"] == 1
    assert rows["a"]["top_risk"]["score"] == 91.5 and rows["boom"]["status"] == "failed"
    assert main(["run", "--repo", repos[0], "--repos", repos[1]]) == 2  # exactly one of the two
