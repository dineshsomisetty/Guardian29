"""D4-10 package-risk detectors from cached registry fixtures (zero network)."""
from __future__ import annotations

import json

import httpx
import pytest

from guardian.core.audit import AuditLog
from guardian.core.store import JsonStore
from guardian.tools.registry import ToolContext, call_tool
from guardian.tools.threat_intel import IntelClient


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network call in an offline test")

    monkeypatch.setattr(httpx.Client, "request", boom)


def packument(name, versions, *, repo="git+https://x/y.git", signed=True, created="2019-01-01T00:00:00Z"):
    """versions: [(version, iso time, [maintainers])]"""
    time = {"created": created, "modified": versions[-1][1]}
    vs = {}
    for v, t, ms in versions:
        time[v] = t
        vs[v] = {"name": name, "version": v, "maintainers": [{"name": m} for m in ms],
                 "dist": {"signatures": [{"keyid": "k", "sig": "s"}]} if signed else {}}
        if repo:
            vs[v]["repository"] = {"url": repo}
    return {"name": name, "dist-tags": {"latest": versions[-1][0]}, "time": time, "versions": vs,
            "maintainers": [{"name": m} for m in versions[-1][2]]}


def seed(name, payload):
    IntelClient(offline=True)._store(f"npm:{name}", payload)


def make_ctx(tmp_path, settings, deps, cfg):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text(json.dumps({"name": "app", "dependencies": deps}, indent=2), encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = ToolContext(run_id="r1", run_dir=run_dir, repo=repo, settings=settings)
    ctx.artifacts["guardian_config"] = cfg
    return ctx, JsonStore(run_dir), AuditLog(run_dir, "r1", echo=False)


def run_detector(ctx, store, audit):
    out = call_tool("detection", "detector:package_risk", None, ctx, store, audit)
    assert out is not None
    for f in out.findings:  # detectors always cite evidence
        assert store.get_evidence(f.evidence_ids[0]).facts
    return out


def by_cat(out):
    res: dict[str, list] = {}
    for f in out.findings:
        res.setdefault(f.category.value, []).append(f)
    return res


def test_maintainer_change_burst_confusion_and_provenance_gap(tmp_path, settings):
    seed("swapped", packument("swapped", [("1.0.0", "2020-01-01T00:00:00Z", ["alice"]),
                                          ("1.1.0", "2021-01-01T00:00:00Z", ["mallory"])], repo=None))
    burst = [(f"2.0.{i}", f"2021-03-0{i + 1}T00:00:00Z", ["bob"]) for i in range(6)]
    seed("bursty", packument("bursty", burst))
    for n in ("signed-a", "signed-b", "signed-c"):
        seed(n, packument(n, [("1.0.0", "2020-01-01T00:00:00Z", ["z"])]))
    seed("unsigned", packument("unsigned", [("1.0.0", "2020-01-01T00:00:00Z", ["z"])], signed=False))
    seed("@acme/billing", packument("@acme/billing", [("9.9.9", "2022-01-01T00:00:00Z", ["squatter"])]))
    deps = {n: "^1.0.0" for n in ("swapped", "bursty", "signed-a", "signed-b", "signed-c", "unsigned")}
    deps["@acme/billing"] = "^1.0.0"
    cfg = {"internal_scopes": ["@acme"], "thresholds": {"package_risk_max_findings": 10}}
    ctx, store, audit = make_ctx(tmp_path, settings, deps, cfg)
    cats = by_cat(run_detector(ctx, store, audit))

    titles = [f.title for f in cats["maintainer_change"]]
    assert any(t.startswith("swapped: maintainer set changed") for t in titles)
    assert any(t.startswith("bursty: unusual release activity") for t in titles)
    assert [f.component_purl for f in cats["dependency_confusion"]] == ["pkg:npm/%40acme/billing@1.0.0"]
    gaps = {f.component_purl.split("/")[-1].split("@")[0]: store.get_evidence(f.evidence_ids[0]).facts["reasons"]
            for f in cats["provenance_gap"]}
    assert "no_repository_and_maintainer_changed" in gaps["swapped"]
    assert gaps["unsigned"] == ["signature_missing_peers_have"]
    swapped = next(f for f in cats["maintainer_change"] if f.title.startswith("swapped"))
    assert swapped.file_path == "package.json" and swapped.line  # file + line of the manifest entry


def test_internal_name_absent_from_public_registry_is_not_confusion(tmp_path, settings):
    ctx, store, audit = make_ctx(tmp_path, settings, {"@acme/private": "1.0.0"}, {"internal_scopes": ["@acme"]})
    assert run_detector(ctx, store, audit).findings == []  # offline cache miss / not on the registry


def test_findings_are_capped_and_only_direct_prod_deps_are_checked(tmp_path, settings):
    for i in range(5):
        seed(f"swap{i}", packument(f"swap{i}", [("1.0.0", "2020-01-01T00:00:00Z", ["a"]),
                                                ("1.1.0", "2021-01-01T00:00:00Z", ["b"])]))
    seed("devonly", packument("devonly", [("1.0.0", "2020-01-01T00:00:00Z", ["a"]),
                                          ("1.1.0", "2021-01-01T00:00:00Z", ["b"])]))
    ctx, store, audit = make_ctx(tmp_path, settings, {f"swap{i}": "1.0.0" for i in range(5)},
                                 {"thresholds": {"package_risk_max_findings": 2}})
    manifest = ctx.repo / "package.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["devDependencies"] = {"devonly": "1.0.0"}
    manifest.write_text(json.dumps(data), encoding="utf-8")
    out = run_detector(ctx, store, audit)
    maint = [f for f in out.findings if f.title.startswith("swap") and "maintainer set" in f.title]
    assert len(maint) == 2
    assert not any("devonly" in f.title for f in out.findings)
