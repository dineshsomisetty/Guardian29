"""D4-07 policy-as-code: native evaluator, Juice-Shop-like fixture fails >= 3 rules, patched copy passes."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from guardian.core.audit import AuditLog
from guardian.core.store import JsonStore
from guardian.tools.policy import build_policy_input, load_config, policy_check
from guardian.tools.registry import ToolContext, call_tool

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "juice-shop"
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
TARGETED = {"unpinned_action", "tag_only_image", "missing_lockfile", "denylisted_package", "typosquat_package"}


def make_repo(root: Path, *, patched: bool) -> Path:
    for sub in ("root", "frontend"):
        d = root if sub == "root" else root / sub
        d.mkdir(parents=True, exist_ok=True)
        data = json.loads((FIX / sub / "package.json").read_text(encoding="utf-8"))
        if patched:
            for sec in ("dependencies", "devDependencies"):
                (data.get(sec) or {}).pop("ngy-cookie", None)
            shutil.copy(FIX / sub / "package-lock.json", d / "package-lock.json")
        (d / "package.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    ref = SHA if patched else "v2"
    (wf / "ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      - uses: coverallsapp/github-action@{ref}\n"
                               "      - uses: ./local\n", encoding="utf-8")
    image = f"node:24@{DIGEST}" if patched else "node:24"
    (root / "Dockerfile").write_text(f"FROM {image}\nEXPOSE 3000\n", encoding="utf-8")
    return root


def test_juice_shop_fixture_fails_at_least_three_rules_and_patched_passes_targeted(tmp_path):
    cfg = load_config()
    before = make_repo(tmp_path / "before", patched=False)
    violations = policy_check(build_policy_input(before, cfg), cfg)
    rules = {v["rule"] for v in violations}
    assert len(rules) >= 3
    assert {"unpinned_action", "tag_only_image", "missing_lockfile", "denylisted_package"} <= rules
    first = next(v for v in violations if v["rule"] == "unpinned_action")
    assert first["file"] == ".github/workflows/ci.yml" and first["line"] == 4  # violations cite file + line

    after = make_repo(tmp_path / "after", patched=True)
    assert not TARGETED & {v["rule"] for v in policy_check(build_policy_input(after, cfg), cfg)}


def test_package_age_threshold_and_alias():
    doc = {"has_lockfile": True, "packages": [{"name": "fresh", "age_days": 2}, {"name": "old", "age_days": 400}]}
    assert [v["rule"] for v in policy_check(doc, {"thresholds": {"min_package_age_days": 7}})] == ["package_too_new"]
    assert [v["rule"] for v in policy_check(doc, {"thresholds": {"max_package_age_days": 7}})] == ["package_too_new"]
    assert policy_check(doc, {"thresholds": {}}) == []


def test_policy_check_tool_emits_policy_result_evidence_and_findings(tmp_path, settings):
    repo = make_repo(tmp_path / "repo", patched=False)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = ToolContext(run_id="r1", run_dir=run_dir, repo=repo, settings=settings)
    store, audit = JsonStore(run_dir), AuditLog(run_dir, "r1", echo=False)
    out = call_tool("detection", "policy_check", None, ctx, store, audit)
    assert out is not None and out.findings
    assert {f.category.value for f in out.findings} == {"policy_violation"}
    for f in out.findings:  # every finding cites policy_result evidence (file+line where the rule has one)
        ev = store.get_evidence(f.evidence_ids[0])
        assert ev.kind == "policy_result" and ev.facts["count"] >= 1 and "rego" in ev.facts
    pinned = next(f for f in out.findings if "unpinned_action" in f.title)
    assert pinned.file_path == ".github/workflows/ci.yml" and pinned.line == 4
    assert (run_dir / "policy_input.json").exists()
    # the validator may re-run it on a patched copy
    assert call_tool("validator", "policy_check", None, ctx, store, audit) is not None


def test_validator_flags_only_new_or_increased_policy_violations(tmp_path):
    """A fix that removes some violations of a rule is not a regression; a new rule, or more of one, is."""
    from guardian.agents.validator import _policy_regressions
    from guardian.core.models import Evidence, Finding, FindingCategory
    from guardian.core.store import JsonStore

    store = JsonStore(tmp_path)

    def pev(rule, count):
        return Evidence(run_id="r", kind="policy_result", source_tool="policy_check",
                        facts={"rule": rule, "count": count, "passed": False})

    for rule, n in (("unpinned_action", 7), ("tag_only_image", 2)):
        ev = pev(rule, n)
        store.add_evidence(ev)
        store.add_finding(Finding(run_id="r", category=FindingCategory.POLICY_VIOLATION, title=f"Policy {rule}",
                                  detector="detector:policy_check", evidence_ids=[ev.evidence_id]))
    after = [pev("unpinned_action", 6), pev("tag_only_image", 3), pev("denylisted_package", 1)]
    assert _policy_regressions(store, after) == ["policy:denylisted_package", "policy:tag_only_image"]
