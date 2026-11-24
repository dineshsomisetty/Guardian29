# Document the contract for the surrounding module or callable.
"""D4-07 policy-as-code: native evaluator, Juice-Shop-like fixture fails >= 3 rules, patched copy passes."""
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Load json for policy check tests.
import json
# Load shutil for policy check tests.
import shutil
# Import Path from pathlib.
from pathlib import Path

# Import AuditLog from guardian.core.audit.
from guardian.core.audit import AuditLog
# Import JsonStore from guardian.core.store.
from guardian.core.store import JsonStore
# Import build_policy_input, load_config, policy_check from guardian.tools.policy.
from guardian.tools.policy import build_policy_input, load_config, policy_check
# Import ToolContext, call_tool from guardian.tools.registry.
from guardian.tools.registry import ToolContext, call_tool

# Store the expression on this line in FIX.
FIX = Path(__file__).resolve().parents[1] / "fixtures" / "juice-shop"
# Store 'a' * 40 in SHA.
SHA = "a" * 40
# Store 'sha256:' + 'b' * 64 in DIGEST.
DIGEST = "sha256:" + "b" * 64
# Store a collection of distinct values in TARGETED.
TARGETED = {"unpinned_action", "tag_only_image", "missing_lockfile", "denylisted_package", "typosquat_package"}


# Define make_repo for policy check tests.
# Inputs include root, patched.
def make_repo(root: Path, *, patched: bool) -> Path:
    # Iterate over ('root', 'frontend').
    # Bind each item to sub before processing it.
    for sub in ("root", "frontend"):
        # Store root if sub == 'root' else root / sub in d.
        d = root if sub == "root" else root / sub
        # Call d.mkdir at this point.
        d.mkdir(parents=True, exist_ok=True)
        # Store the result of json.loads in data.
        data = json.loads((FIX / sub / "package.json").read_text(encoding="utf-8"))
        # Check whether patched.
        if patched:
            # Iterate over ('dependencies', 'devDependencies').
            # Bind each item to sec before processing it.
            for sec in ("dependencies", "devDependencies"):
                # Call (data.get(sec) or {}).pop at this point.
                (data.get(sec) or {}).pop("ngy-cookie", None)
            # Call shutil.copy at this point.
            shutil.copy(FIX / sub / "package-lock.json", d / "package-lock.json")
        # Call (d / 'package.json').write_text at this point.
        (d / "package.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    # Store root / '.github' / 'workflows' in wf.
    wf = root / ".github" / "workflows"
    # Call wf.mkdir at this point.
    wf.mkdir(parents=True, exist_ok=True)
    # Store SHA if patched else 'v2' in ref.
    ref = SHA if patched else "v2"
    # Call (wf / 'ci.yml').write_text at this point.
    (wf / "ci.yml").write_text(f"jobs:\n  a:\n    steps:\n      - uses: coverallsapp/github-action@{ref}\n"
                               # Supply the next part of the expression started above.
                               "      - uses: ./local\n", encoding="utf-8")
    # Store f'node:24@{DIGEST}' if patched else 'node:24' in image.
    image = f"node:24@{DIGEST}" if patched else "node:24"
    # Call (root / 'Dockerfile').write_text at this point.
    (root / "Dockerfile").write_text(f"FROM {image}\nEXPOSE 3000\n", encoding="utf-8")
    # Return root to the caller.
    return root


# Exercise the expected behavior for juice shop fixture fails at least three rules and patched passes targeted.
def test_juice_shop_fixture_fails_at_least_three_rules_and_patched_passes_targeted(tmp_path):
    # Store the result of load_config in cfg.
    cfg = load_config()
    # Store the result of make_repo in before.
    before = make_repo(tmp_path / "before", patched=False)
    # Store the result of policy_check in violations.
    violations = policy_check(build_policy_input(before, cfg), cfg)
    # Store values selected or transformed from the input in rules.
    rules = {v["rule"] for v in violations}
    # Check that len(rules) >= 3.
    assert len(rules) >= 3
    # Check that the expression on this line.
    assert {"unpinned_action", "tag_only_image", "missing_lockfile", "denylisted_package"} <= rules
    # Store the result of next in first.
    first = next(v for v in violations if v["rule"] == "unpinned_action")
    # Check that the expression on this line.
    assert first["file"] == ".github/workflows/ci.yml" and first["line"] == 4  # violations cite file + line

    # Store the result of make_repo in after.
    after = make_repo(tmp_path / "after", patched=True)
    # Check that the expression on this line.
    assert not TARGETED & {v["rule"] for v in policy_check(build_policy_input(after, cfg), cfg)}


# Exercise the expected behavior for package age threshold and alias.
def test_package_age_threshold_and_alias():
    # Store a mapping keyed by the fields below in doc.
    doc = {"has_lockfile": True, "packages": [{"name": "fresh", "age_days": 2}, {"name": "old", "age_days": 400}]}
    # Check that the expression on this line.
    assert [v["rule"] for v in policy_check(doc, {"thresholds": {"min_package_age_days": 7}})] == ["package_too_new"]
    # Check that the expression on this line.
    assert [v["rule"] for v in policy_check(doc, {"thresholds": {"max_package_age_days": 7}})] == ["package_too_new"]
    # Check that policy_check(doc, {'thresholds': {}}) == [].
    assert policy_check(doc, {"thresholds": {}}) == []


# Exercise the expected behavior for policy check tool emits policy result evidence and findings.
def test_policy_check_tool_emits_policy_result_evidence_and_findings(tmp_path, settings):
    # Store the result of make_repo in repo.
    repo = make_repo(tmp_path / "repo", patched=False)
    # Store tmp_path / 'run' in run_dir.
    run_dir = tmp_path / "run"
    # Call run_dir.mkdir at this point.
    run_dir.mkdir()
    # Store the result of ToolContext in ctx.
    ctx = ToolContext(run_id="r1", run_dir=run_dir, repo=repo, settings=settings)
    # Store (JsonStore(run_dir), AuditLog(run_dir, 'r1', echo=False)) in (store, audit).
    store, audit = JsonStore(run_dir), AuditLog(run_dir, "r1", echo=False)
    # Store the result of call_tool in out.
    out = call_tool("detection", "policy_check", None, ctx, store, audit)
    # Check that out is not None and out.findings.
    assert out is not None and out.findings
    # Check that the expression on this line.
    assert {f.category.value for f in out.findings} == {"policy_violation"}
    # Iterate over out.findings.
    # Bind each item to f before processing it.
    for f in out.findings:  # every finding cites policy_result evidence (file+line where the rule has one)
        # Store the result of store.get_evidence in ev.
        ev = store.get_evidence(f.evidence_ids[0])
        # Check that the expression on this line.
        assert ev.kind == "policy_result" and ev.facts["count"] >= 1 and "rego" in ev.facts
    # Store the result of next in pinned.
    pinned = next(f for f in out.findings if "unpinned_action" in f.title)
    # Check that the expression on this line.
    assert pinned.file_path == ".github/workflows/ci.yml" and pinned.line == 4
    # Check that (run_dir / 'policy_input.json').exists().
    assert (run_dir / "policy_input.json").exists()
    # the validator may re-run it on a patched copy
    # Check that the expression on this line.
    assert call_tool("validator", "policy_check", None, ctx, store, audit) is not None


# Exercise the expected behavior for validator flags only new or increased policy violations.
def test_validator_flags_only_new_or_increased_policy_violations(tmp_path):
    # Document the contract for the surrounding module or callable.
    """A fix that removes some violations of a rule is not a regression; a new rule, or more of one, is."""
    # Import _policy_regressions from guardian.agents.validator.
    from guardian.agents.validator import _policy_regressions
    # Import Evidence, Finding, FindingCategory from guardian.core.models.
    from guardian.core.models import Evidence, Finding, FindingCategory
    # Import JsonStore from guardian.core.store.
    from guardian.core.store import JsonStore

    # Store the result of JsonStore in store.
    store = JsonStore(tmp_path)

    # Define pev for policy check tests.
    # Inputs include rule, count.
    def pev(rule, count):
        # Return the result of Evidence to the caller.
        return Evidence(run_id="r", kind="policy_result", source_tool="policy_check",
                        # Supply facts as named arguments to the surrounding call.
                        # These names connect the values to the receiving parameters.
                        facts={"rule": rule, "count": count, "passed": False})

    # Iterate over (('unpinned_action', 7), ('tag_only_image', 2)).
    # Bind each item to (rule, n) before processing it.
    for rule, n in (("unpinned_action", 7), ("tag_only_image", 2)):
        # Store the result of pev in ev.
        ev = pev(rule, n)
        # Call store.add_evidence at this point.
        store.add_evidence(ev)
        # Call store.add_finding at this point.
        store.add_finding(Finding(run_id="r", category=FindingCategory.POLICY_VIOLATION, title=f"Policy {rule}",
                                  # Supply detector, evidence_ids as named arguments to the surrounding call.
                                  # These names connect the values to the receiving parameters.
                                  detector="detector:policy_check", evidence_ids=[ev.evidence_id]))
    # Store an ordered collection in after.
    after = [pev("unpinned_action", 6), pev("tag_only_image", 3), pev("denylisted_package", 1)]
    # Check that the expression on this line.
    assert _policy_regressions(store, after) == ["policy:denylisted_package", "policy:tag_only_image"]
