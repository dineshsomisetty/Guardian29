"""Pre-flight (a plan that drops a still-imported package never reaches the sandbox) and bisection of a failed
combined run. The sandbox run itself is replaced by a fake `_validate_run`; no Docker, no network."""

import json
from types import SimpleNamespace as NS

import pytest

from guardian.agents import validator
from guardian.agents.validator import Item, still_imported, validate_plans
from guardian.core.models import Confidence, PatchOp, ValidationResult


def _plan(pid, ops=()):
    return NS(plan_id=pid, action="upgrade", ops=list(ops), target_version="1.0.0", attempt=1)


def _item(pid, ops=()):
    return Item(_plan(pid, ops), NS(), [NS(finding_id="f_" + pid, title=pid)])


def _res(pid, verdict, combined, group_failure=False):
    return ValidationResult(attempt_id=f"at_{pid}_{verdict}", plan_id=pid, finding_id="f_" + pid, build_ok=True,
                            target_finding_resolved=verdict == "verified", risk_before=1, risk_after=0, verdict=verdict,
                            final_confidence=Confidence.MEDIUM, combined=combined, group_failure=group_failure)


class Rig:
    """Fake `_validate_run`: a run fails (failed_build, shared) when it holds a culprit, or when it holds `pair`."""

    def __init__(self, culprits=(), pair=()):
        self.culprits, self.pair, self.runs = set(culprits), set(pair), []

    def __call__(self, rc, items, *, combined, round_no=None, settle=None, limitation=None):
        ids = [i.plan.plan_id for i in items]
        self.runs.append(ids)
        bad = bool(self.culprits & set(ids)) or bool(self.pair and self.pair <= set(ids))
        iso = combined and len(items) > 1 and bad
        out = []
        for it in items:
            v = "failed_build" if bad else "verified"
            res = _res(it.plan.plan_id, v, combined, group_failure=iso)
            if settle is not None and not iso:
                settle(it, res)
            out.append((it, res, True))
        return out, iso


def _rc(tmp_path):
    audit = NS(emit=lambda *a, **k: None)
    return NS(audit=audit, tool_ctx=NS(repo=tmp_path, budget=None, run_dir=tmp_path))


def _run(monkeypatch, tmp_path, rig, n, carried=()):
    monkeypatch.setattr(validator, "_validate_run", rig)
    settled = {}

    def settle(it, res, interaction=False, dropped=False):
        settled[it.plan.plan_id] = ("interaction" if interaction else res.verdict)

    items = [_item(f"p{i}") for i in range(n)]
    final = validate_plans(_rc(tmp_path), items, 1, settle, [_item(c) for c in carried])
    return final, settled


@pytest.mark.parametrize("n,culprit", [(21, "p13"), (21, "p0"), (21, "p20"), (8, "p3")])
def test_one_culprit_is_found_in_about_log_n_runs(monkeypatch, tmp_path, n, culprit):
    rig = Rig(culprits={culprit})
    final, settled = _run(monkeypatch, tmp_path, rig, n)
    assert [p for p, v in settled.items() if v != "verified"] == [culprit]
    assert len(settled) == n and not final[culprit].group_failure and final[culprit].verdict == "failed_build"
    assert all(final[p].verdict == "verified" for p in settled if p != culprit)
    assert len(rig.runs) <= 1 + 2 * 5  # the combined run plus two halves per level (vs 1 + 21 runs alone)
    assert len(rig.runs) < n


def test_two_culprits_and_no_culprit(monkeypatch, tmp_path):
    rig = Rig(culprits={"p1", "p6"})
    _, settled = _run(monkeypatch, tmp_path, rig, 8)
    assert sorted(p for p, v in settled.items() if v != "verified") == ["p1", "p6"]


def test_interaction_when_every_part_passes(monkeypatch, tmp_path):
    rig = Rig(pair={"p0", "p5"})  # fails only when both are in one run
    final, settled = _run(monkeypatch, tmp_path, rig, 6)
    assert set(settled.values()) == {"verified"}  # each verified in a group, reported with the NOT-verified note
    assert rig.runs[0] == [f"p{i}" for i in range(6)]


def test_carried_plans_stay_underneath_and_a_lone_new_plan_goes_back_as_interaction(monkeypatch, tmp_path):
    rig = Rig(pair={"c0", "p0"})
    _, settled = _run(monkeypatch, tmp_path, rig, 1, carried=["c0"])
    assert settled == {"p0": "interaction"}
    assert rig.runs == [["c0", "p0"], ["p0"]]  # no pointless re-run of the same group, then alone


def test_group_failure_results_are_marked(monkeypatch, tmp_path):
    rig = Rig(culprits={"p2"})
    seen = []

    def spy(*a, **k):
        out = rig(*a, **k)
        seen.append([(r.plan_id, r.group_failure) for _, r, _ in out[0]])
        return out

    monkeypatch.setattr(validator, "_validate_run", spy)
    validate_plans(_rc(tmp_path), [_item(f"p{i}") for i in range(4)], 1, lambda *a, **k: None, [])
    assert all(g for _, g in seen[0]) and len(seen[0]) == 4  # the shared failure blames nobody yet
    assert seen[-1] == [("p2", False)] or seen[-2] == [("p2", False)]  # the culprit ends up alone, really blamed


# ---------------------------------------------------------------- pre-flight


def _repo(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"ngy-cookie": "1", "left": "1"}}))
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.ts").write_text("import x from 'y'\nimport { C } from 'ngy-cookie';\n")
    (tmp_path / "src" / "util.ts").write_text("import { C } from 'ngy-cookie/sub';\n")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "a.test.ts").write_text("import 'left'\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package.json").write_text("{}")
    (tmp_path / "sub" / "own.ts").write_text("import 'only-sub'\n")
    return tmp_path


def _drop(op, name="ngy-cookie", file="package.json", **extra):
    return _plan("pl", [PatchOp(op=op, file_path=file, args={"name": name, **extra})])


@pytest.mark.parametrize("op", ["remove_dependency", "block_package", "replace_dependency"])
def test_still_imported_names_file_and_line(tmp_path, op):
    from guardian.tools import reachability
    reachability._INDEX.clear()
    why = still_imported(_repo(tmp_path), _drop(op, new_name="ngx-cookie") if op == "replace_dependency"
                         else _drop(op))
    assert why == ("the package 'ngy-cookie' is still imported by src/app.ts:2; remove or replace the imports first")


def test_preflight_ignores_tests_other_manifests_renames_and_unknowns(tmp_path):
    from guardian.tools import reachability
    reachability._INDEX.clear()
    repo = _repo(tmp_path)
    assert still_imported(repo, _drop("remove_dependency", name="left")) is None  # only a test imports it
    assert still_imported(repo, _drop("remove_dependency", name="nobody")) is None
    assert still_imported(repo, _drop("remove_dependency", name="only-sub")) is None  # sub/ has its own manifest
    assert still_imported(repo, _drop("remove_dependency", name="only-sub", file="sub/package.json")) is not None
    renames = [PatchOp(op="rename_import", file_path=f, args={"name": "ngy-cookie", "new_name": "ngx-cookie"})
               for f in ("src/app.ts", "src/util.ts")]
    plan = _plan("pl", [PatchOp(op="replace_dependency", file_path="package.json",
                                args={"name": "ngy-cookie", "new_name": "ngx-cookie"}), *renames])
    assert still_imported(repo, plan) is None  # the plan itself rewrites every import
    assert still_imported(repo, _plan("pl", [PatchOp(op="set_dependency_version", file_path="package.json",
                                                      args={"name": "ngy-cookie", "version": "2"})])) is None
