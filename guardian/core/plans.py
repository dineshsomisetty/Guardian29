"""Run files for the remediation loop (§4.1 Day-2 files, used from Day 1). Owner: Dev1.

runs/<id>/plans/<plan_id>.json          RemediationPlan (written once, before the human sees it)
runs/<id>/pending_plan.json             {"plan_id", "plan_hash"} only while the run waits at the human gate
runs/<id>/approvals.jsonl               every human decision, append-only
runs/<id>/validation/<attempt_id>.json  ValidationResult per attempt
"""

from __future__ import annotations

import json
from pathlib import Path

from guardian.core.models import Approval, RemediationPlan, ValidationResult


def save_plan(run_dir: Path, plan: RemediationPlan) -> Path:
    path = run_dir / "plans" / f"{plan.plan_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"plan {plan.plan_id} already written (plans are immutable)")
    path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_plan(run_dir: Path, plan_id: str) -> RemediationPlan | None:
    path = run_dir / "plans" / f"{plan_id}.json"
    return RemediationPlan.model_validate_json(path.read_text(encoding="utf-8")) if path.exists() else None


def list_plans(run_dir: Path) -> list[RemediationPlan]:
    d = run_dir / "plans"
    return [RemediationPlan.model_validate_json(p.read_text(encoding="utf-8")) for p in sorted(d.glob("pl_*.json"))] \
        if d.is_dir() else []


def set_pending(run_dir: Path, plan: RemediationPlan | None) -> None:
    path = run_dir / "pending_plan.json"
    if plan is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(json.dumps({"plan_id": plan.plan_id, "plan_hash": plan.plan_hash}), encoding="utf-8")


def get_pending(run_dir: Path) -> RemediationPlan | None:
    path = run_dir / "pending_plan.json"
    if not path.exists():
        return None
    return load_plan(run_dir, json.loads(path.read_text(encoding="utf-8"))["plan_id"])


def append_approval(run_dir: Path, approval: Approval) -> None:
    with (run_dir / "approvals.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(approval.model_dump_json() + "\n")


def save_validation(run_dir: Path, result: ValidationResult) -> Path:
    path = run_dir / "validation" / f"{result.attempt_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def list_validations(run_dir: Path) -> list[ValidationResult]:
    d = run_dir / "validation"
    return [ValidationResult.model_validate_json(p.read_text(encoding="utf-8")) for p in sorted(d.glob("at_*.json"))] \
        if d.is_dir() else []
