"""Run files for the remediation loop (§4.1 Day-2 files, used from Day 1). Owner: Dev1.

runs/<id>/plans/<plan_id>.json          RemediationPlan (written once, before the human sees it)
runs/<id>/pending_plan.json             {"plan_id", "plan_hash"} only while the run waits at the human gate
runs/<id>/approvals.jsonl               every human decision, append-only
runs/<id>/validation/<attempt_id>.json  ValidationResult per attempt
runs/<id>/validation/<attempt_id>.<plan_id>.json  one per plan when several plans were validated together (batch)
runs/<id>/pending_batch.json            {"batch_id", "round", "items": [...]} only while a batch waits for decisions

Why files and not only graph state: the run pauses at the human gate and is resumed later, possibly by another
process (CLI `guardian decide` or the API). The gate, the API and the validator all read these files, so a
plan is stored once, immutable, and referenced by id + hash everywhere else (G5.1). Plans are never edited:
a changed plan would have a different hash and an old approval could not apply to it.
Batch-mode state (recommendations.json) is handled by core/recs.py; this module only holds the pending batch
snapshot that guardrails/approval.py `check_batch` validates incoming decisions against.
"""

from __future__ import annotations

import json
from pathlib import Path

from guardian.core.models import Approval, RemediationPlan, RiskAssessment, ValidationResult


def save_plan(run_dir: Path, plan: RemediationPlan) -> Path:
    """Write plans/<plan_id>.json and return its path. Raises FileExistsError if the id exists: plans are
    immutable, so the hash a human approved can never describe different content later."""
    path = run_dir / "plans" / f"{plan.plan_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"plan {plan.plan_id} already written (plans are immutable)")
    path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_plan(run_dir: Path, plan_id: str) -> RemediationPlan | None:
    """The stored plan with this id, or None if it was never written."""
    path = run_dir / "plans" / f"{plan_id}.json"
    return RemediationPlan.model_validate_json(path.read_text(encoding="utf-8")) if path.exists() else None


def list_plans(run_dir: Path) -> list[RemediationPlan]:
    """All plans of the run, sorted by file name (plan ids are time-ordered ULIDs, so oldest first)."""
    d = run_dir / "plans"
    return [RemediationPlan.model_validate_json(p.read_text(encoding="utf-8")) for p in sorted(d.glob("pl_*.json"))] \
        if d.is_dir() else []


def set_pending(run_dir: Path, plan: RemediationPlan | None) -> None:
    """Mark `plan` as the one waiting at the human gate (sequential mode), or clear the marker with None.
    Only id and hash are stored; the plan itself is read back from plans/. `resume` uses it to check that a
    decision is for exactly the plan the human was shown."""
    path = run_dir / "pending_plan.json"
    if plan is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(json.dumps({"plan_id": plan.plan_id, "plan_hash": plan.plan_hash}), encoding="utf-8")


def get_pending(run_dir: Path) -> RemediationPlan | None:
    """The plan currently waiting for a decision (sequential mode), or None when the run is not paused."""
    path = run_dir / "pending_plan.json"
    if not path.exists():
        return None
    return load_plan(run_dir, json.loads(path.read_text(encoding="utf-8"))["plan_id"])


def set_pending_batch(run_dir: Path, batch: dict | None) -> None:
    """Write (or clear with None) the batch waiting at the gate: {"batch_id", "round", "items": [{plan_id,
    plan_hash, ...}]}. The file's existence is what tells the API and CLI that decisions are expected."""
    path = run_dir / "pending_batch.json"
    if batch is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(json.dumps(batch, indent=1), encoding="utf-8")


def get_pending_batch(run_dir: Path) -> dict | None:
    """The pending batch dict, or None if absent or unreadable (a corrupt file counts as "nothing pending")."""
    path = run_dir / "pending_batch.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def append_approval(run_dir: Path, approval: Approval) -> None:
    """Append one human decision to approvals.jsonl (append-only record of who decided what, and when)."""
    with (run_dir / "approvals.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(approval.model_dump_json() + "\n")


def _withdrawn_keys(run_dir: Path) -> set[tuple[str, str, str]]:
    """(plan_id, plan_hash, original ts) of every decision withdrawn by the user (approvals.withdrawn.jsonl).
    The withdrawal is a sidecar, so approvals.jsonl stays the untouched, append-only audit record."""
    path = run_dir / "approvals.withdrawn.jsonl"
    out: set[tuple[str, str, str]] = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                w = json.loads(line)
            except ValueError:
                continue
            if isinstance(w, dict) and w.get("withdrawn"):
                out.add((str(w.get("plan_id")), str(w.get("plan_hash")), str(w.get("original_ts"))))
    return out


def read_approvals(run_dir: Path, include_withdrawn: bool = False) -> list[dict]:
    """Every decision line of approvals.jsonl, oldest first, as dicts. Withdrawn decisions are left out unless
    `include_withdrawn`, in which case they are kept and marked `"withdrawn": true` (the API shows the full trail).
    Unreadable lines are skipped."""
    path = run_dir / "approvals.jsonl"
    if not path.exists():
        return []
    withdrawn = _withdrawn_keys(run_dir)
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if not isinstance(a, dict):
            continue
        if (str(a.get("plan_id")), str(a.get("plan_hash")), str(a.get("ts"))) in withdrawn:
            if not include_withdrawn:
                continue
            a = {**a, "withdrawn": True}
        out.append(a)
    return out


def voided_plan_ids(run_dir: Path) -> set[str]:
    """Plans that exist only because of a decision the user later withdrew, so they are no memory of anything.

    A plan is voided when its only decision was a withdrawn rejection, or a withdrawal line lists it under
    `voids_plans` (the alternatives built on a withdrawn rejection), and in both cases it has no live decision and no
    validation (a validated plan is real history: it was tested). Voided plans stay on disk; the planner just does
    not count them as tried or as spent attempts, so the item can be proposed afresh."""
    path = run_dir / "approvals.withdrawn.jsonl"
    if not path.exists():
        return set()
    cand: set[str] = set()
    for a in read_approvals(run_dir, include_withdrawn=True):
        if a.get("withdrawn") and a.get("decision") == "reject":
            cand.add(str(a.get("plan_id")))
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            w = json.loads(line)
        except ValueError:
            continue
        if isinstance(w, dict) and w.get("withdrawn"):
            cand.update(str(x) for x in (w.get("voids_plans") or []))
    if not cand:
        return set()
    live = {str(a.get("plan_id")) for a in read_approvals(run_dir)}
    d = run_dir / "validation"
    validated = set()
    if d.is_dir():
        for f in d.glob("at_*.json"):
            try:
                validated.add(str(json.loads(f.read_text(encoding="utf-8")).get("plan_id")))
            except ValueError:
                continue
    return cand - live - validated


def validation_path(run_dir: Path, attempt_id: str, plan_id: str | None = None, combined: bool = False) -> Path:
    """File for one validation result. A combined (batch) attempt validates several plans in one build, so it
    gets one file per plan (`<attempt>.<plan>.json`); a single-plan attempt uses `<attempt>.json`."""
    name = f"{attempt_id}.{plan_id}.json" if combined and plan_id else f"{attempt_id}.json"
    return run_dir / "validation" / name


def load_validation(run_dir: Path, attempt_id: str, plan_id: str) -> ValidationResult | None:
    """The result of `plan_id` in attempt `attempt_id` (a combined attempt has one file per plan)."""
    for path in (validation_path(run_dir, attempt_id, plan_id, True), validation_path(run_dir, attempt_id)):
        if path.exists():
            result = ValidationResult.model_validate_json(path.read_text(encoding="utf-8"))
            if result.plan_id == plan_id:
                return result
    return None


def save_validation(run_dir: Path, result: ValidationResult) -> Path:
    """Write the ValidationResult next to its attempt (creating validation/ on first use); returns the path."""
    path = validation_path(run_dir, result.attempt_id, result.plan_id, result.combined)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    return path


def list_validations(run_dir: Path) -> list[ValidationResult]:
    """Single-plan validation results (at_*.json). Per-plan files of combined attempts have a second dot in
    the name (`at_x.pl_y.json`) and are matched too by the glob, so each plan appears once."""
    d = run_dir / "validation"
    return [ValidationResult.model_validate_json(p.read_text(encoding="utf-8")) for p in sorted(d.glob("at_*.json"))] \
        if d.is_dir() else []


def save_risks(run_dir: Path, risks: list) -> None:
    """risk.json: list[RiskAssessment], highest score first (written by the risk analyst)."""
    data = [r.model_dump(mode="json") for r in risks]
    (run_dir / "risk.json").write_text(json.dumps(data, indent=1), encoding="utf-8")


def load_risks(run_dir: Path) -> dict[str, RiskAssessment]:
    path = run_dir / "risk.json"
    if not path.exists():
        return {}
    return {r["finding_id"]: RiskAssessment.model_validate(r) for r in json.loads(path.read_text(encoding="utf-8"))}
