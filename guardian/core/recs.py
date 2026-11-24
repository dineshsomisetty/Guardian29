"""Batch remediation files (recommendations.json), shared by the graph, the API and the CLI. Owner: Dev1.

runs/<id>/recommendations.json  {"round", "status", "batch_id", "items": [Recommendation]} (all rounds' state)
runs/<id>/pending_batch.json    only while the run waits for the human's decisions (see core/plans.py)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

Outcome = Literal["awaiting_decision", "validating", "verified", "failed", "rejected", "accepted",
                  "no_alternative", "needs_person"]
FINAL = {"verified", "accepted", "no_alternative", "needs_person"}


class Alternative(BaseModel):
    action: str
    target_version: str | None = None
    summary: str


class Previous(BaseModel):
    plan_id: str
    outcome: Literal["failed", "rejected"]
    detail: str
    reason_type: str | None = None  # for a rejection: steers which alternative comes next


class Recommendation(BaseModel):
    rec_id: str
    round: int
    finding_ids: list[str]
    primary_finding_id: str
    kind: Literal["fix", "no_alternative"]
    plan_id: str | None = None
    plan_hash: str | None = None
    alternatives: list[Alternative] = []
    reason: str | None = None
    previous: Previous | None = None
    decision: Literal["approve", "reject", "accept_risk"] | None = None
    outcome: Outcome
    attempt: int = 0  # ADDITIVE: attempts spent on this group (G5.4 max 3)
    score: float = 0  # ADDITIVE: risk score of the primary finding (items are sorted by it)


def recs_path(run_dir: Path) -> Path:
    return run_dir / "recommendations.json"


def load_recs(run_dir: Path) -> dict:
    """{"round", "status", "batch_id", "items": [Recommendation]}; empty state when nothing was written yet."""
    path = recs_path(run_dir)
    if not path.exists():
        return {"round": 0, "step": 0, "status": "awaiting_decisions", "batch_id": None, "items": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    data.setdefault("step", 0)
    data["items"] = [Recommendation.model_validate(i) for i in data.get("items", [])]
    return data


def save_recs(run_dir: Path, round_no: int, status: str, batch_id: str | None, items: list[Recommendation],
              step: int | None = None) -> None:
    """`round` = full rounds; `step` = decision sets submitted so far (full or one at a time), kept when not given."""
    if step is None:
        step = load_recs(run_dir)["step"]
    ordered = sorted(items, key=lambda r: (-r.score, r.rec_id))
    body = {"round": round_no, "step": step, "status": status, "batch_id": batch_id,
            "items": [r.model_dump(mode="json") for r in ordered]}
    recs_path(run_dir).write_text(json.dumps(body, indent=1), encoding="utf-8")
