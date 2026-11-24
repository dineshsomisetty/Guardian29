"""LangGraph state + per-run context. Owner: Dev1. Contract file (§9.4).

GraphState holds only JSON-serialisable values (ids, paths as str) so a checkpointer can persist it (D1-05).
Live objects (store, audit log, tool context, LLM) live in RunContext, looked up by run_id.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass
from typing import Annotated, TypedDict

from guardian.core.audit import AuditLog
from guardian.core.store import JsonStore
from guardian.llm.provider import LLMProvider
from guardian.tools.registry import ToolContext


class GraphState(TypedDict, total=False):
    run_id: str
    status: str  # created|discovering|detecting|analysing|...|done|failed (§5.2)
    sbom_evidence_id: str | None
    graph_evidence_id: str | None
    finding_ids: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]
    # ADDITIVE (Dev1, D1-05): enough to rebuild the RunContext when a paused run resumes in a new process
    repo: str
    work_dir: str | None
    sbom_path: str | None
    compare_ref: str | None
    # remediation loop (one finding at a time)
    plan_queue: list[str]  # finding ids still to plan, in priority order
    current: str | None  # finding being remediated
    attempt: int  # attempt number for `current` (1-based, max 3, G5.4)
    plan_id: str | None  # plan waiting at / coming from the human gate
    decision: dict | None  # Approval as JSON, written by the human gate on resume
    route: str | None  # set by record_decision / validator for the conditional edge
    last_validation: dict | None  # previous failed attempt, so re-planning picks a different plan
    # batch remediation (settings.remediation_mode == "batch"): state of the round lives in recommendations.json
    round: int  # remediation round in progress (1-based)
    batch_id: str | None  # batch waiting at the gate
    batch_decision: dict | None  # {"batch_id", "decisions": [Approval as JSON]}, written by the gate on resume


@dataclass
class RunContext:
    tool_ctx: ToolContext
    store: JsonStore
    audit: AuditLog
    llm: LLMProvider | None


_CONTEXTS: dict[str, RunContext] = {}


def register(ctx: RunContext) -> None:
    _CONTEXTS[ctx.tool_ctx.run_id] = ctx


def get_ctx(run_id: str) -> RunContext:
    return _CONTEXTS[run_id]


def unregister(run_id: str) -> None:
    _CONTEXTS.pop(run_id, None)
