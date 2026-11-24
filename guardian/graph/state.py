"""LangGraph state + per-run context. Owner: Dev1. Contract file (§9.4).

GraphState holds only JSON-serialisable values (ids, paths as str) so a checkpointer can persist it (D1-05).
Live objects (store, audit log, tool context, LLM) live in RunContext, looked up by run_id.

Why the split: LangGraph checkpoints GraphState to runs/<id>/checkpoints.sqlite at every step, which is what lets
a run pause at the human gate and resume days later in another process. Anything that cannot be serialised
(open files, the LLM client, locks) therefore must not be in the state; it is rebuilt on resume and registered
under the run id. Node functions get the state as input and call `get_ctx(state["run_id"])` for the live parts.
Fields marked ADDITIVE were added to the original contract and are only ever appended (§9.4).
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
    """State passed between graph nodes (total=False: a node returns only the keys it changes).
    `finding_ids` and `errors` use an `operator.add` reducer, so several nodes can append to them and
    LangGraph concatenates instead of overwriting. Every other key is last-write-wins."""

    run_id: str
    status: str  # created|discovering|detecting|analysing|...|done|failed (§5.2)
    sbom_evidence_id: str | None
    graph_evidence_id: str | None
    finding_ids: Annotated[list[str], operator.add]
    errors: Annotated[list[str], operator.add]
    # ADDITIVE (Dev1, D1-05): enough to rebuild the RunContext when a paused run resumes in a new process
    repo: str  # absolute path of the analysed repository
    work_dir: str | None
    sbom_path: str | None
    compare_ref: str | None
    # remediation loop (one finding at a time)
    plan_queue: list[str]  # finding ids still to plan, in priority order
    current: str | None  # finding being remediated
    attempt: int  # attempt number for `current` (1-based, max 3, G5.4)
    plan_id: str | None  # plan waiting at / coming from the human gate
    decision: dict | None  # Approval as JSON, written by the human gate on resume
    # Routing: the node that just ran sets `route`, the conditional edge function reads it (and emits the
    # supervisor `decision` event that explains the choice).
    route: str | None  # set by record_decision / validator for the conditional edge
    last_validation: dict | None  # previous failed attempt, so re-planning picks a different plan
    # batch remediation (settings.remediation_mode == "batch"): state of the round lives in recommendations.json
    round: int  # remediation round in progress (1-based)
    batch_id: str | None  # batch waiting at the gate
    # {"batch_id", "decisions": [Approval as JSON], "partial"} or, for "validate now",
    # {"batch_id", "validate_now": [plan_id, ...], "decisions": []}; written by the gate on resume
    batch_decision: dict | None


@dataclass
class RunContext:
    """The live, non-serialisable objects of one run. `llm` is None when no provider could be created, in which
    case agents fall back to their deterministic rules."""

    tool_ctx: ToolContext
    store: JsonStore
    audit: AuditLog
    llm: LLMProvider | None


# run_id -> RunContext for runs driven by this process (several runs may be driven concurrently by the API).
_CONTEXTS: dict[str, RunContext] = {}


def register(ctx: RunContext) -> None:
    """Make the context available to the nodes of its run (called by the driver before the graph starts)."""
    _CONTEXTS[ctx.tool_ctx.run_id] = ctx


def get_ctx(run_id: str) -> RunContext:
    """The live context of a running run; KeyError if the run is not being driven by this process."""
    return _CONTEXTS[run_id]


def unregister(run_id: str) -> None:
    """Forget the run's context when the driver returns (finished or paused at the gate)."""
    _CONTEXTS.pop(run_id, None)
