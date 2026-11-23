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
