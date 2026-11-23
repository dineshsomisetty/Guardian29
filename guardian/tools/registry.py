"""Tool calling convention + bindings between agents and Dev2/Dev4 tools. Owner: Dev1.

Every tool the pipeline calls has the signature

    def <name>(ctx: ToolContext) -> ToolOutput

and is referenced here by "module:function". Agents never import tools directly; they go through
`call_tool`, which logs tool_call / tool_result events, writes the audit log and stores Evidence/Findings.
D1-04 (evening) adds per-agent allowlists, typed args, budgets and the approval check on top of this.
"""

from __future__ import annotations

import importlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardian.core.audit import AuditLog
from guardian.core.config import Settings
from guardian.core.models import Evidence, Finding
from guardian.core.store import JsonStore


@dataclass
class ToolContext:
    run_id: str
    run_dir: Path
    repo: Path  # the target as given on the CLI (read-only)
    settings: Settings
    work_dir: Path | None = None  # sandboxed work copy (set by the workspace tool)
    sbom_path: Path | None = None
    graph: Any = None  # Dev2 graph object (to_json, paths_to, stats, add_pseudo_nodes)
    artifacts: dict[str, Any] = field(default_factory=dict)  # free-form outputs shared between tools


@dataclass
class ToolOutput:
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    summary: str | None = None


# agent -> ordered list of (tool name, "module:function")
BINDINGS: dict[str, list[tuple[str, str]]] = {
    "discovery": [
        ("workspace", "guardian.core.workspace:prepare_workspace"),  # Dev2 D2-02
        ("resolve_lockfiles", "guardian.tools.resolve:resolve_lockfiles"),  # Dev2 D2-02
        ("sbom", "guardian.tools.sbom:generate_sbom"),  # Dev2 D2-02
        ("graph_build", "guardian.core.graph_build:build_graph"),  # Dev2 D2-03
    ],
    "detection": [
        ("grype", "guardian.tools.scanners:grype_scan"),  # Dev2 D2-04
        ("osv", "guardian.tools.scanners:osv_scan"),  # Dev2 D2-04 (P1)
        ("detector:lockfile", "guardian.tools.detectors.lockfile:detect"),  # Dev2 D2-05
        ("detector:typosquat", "guardian.tools.detectors.typosquat:detect"),  # Dev2 D2-05 + Dev4 D4-01
        ("detector:ci_pin", "guardian.tools.detectors.ci_pin:detect"),  # Dev4 D4-12
        ("detector:image_pin", "guardian.tools.detectors.image_pin:detect"),  # Dev4 D4-12
        ("changes", "guardian.tools.detectors.unexpected_change:mini_diff"),  # Dev4 D4-11 (Dev2 D2-06 later)
    ],
}

# Initial-risk rule (Dev4 D4-02). Signature: initial_risk(finding: Finding) -> Priority
INITIAL_RISK_RULE = "guardian.core.scoring:initial_risk"


class ToolUnavailable(Exception):
    pass


def resolve(target: str):
    module_name, func_name = target.split(":")
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name and module_name.startswith(exc.name):
            raise ToolUnavailable(f"{module_name} not implemented yet") from exc
        raise
    fn = getattr(module, func_name, None)
    if fn is None:
        raise ToolUnavailable(f"{target} not found")
    return fn


def call_tool(agent: str, name: str, target: str, ctx: ToolContext, store: JsonStore, audit: AuditLog) -> ToolOutput | None:
    """Run one bound tool. Unavailable or failing tools are logged and skipped (pipeline continues)."""
    try:
        fn = resolve(target)
    except ToolUnavailable as exc:
        audit.emit(agent, "error", f"tool {name} unavailable: {exc}", data={"tool": name})
        return None

    audit.emit(agent, "tool_call", f"{name}", data={"tool": name, "target": target})
    t0 = time.monotonic()
    try:
        out = fn(ctx)
    except Exception as exc:  # tool failures must not kill the run
        audit.emit(agent, "error", f"tool {name} failed: {type(exc).__name__}: {str(exc)[:300]}",
                   data={"tool": name})
        return None
    if out is None:
        out = ToolOutput()
    if not isinstance(out, ToolOutput):
        audit.emit(agent, "error", f"tool {name} returned {type(out).__name__}, expected ToolOutput",
                   data={"tool": name})
        return None

    for ev in out.evidence:
        if not store.has_evidence(ev.evidence_id):
            store.add_evidence(ev)
    ctx.artifacts.update(out.artifacts)
    for key in ("work_dir", "sbom_path", "graph"):
        if key in out.artifacts:
            setattr(ctx, key, out.artifacts[key])

    summary = out.summary or f"{len(out.findings)} findings, {len(out.evidence)} evidence"
    audit.emit(agent, "tool_result", f"{name}: {summary}",
               evidence_ids=[e.evidence_id for e in out.evidence][:50],
               data={"tool": name, "ms": int((time.monotonic() - t0) * 1000),
                     "findings": len(out.findings), "evidence": len(out.evidence)})
    return out
