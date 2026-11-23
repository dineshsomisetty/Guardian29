"""Tool calling convention + bindings between agents and Dev2/Dev4 tools. Owner: Dev1.

Every tool the pipeline calls has the signature

    def <name>(ctx: ToolContext) -> ToolOutput

and is referenced here by "module:function". Tools that take arguments are `fn(ctx, args)` where `args` is a
Pydantic model declared in their ToolSpec. Agents never import tools directly; they go through `call_tool`,
which enforces the G3 guardrails (D1-04) before anything runs:

  G3.1 per-agent allowlist  (BINDINGS for the pipeline agents + ToolSpec.agents + EXTRA_ALLOW)
  G3.2 typed args           (Pydantic validation; bad args never reach the tool)
  G3.3 write tools          (ToolSpec.writes) need an `approve` Approval matching plan_id + plan_hash
  G3.4 no publish/push/merge/deploy tool can be registered or called
  G3.6 budgets              (tool calls + wall-clock per agent; LLM tokens per run, see guardrails/budgets)

and then logs tool_call / tool_result events, writes the audit log and stores Evidence.
"""

from __future__ import annotations

import importlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from guardian.core.audit import AuditLog
from guardian.core.config import Settings
from guardian.core.models import Approval, Evidence, Finding, RemediationPlan
from guardian.core.store import JsonStore
from guardian.guardrails.approval import check_write
from guardian.guardrails.budgets import Budget


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
    budget: Budget | None = None  # G3.6, set by the run driver


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
        ("detector:install_scripts", "guardian.tools.detectors.install_scripts:detect"),  # Dev2 D2-06
        ("changes", "guardian.tools.detectors.unexpected_change:detect"),  # Dev4 D4-11 + Dev2 D2-06
        ("detector:package_risk", "guardian.tools.detectors.package_risk:detect"),  # D4-10
        ("policy_check", "guardian.tools.policy:run_policy_check"),  # D4-07
    ],
}


@dataclass(frozen=True)
class ToolSpec:
    """A tool outside the fixed discovery/detection sequence, called by an agent with arguments."""

    name: str
    target: str
    agents: frozenset[str]
    args_model: type[BaseModel] | None = None
    writes: bool = False  # sandbox_write: changes files -> needs a matching Approval (G3.3)


def _spec(name: str, target: str, agents: set[str], args: str | None = None, writes: bool = False) -> ToolSpec:
    model = None
    if args:
        module, cls = args.split(":")
        model = getattr(importlib.import_module(module), cls)
    return ToolSpec(name, target, frozenset(agents), model, writes)


def _tool_specs() -> dict[str, ToolSpec]:
    specs = [
        _spec("resolve_action_sha", "guardian.tools.patching:resolve_action_sha", {"remediation"},
              "guardian.tools.patching:ActionRefArgs"),
        _spec("resolve_image_digest", "guardian.tools.patching:resolve_image_digest", {"remediation"},
              "guardian.tools.patching:ImageArgs"),
        _spec("plan_preview", "guardian.tools.patching:plan_preview", {"remediation"},
              "guardian.tools.patching:PlanArgs"),
        _spec("registry_metadata", "guardian.tools.investigate:registry_metadata", {"investigator"},
              "guardian.tools.investigate:RegistryMetadataArgs"),
        _spec("file_excerpt", "guardian.tools.investigate:file_excerpt", {"investigator"},
              "guardian.tools.investigate:FileExcerptArgs"),
        _spec("manifest_diff", "guardian.tools.investigate:manifest_diff", {"investigator"}),
        _spec("threat_intel", "guardian.tools.risk_tools:threat_intel", {"risk_analyst"},
              "guardian.tools.risk_tools:ThreatIntelArgs"),
        _spec("reachability", "guardian.tools.risk_tools:reachability", {"risk_analyst"},
              "guardian.tools.risk_tools:PackagesArgs"),
        _spec("exposure_signals", "guardian.tools.risk_tools:exposure_signals", {"risk_analyst"},
              "guardian.tools.risk_tools:PackagesArgs"),
        _spec("package_scope", "guardian.tools.risk_tools:package_scope", {"risk_analyst"},
              "guardian.tools.risk_tools:PurlsArgs"),
        _spec("provenance_signals", "guardian.tools.risk_tools:provenance_signals", {"risk_analyst"},
              "guardian.tools.risk_tools:PurlsArgs"),
        _spec("safe_version_lookup", "guardian.tools.risk_tools:safe_version_lookup", {"remediation"},
              "guardian.tools.risk_tools:SafeVersionArgs"),
        _spec("compat_hint", "guardian.tools.risk_tools:compat_hint", {"remediation"},
              "guardian.tools.risk_tools:CompatArgs"),
        _spec("apply_plan", "guardian.tools.patching:apply_plan", {"validator"},
              "guardian.tools.patching:PlanArgs", writes=True),
        _spec("sandbox_validate", "guardian.tools.sandbox:sandbox_validate", {"validator"}),
        _spec("rescan_patched", "guardian.tools.sandbox:rescan_patched", {"validator"}),
        _spec("local_fix_branch", "guardian.tools.local_pr:local_fix_branch", {"validator"},
              "guardian.tools.local_pr:BranchArgs", writes=True),
    ]
    for s in specs:
        assert not any(w in s.name for w in FORBIDDEN_WORDS), s.name  # G3.4
    return {s.name: s for s in specs}


# Detectors the validator re-runs on the patched copy (C4: non-CVE fixes are verified by their detector).
EXTRA_ALLOW: dict[str, set[str]] = {
    "validator": {"detector:lockfile", "detector:typosquat", "detector:ci_pin", "detector:image_pin",
                  "detector:install_scripts", "policy_check",
                  # re-resolve the patched copy's lockfiles (--ignore-scripts) so the rescan sees the upgrade
                  "resolve_lockfiles"},
}
FORBIDDEN_WORDS = ("publish", "push", "merge", "deploy")  # G3.4
_SPECS: dict[str, ToolSpec] | None = None


def tool_specs() -> dict[str, ToolSpec]:
    global _SPECS
    if _SPECS is None:
        _SPECS = _tool_specs()
    return _SPECS


def allowed_tools(agent: str) -> set[str]:
    names = {n for n, _ in BINDINGS.get(agent, [])} | EXTRA_ALLOW.get(agent, set())
    return names | {s.name for s in tool_specs().values() if agent in s.agents}


def target_of(name: str) -> str | None:
    for binding in BINDINGS.values():
        for n, t in binding:
            if n == name:
                return t
    spec = tool_specs().get(name)
    return spec.target if spec else None

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


def _block(audit: AuditLog, agent: str, name: str, rule: str, reason: str) -> None:
    audit.emit("guardrail", "guardrail", f"{rule} blocked {name} for {agent}: {reason}",
               data={"rule": rule, "tool": name, "agent": agent, "reason": reason[:300]})


def call_tool(agent: str, name: str, target: str | None, ctx: ToolContext, store: JsonStore, audit: AuditLog,
              *, args: dict | BaseModel | None = None, plan: RemediationPlan | None = None,
              approval: Approval | None = None) -> ToolOutput | None:
    """Run one tool through the G3 guardrails. Blocked, unavailable or failing tools are logged and return
    None (the pipeline continues)."""
    if any(w in name.lower() for w in FORBIDDEN_WORDS):
        _block(audit, agent, name, "G3.4", "publish/push/merge/deploy tools do not exist")
        return None
    if name not in allowed_tools(agent):
        _block(audit, agent, name, "G3.1", "not in this agent's tool allowlist")
        return None
    target = target or target_of(name)
    spec = tool_specs().get(name)
    parsed = None
    if spec and spec.args_model is not None:
        try:
            parsed = args if isinstance(args, spec.args_model) else spec.args_model.model_validate(args or {})
        except ValidationError as exc:
            _block(audit, agent, name, "G3.2", f"invalid args: {exc.errors()[0].get('msg', exc)}")
            return None
    elif args is not None:
        _block(audit, agent, name, "G3.2", "tool takes no arguments")
        return None
    if spec and spec.writes:
        reason = check_write(plan, approval)
        if reason:
            _block(audit, agent, name, "G3.3", reason)
            return None
    if ctx.budget is not None:
        reason = ctx.budget.charge_tool(agent)
        if reason:
            _block(audit, agent, name, "G3.6", f"budget exhausted ({reason})")
            return None
    try:
        if target is None:
            raise ToolUnavailable(f"{name} has no binding")
        fn = resolve(target)
    except ToolUnavailable as exc:
        audit.emit(agent, "error", f"tool {name} unavailable: {exc}", data={"tool": name})
        return None

    extra = {"args": parsed.model_dump(mode="json")} if parsed is not None else {}
    audit.emit(agent, "tool_call", f"{name}", data={"tool": name, "target": target, **extra})
    t0 = time.monotonic()
    try:
        out = fn(ctx, parsed) if parsed is not None else fn(ctx)
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
