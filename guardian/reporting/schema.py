"""Guardian report schema (D4-06): `report.json` must validate against `Report` (docs/day2_contracts.md)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from guardian.core.models import (
    AgentEvent,
    Approval,
    Evidence,
    Finding,
    RemediationPlan,
    RiskAssessment,
    ValidationResult,
)


class Inventory(BaseModel):
    components: int = 0
    direct: int = 0
    transitive: int = 0


class ReportFinding(BaseModel):
    finding: Finding
    risk: RiskAssessment | None = None
    evidence: list[Evidence] = []  # excerpt truncated to 2000 chars
    paths: list[list[str]] = []


class ReportAction(BaseModel):
    plan: RemediationPlan
    approval: Approval | None = None
    validations: list[ValidationResult] = []


class RemainingRisk(BaseModel):
    finding_id: str
    status: str  # accepted|escalated|assessed|...
    score: float = 0


class Audit(BaseModel):
    events: int = 0
    llm_calls: int = 0
    tool_calls: int = 0


class Report(BaseModel):
    run_id: str
    target: str | None = None
    commit: str | None = None
    generated_at: str
    summary: dict[str, Any] = {}
    inventory: Inventory = Inventory()
    findings: list[ReportFinding] = []
    ranking: list[str] = []
    actions: list[ReportAction] = []
    remaining_risk: list[RemainingRisk] = []
    final_confidence: str = "low"  # high|medium|low
    guardrail_events: list[AgentEvent] = []
    audit: Audit = Audit()
