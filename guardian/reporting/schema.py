"""Guardian Report schema (D4-06). The JSON report must validate against `Report`."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Inventory(BaseModel):
    component_count: int = 0
    direct_count: int = 0
    transitive_count: int = 0
    roots: list[str] = []
    by_ecosystem: dict[str, int] = {}
    vulnerable_paths: list[dict[str, Any]] = []  # [{finding_id, purl, paths: [[purl...]]}]
    changes: dict[str, Any] | None = None  # changes.json as-is


class FindingEntry(BaseModel):
    finding_id: str
    category: str
    title: str
    component_purl: str | None = None
    scope: str = "unknown"
    vuln_id: str | None = None
    severity: str | None = None
    cvss: float | None = None
    fixed_versions: list[str] = []
    affected_range: str | None = None
    dependency_paths: list[list[str]] = []
    initial_risk: str | None = None
    status: str = "open"
    evidence: list[dict[str, Any]] = []  # full Evidence documents, resolved by id
    claims: list[dict[str, Any]] = []    # structured claims with VERIFIED/INFERRED labels


class RankedRisk(BaseModel):
    finding_id: str
    score: float
    priority: str
    confidence: str
    factors: list[dict[str, Any]] = []
    provenance_bonus: int = 0
    override_applied: bool = False


class ActionEntry(BaseModel):
    finding_id: str
    plan_id: str | None = None
    action: str | None = None
    target_version: str | None = None
    rationale: str | None = None
    expected_risk_reduction: str | None = None
    compatibility_impact: str | None = None
    rollback: str | None = None
    approval: dict[str, Any] | None = None  # {decision, by, at, comment}


class ValidationEntry(BaseModel):
    finding_id: str
    attempt: int = 1
    verdict: str | None = None  # verified | failed | regressed
    build_ok: bool | None = None
    unit_tests: dict[str, int] = {}
    integration_tests: dict[str, int] = {}
    target_finding_resolved: bool | None = None
    new_findings: list[str] = []
    risk_before: float | None = None
    risk_after: float | None = None
    sbom_diff: dict[str, Any] = {}
    artifact_rescanned: str | None = None
    final_confidence: str | None = None


class Report(BaseModel):
    schema_version: str = "1.0"
    run_id: str
    target: str | None = None
    generated_at: str
    summary: dict[str, Any] = {}
    inventory: Inventory = Field(default_factory=Inventory)
    findings: list[FindingEntry] = []
    ranking: list[RankedRisk] = []
    actions: list[ActionEntry] = []
    validations: list[ValidationEntry] = []
    remaining_risk: list[dict[str, Any]] = []  # findings not verified, or accepted by a human
    guardrail_events: list[dict[str, Any]] = []
    audit: list[dict[str, Any]] = []
    limitations: list[str] = []
