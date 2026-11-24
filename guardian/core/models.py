"""Guardian data model (GUARDIAN_PLAN.md §5.1). Owner: Dev1.

Contract file: changes are additive only and must be announced (§9.4).
Additions beyond §5.1 are marked `# ADDITIVE (Dev1)`.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------- ids

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    """Minimal ULID: 48-bit ms timestamp + 80 random bits, Crockford base32 (26 chars)."""
    value = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    chars = []
    for _ in range(26):
        chars.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_id(prefix: str) -> str:
    return f"{prefix}_{new_ulid()}"


def utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------- enums


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ClaimLabel(str, Enum):
    VERIFIED = "verified"
    INFERRED = "inferred"
    UNSUPPORTED = "unsupported"


class FindingStatus(str, Enum):
    OPEN = "open"
    ASSESSED = "assessed"
    PLANNED = "planned"
    AWAITING_HUMAN = "awaiting_human"
    VALIDATING = "validating"
    VERIFIED = "verified"
    ACCEPTED = "accepted"
    ESCALATED = "escalated"
    BELOW_THRESHOLD = "below_threshold"


class ReachabilityTier(str, Enum):
    CALLED = "called"
    IMPORTED = "imported"
    NOT_IMPORTED = "not_imported"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"  # CI/lockfile/image findings


class Scope(str, Enum):
    PROD = "prod"
    DEV = "dev"
    UNKNOWN = "unknown"


class FindingCategory(str, Enum):
    CVE = "cve"
    TYPOSQUAT = "typosquat"
    INSTALL_SCRIPT = "install_script"
    LOCKFILE = "lockfile"
    UNPINNED_CI = "unpinned_ci"
    UNTRUSTED_IMAGE = "untrusted_image"
    UNEXPECTED_CHANGE = "unexpected_change"
    MALICIOUS_INDICATOR = "malicious_indicator"
    POLICY_VIOLATION = "policy_violation"
    OUTDATED = "outdated"
    INTEGRITY_CHANGE = "integrity_change"
    MAJOR_JUMP = "major_jump"
    PROVENANCE_GAP = "provenance_gap"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    MAINTAINER_CHANGE = "maintainer_change"


# ---------------------------------------------------------------- evidence & trace


class Evidence(BaseModel):
    """The ONLY thing grounding checks against. Created by tools, never by an LLM."""

    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    run_id: str
    kind: str  # sbom|graph|scanner_output|file_excerpt|registry_metadata|epss|kev|osv|diff|changes|
    # patch_diff|build_log|test_result|sbom_diff|policy_result|provenance|
    # reachability|exposure|compat_hint|detector_result
    source_tool: str  # "grype@x.y", "detector:ci_pin"
    created_at: datetime = Field(default_factory=utcnow)
    facts: dict[str, Any] = {}
    excerpt: str | None = None
    file_path: str | None = None
    line: int | None = None
    artifact_path: str | None = None
    sha256: str | None = None


class AgentEvent(BaseModel):
    """One line of trace.jsonl."""

    ts: datetime = Field(default_factory=utcnow)
    run_id: str
    agent: str  # discovery|detection|evidence_analyst|investigator|risk_analyst|
    # remediation|human_gate|validator|reporter|supervisor|guardrail
    type: str  # agent_start|tool_call|tool_result|llm_call|llm_result|handoff|decision|guardrail|
    # gate_wait|gate_resume|agent_end|error
    summary: str
    finding_id: str | None = None
    evidence_ids: list[str] = []
    data: dict[str, Any] = {}  # never contains secrets (G1)


class Provenance(BaseModel):
    origin: str | None = None
    integrity: str | None = None
    signature_verified: bool | None = None
    attestation_present: bool | None = None
    repository_url: str | None = None
    evidence_ids: list[str] = []


class Claim(BaseModel):
    """Structured, checkable statement. `label` is set by grounding code, never by the LLM."""

    text: str
    field: str | None = None
    value: str | None = None
    evidence_ids: list[str] = []
    label: ClaimLabel


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: new_id("fd"))
    run_id: str
    category: FindingCategory
    title: str
    detector: str
    component_purl: str | None = None
    scope: Scope = Scope.UNKNOWN
    project: str | None = None
    file_path: str | None = None
    line: int | None = None
    dependency_paths: list[list[str]] = []
    vuln_id: str | None = None
    aliases: list[str] = []
    cvss: float | None = None
    severity: str | None = None
    fixed_versions: list[str] = []
    affected_range: str | None = None
    provenance: Provenance | None = None
    initial_risk: Priority | None = None
    evidence_ids: list[str] = Field(min_length=1)  # a Finding without evidence raises
    status: FindingStatus = FindingStatus.OPEN
    # ADDITIVE (Dev1): evidence analyst output, shown in the findings list (CP1 DoD "LLM explanation labelled")
    explanation: str | None = None
    claims: list[Claim] = []
    initial_risk_source: str | None = None  # "llm" | "rule"


class FactorValue(BaseModel):
    value: float
    tier: str
    unknown: bool = False
    label: ClaimLabel
    evidence_ids: list[str] = []


class RiskFactors(BaseModel):
    S: FactorValue
    E: FactorValue
    R: FactorValue
    P: FactorValue
    X: FactorValue
    provenance_modifier: float = 0.0
    provenance_evidence_ids: list[str] = []


class RiskAssessment(BaseModel):
    finding_id: str
    score: float
    band: Priority
    confidence: Confidence
    override_applied: str | None = None
    factors: RiskFactors
    summary: str
    claims: list[Claim] = []


class PatchOp(BaseModel):
    op: str  # set_dependency_version | remove_dependency | replace_dependency
    # | pin_action_sha | pin_image_digest | generate_lockfile | update_base_image | block_package
    file_path: str
    args: dict[str, Any]


class CompatHint(BaseModel):
    from_version: str
    to_version: str
    semver_delta: str  # major|minor|patch|none|unknown
    engines_ok: bool | None = None
    peer_dep_changes: list[str] = []
    deprecated_target: bool | None = None
    level: str  # low|medium|high


class RemediationPlan(BaseModel):
    plan_id: str
    plan_hash: str
    finding_id: str
    attempt: int
    action: str  # upgrade|replace|remove|pin|update_base_image|block|mitigate|escalate
    ops: list[PatchOp] = []
    target_version: str | None = None
    rationale: list[Claim] = []
    expected_risk_reduction: str
    compatibility_impact: CompatHint | None = None
    rollback: str
    evidence_ids: list[str] = Field(min_length=1)


class Approval(BaseModel):
    plan_id: str
    plan_hash: str
    decision: str  # approve|reject|accept_risk
    comment: str | None = None
    decided_by: str
    ts: datetime = Field(default_factory=utcnow)


class ValidationResult(BaseModel):
    attempt_id: str
    plan_id: str
    finding_id: str
    build_ok: bool | None  # ADDITIVE (Dev1): None = build not run (Day-1 validator: detectors only)
    unit_tests: dict[str, int] = {}
    integration_tests: dict[str, int] = {}
    artifact_rescanned: str | None = None
    target_finding_resolved: bool
    new_findings: list[str] = []
    sbom_diff_evidence_id: str | None = None
    detector_evidence_ids: list[str] = []
    risk_before: float
    risk_after: float
    verdict: str  # verified|failed_build|failed_tests|regressed|not_resolved|timeout
    final_confidence: Confidence
    log_evidence_ids: list[str] = []
