"""Guardian data model (GUARDIAN_PLAN.md §5.1). Owner: Dev1.

Contract file: changes are additive only and must be announced (§9.4).
Additions beyond §5.1 are marked `# ADDITIVE (Dev1)`.

Every agent, tool, the store, the API and the UI read these pydantic models, so they are the shared vocabulary of
a run. How they relate, in pipeline order:

    Evidence      what a tool observed (immutable; the only thing LLM claims are checked against, G4)
    Finding       a problem found by a detector/scanner, citing >= 1 Evidence
    Claim         one checkable statement about a finding; `label` is set by grounding code, never by an LLM
    RiskAssessment  the scored priority of a finding (factors S/E/R/P/X, see core/scoring.py)
    RemediationPlan  what to change (ops), hashed so an approval binds to exactly this plan (G5.1)
    Approval      the human decision on one plan (G5.2: reject / accept_risk need a comment)
    ValidationResult  what happened when an approved plan was applied in the sandbox and re-scanned

Ids are prefixed ULIDs (`ev_`, `fd_`, ...): unique, sortable by creation time, readable in logs.
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
    """`<prefix>_<ULID>`, e.g. new_id("fd") -> "fd_01J...": the id format of evidence, findings, plans ..."""
    return f"{prefix}_{new_ulid()}"


def utcnow() -> datetime:
    """Timezone-aware current UTC time; every timestamp in a run uses this so ordering is unambiguous."""
    return datetime.now(UTC)


# ---------------------------------------------------------------- enums


class Priority(str, Enum):
    """Risk band of a finding (initial rule/LLM risk and the final scored band share it)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(str, Enum):
    """How much to trust a score: drops with every risk factor that had to be assumed (see scoring.compute)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ClaimLabel(str, Enum):
    """Grounding result for a claim, set in code (guardrails/grounding.py, G4.3):
    VERIFIED = field/value matches a fact of the cited evidence; INFERRED = plausible but not matched exactly,
    shown to users as "AI interpretation"; UNSUPPORTED = no evidence, removed from what is kept (G4.6)."""

    VERIFIED = "verified"
    INFERRED = "inferred"
    UNSUPPORTED = "unsupported"


class FindingStatus(str, Enum):
    """Where a finding stands in the pipeline: open -> assessed (analyst) -> planned -> awaiting_human ->
    validating -> verified. ACCEPTED = the human accepted the risk; ESCALATED = needs a person (no safe plan, or
    G5.4 attempt limit, or LLM output invalid after repair); BELOW_THRESHOLD = scored too low to remediate."""

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
    """Factor R: is the vulnerable package actually used by the code? (called > imported > not_imported.)"""

    CALLED = "called"
    IMPORTED = "imported"
    NOT_IMPORTED = "not_imported"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"  # CI/lockfile/image findings


class Scope(str, Enum):
    """Does the component ship to production (`prod`) or only run in development/test tooling (`dev`)?"""

    PROD = "prod"
    DEV = "dev"
    UNKNOWN = "unknown"


class FindingCategory(str, Enum):
    """What kind of problem a finding is. CVE comes from the vulnerability scanner; the rest from the
    detectors (supply-chain heuristics, CI/image/lockfile hygiene). Heuristic ones (typosquat, malicious
    indicator) may only be remediated by replace/remove/block/escalate (G5.3)."""

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
    """The ONLY thing grounding checks against. Created by tools, never by an LLM.

    `facts` is the machine-readable payload (flattened and compared by guardrails/grounding.py); `excerpt` is
    a short human-readable snippet; `artifact_path`+`sha256` point to a larger file under the run directory
    (log, diff) and prove it was not changed afterwards."""

    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    run_id: str
    kind: str  # sbom|graph|scanner_output|file_excerpt|registry_metadata|epss|kev|osv|diff|changes|
    # patch_diff|build_log|test_result|sbom_diff|policy_result|provenance|
    # reachability|exposure|compat_hint|detector_result
    source_tool: str  # "grype@x.y", "detector:ci_pin": which tool (and version) observed this
    created_at: datetime = Field(default_factory=utcnow)
    facts: dict[str, Any] = {}
    excerpt: str | None = None
    file_path: str | None = None
    line: int | None = None
    artifact_path: str | None = None
    sha256: str | None = None


class AgentEvent(BaseModel):
    """One line of trace.jsonl: a step an agent took, shown in the UI trace list and (for some types) audited.

    `agent` is who acted, `type` is what kind of step it was (a decision of the supervisor, a guardrail hit, a
    gate wait ...); `finding_id` / `evidence_ids` link the step to what it concerned."""

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
    """Supply-chain provenance of a package, as verified by tools (None = not checked, which is not the same
    as False). `signature_verified` / `attestation_present` come from registry signature checks; `origin` and
    `integrity` are the lockfile's resolved URL and hash. Evidence ids say which tool output backs each value.
    A failed provenance check adds a flat +5 points to the risk score (scoring.PROVENANCE_BONUS)."""

    origin: str | None = None
    integrity: str | None = None
    signature_verified: bool | None = None
    attestation_present: bool | None = None
    repository_url: str | None = None
    evidence_ids: list[str] = []


class Claim(BaseModel):
    """Structured, checkable statement. `label` is set by grounding code, never by the LLM.

    `field`/`value` is the part that can be machine-checked ("fixed_version" = "4.17.21") against the facts of
    the cited `evidence_ids`; `text` is the free-form sentence shown to the user."""

    text: str
    field: str | None = None
    value: str | None = None
    evidence_ids: list[str] = []
    label: ClaimLabel


class Finding(BaseModel):
    """One problem in the analysed project. Created by a detector/scanner with its evidence, then enriched by the
    evidence analyst (explanation, claims, initial risk) and updated as it moves through remediation.
    Findings are never deleted, only their status/analysis changes."""

    finding_id: str = Field(default_factory=lambda: new_id("fd"))
    run_id: str
    category: FindingCategory
    title: str
    detector: str
    component_purl: str | None = None  # package URL of the affected component; the graph node id
    scope: Scope = Scope.UNKNOWN
    project: str | None = None  # which project root (monorepo) the finding belongs to
    file_path: str | None = None
    line: int | None = None
    dependency_paths: list[list[str]] = []  # root -> ... -> component chains from the graph (how it is pulled in)
    vuln_id: str | None = None  # primary advisory id (CVE-... or GHSA-...)
    aliases: list[str] = []  # other ids for the same advisory (CVE <-> GHSA); grounding treats them as known
    cvss: float | None = None
    severity: str | None = None
    fixed_versions: list[str] = []  # versions the scanner says fix the issue; the remediation candidates start here
    affected_range: str | None = None
    provenance: Provenance | None = None
    initial_risk: Priority | None = None  # first-pass band (rule in scoring.initial_risk, or the analyst LLM)
    evidence_ids: list[str] = Field(min_length=1)  # a Finding without evidence raises
    status: FindingStatus = FindingStatus.OPEN
    # ADDITIVE (Dev1): evidence analyst output, shown in the findings list (CP1 DoD "LLM explanation labelled")
    explanation: str | None = None
    claims: list[Claim] = []
    initial_risk_source: str | None = None  # "llm" | "rule"


class FactorValue(BaseModel):
    """One scored risk factor: `value` in 0..1, the named `tier` it came from (e.g. "kev", "called", "prod"),
    and whether it had to be assumed (`unknown=True`: no evidence, a neutral default was used, which lowers the
    assessment's confidence). `label` says whether evidence backs it (VERIFIED) or not (INFERRED)."""

    value: float
    tier: str
    unknown: bool = False
    label: ClaimLabel
    evidence_ids: list[str] = []


class RiskFactors(BaseModel):
    """The five inputs of the risk score (weights and formula: core/scoring.py).
    S severity of the issue, E exploitability (EPSS/KEV), R reachability of the code, P production scope,
    X network exposure. `provenance_modifier` is a score adjustment in points (not a factor)."""

    S: FactorValue
    E: FactorValue
    R: FactorValue
    P: FactorValue
    X: FactorValue
    provenance_modifier: float = 0.0
    provenance_evidence_ids: list[str] = []


class RiskAssessment(BaseModel):
    """The scored risk of one finding (an entry of risk.json). Recomputable from `factors` alone."""

    finding_id: str
    score: float  # 0..100
    band: Priority
    confidence: Confidence
    override_applied: str | None = None  # name of a rule that raised the band (e.g. "kev_reachable_prod")
    factors: RiskFactors
    summary: str
    claims: list[Claim] = []


class PatchOp(BaseModel):
    """One concrete edit of a plan, executed on a fresh copy of the target by tools/patching.py.
    `args` depends on `op` (e.g. package name + new version); `file_path` is relative to the project root and
    confined to the copy (G6.6)."""

    op: str  # set_dependency_version | remove_dependency | replace_dependency
    # | pin_action_sha | pin_image_digest | generate_lockfile | update_base_image | block_package
    file_path: str
    args: dict[str, Any]


class CompatHint(BaseModel):
    """Compatibility signals for an upgrade, computed by a tool from registry metadata (not by an LLM): the
    semver step, whether the new version's engines/peer dependencies still fit, and an overall `level` of
    breaking-change risk. Shown to the reviewer next to the plan."""

    from_version: str
    to_version: str
    semver_delta: str  # major|minor|patch|none|unknown
    engines_ok: bool | None = None
    peer_dep_changes: list[str] = []
    deprecated_target: bool | None = None
    level: str  # low|medium|high


class RemediationPlan(BaseModel):
    """A proposed fix for one finding. Immutable once written: `plan_hash` is a SHA-256 over all other fields
    (guardrails/approval.plan_hash), so an Approval for this hash cannot be reused on an edited plan (G5.1).
    The plan changes nothing by itself; ops run only in the validator, only after an `approve` decision."""

    plan_id: str
    plan_hash: str
    finding_id: str
    attempt: int  # 1-based attempt number for this finding (G5.4: at most 3)
    action: str  # upgrade|replace|remove|pin|update_base_image|block|mitigate|escalate
    ops: list[PatchOp] = []  # empty for escalate/mitigate-style plans that change no file
    target_version: str | None = None  # must come from tool evidence (G4.5), never from the LLM alone
    rationale: list[Claim] = []
    expected_risk_reduction: str  # text for the reviewer; the numeric score-after is simulated in code
    compatibility_impact: CompatHint | None = None
    rollback: str  # how to undo the change (it is only applied to a copy, so this is for the merge step)
    evidence_ids: list[str] = Field(min_length=1)


class Approval(BaseModel):
    """A human decision on one plan. `plan_hash` must equal the plan's current hash or the decision is refused
    (G5.1). `decided_by` is the authenticated approver's name recorded in approvals.jsonl."""

    plan_id: str
    plan_hash: str
    decision: str  # approve|reject|accept_risk
    comment: str | None = None
    reason_type: str | None = None  # ADDITIVE: why a fix was rejected (too_big|breaks_app|different_approach|other)
    decided_by: str
    ts: datetime = Field(default_factory=utcnow)


class ValidationResult(BaseModel):
    """Outcome of applying one approved plan to a fresh copy, building/testing it in the sandbox and re-scanning.
    `verdict` says why it passed or failed; `target_finding_resolved` and `new_findings` show whether the fix
    worked without introducing new problems; `risk_before`/`risk_after` are scores before and after the change."""

    attempt_id: str
    plan_id: str
    finding_id: str
    build_ok: bool | None  # ADDITIVE (Dev1): None = build not run (Day-1 validator: detectors only)
    unit_tests: dict[str, int] = {}  # counts such as {"passed": n, "failed": m}; empty when the suite did not run
    integration_tests: dict[str, int] = {}
    artifact_rescanned: str | None = None  # image tag of the built artifact that was re-scanned (G6.7), if any
    target_finding_resolved: bool
    new_findings: list[str] = []
    sbom_diff_evidence_id: str | None = None
    detector_evidence_ids: list[str] = []
    risk_before: float
    risk_after: float
    verdict: str  # verified|failed_build|failed_tests|regressed|not_resolved|timeout|still_imported|mitigated
    final_confidence: Confidence
    log_evidence_ids: list[str] = []
    combined: bool = False  # ADDITIVE (batch mode): validated together with other approved plans in one attempt
    round: int | None = None  # ADDITIVE (batch mode): remediation round this validation belongs to
    # ADDITIVE: why a plan failed when the verdict alone does not say (e.g. which file still imports a removed package)
    reason: str | None = None
    # ADDITIVE: True when `verdict` is the SHARED failure of a run of several plans that could not be blamed on this one
    # plan yet; a later result for the same plan (a smaller group, or alone) is what says whether it is at fault
    group_failure: bool = False
