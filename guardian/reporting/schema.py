# Document the contract for the surrounding module or callable.
"""Guardian report schema (D4-06): `report.json` must validate against `Report` (docs/day2_contracts.md).

Pydantic models only, no logic. `build_report` (build.py) fills a `Report`, `write_reports` (render.py) dumps it
to report.json and feeds the HTML template, and the UI/API read that JSON back. Fields marked ADDITIVE were
added after the contract was first agreed and are optional, so older readers keep working.
"""
# Postpone annotation evaluation for this module.
# Type hints can refer to names before they are resolved at runtime.
from __future__ import annotations

# Import Any from typing.
from typing import Any

# Import BaseModel from pydantic.
from pydantic import BaseModel

# Import AgentEvent, Approval, Evidence, Finding, RemediationPlan, RiskAssessment, ValidationResult from guardian.core.models.
from guardian.core.models import (
    # Supply the next part of the expression started above.
    AgentEvent,
    # Supply the next part of the expression started above.
    Approval,
    # Supply the next part of the expression started above.
    Evidence,
    # Supply the next part of the expression started above.
    Finding,
    # Supply the next part of the expression started above.
    RemediationPlan,
    # Supply the next part of the expression started above.
    RiskAssessment,
    # Supply the next part of the expression started above.
    ValidationResult,
# Close the current expression or collection.
)


# Define Inventory for the report data contract.
# Inherit the class behavior from BaseModel.
class Inventory(BaseModel):
    # Document the contract for the surrounding module or callable.
    """Size of the dependency inventory (SBOM): all components, and how many are direct vs transitive."""

    # Declare components with type int.
    # Use 0 as its initial value.
    components: int = 0
    # Declare direct with type int.
    # Use 0 as its initial value.
    direct: int = 0
    # Declare transitive with type int.
    # Use 0 as its initial value.
    transitive: int = 0


# Define ReportFinding for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportFinding(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One finding with everything needed to read it alone: its risk assessment, evidence and dependency paths."""

    # Declare finding with type Finding.
    # The caller or container supplies the value.
    finding: Finding
    # Declare risk with type RiskAssessment | None.
    # Use None to represent an absent value as its initial value.
    risk: RiskAssessment | None = None
    # Declare evidence with type list[Evidence].
    # Use an ordered collection as its initial value.
    evidence: list[Evidence] = []  # excerpt truncated to 2000 chars
    # Declare paths with type list[list[str]].
    # Use an ordered collection as its initial value.
    paths: list[list[str]] = []  # dependency chains root -> ... -> vulnerable package


# Define ReportAction for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportAction(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One remediation plan with the human decision on it and the validation attempts that tested it."""

    # Declare plan with type RemediationPlan.
    # The caller or container supplies the value.
    plan: RemediationPlan
    # Declare approval with type Approval | None.
    # Use None to represent an absent value as its initial value.
    approval: Approval | None = None
    # Declare validations with type list[ValidationResult].
    # Use an ordered collection as its initial value.
    validations: list[ValidationResult] = []
    # Declare pr_markdown with type str | None.
    # Use None to represent an absent value as its initial value.
    pr_markdown: str | None = None  # ADDITIVE (D2-10): run-relative path of PR.md for a verified attempt


# Define RemainingRisk for the report data contract.
# Inherit the class behavior from BaseModel.
class RemainingRisk(BaseModel):
    # Document the contract for the surrounding module or callable.
    """A finding still not fixed at the end of the run (rejected, accepted risk, no fix found, unverified)."""

    # Declare finding_id with type str.
    # The caller or container supplies the value.
    finding_id: str
    # Declare status with type str.
    # The caller or container supplies the value.
    status: str  # accepted|escalated|assessed|...
    # Declare score with type float.
    # Use 0 as its initial value.
    score: float = 0
    # Declare note with type str | None.
    # Use None to represent an absent value as its initial value.
    note: str | None = None  # ADDITIVE: e.g. an accepted mitigation (nothing was fixed)


# Define Audit for the report data contract.
# Inherit the class behavior from BaseModel.
class Audit(BaseModel):
    # Document the contract for the surrounding module or callable.
    """Counters taken from trace.jsonl: how much the agents did (events, model calls, tool calls)."""

    # Declare events with type int.
    # Use 0 as its initial value.
    events: int = 0
    # Declare llm_calls with type int.
    # Use 0 as its initial value.
    llm_calls: int = 0
    # Declare tool_calls with type int.
    # Use 0 as its initial value.
    tool_calls: int = 0


# ---- ADDITIVE: plain-language sections (built by reporting/narrative.py; all optional so old report.json files load)

# Define ReportCounts for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportCounts(BaseModel):
    # Document the contract for the surrounding module or callable.
    """How the findings split: by risk level, and by what became of them (the four states add up to `total`)."""

    # Declare total with type int.
    # Use 0 as its initial value.
    total: int = 0
    # Declare by_level with type dict[str, int].
    # Use a mapping keyed by the fields below as its initial value.
    by_level: dict[str, int] = {}
    # Declare fixed with type int.
    # Use 0 as its initial value.
    fixed: int = 0  # a fix was built, tested and verified
    # Declare accepted with type int.
    # Use 0 as its initial value.
    accepted: int = 0  # a person accepted the risk
    # Declare open with type int.
    # Use 0 as its initial value.
    open: int = 0  # not fixed, not accepted
    # Declare needs_person with type int.
    # Use 0 as its initial value.
    needs_person: int = 0  # Guardian has no safe automatic option
    # Declare awaiting_decision with type int.
    # Use 0 as its initial value.
    awaiting_decision: int = 0  # ADDITIVE: suggested fixes still waiting for a person (a subset of `open`, not a fifth state)
    # Declare awaiting_decision with type int.
    # Use 0 as its initial value.
    awaiting_decision: int = 0  # ADDITIVE: suggested fixes still waiting for a person (a subset of `open`, not a fifth state)


# Define ReportOverview for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportOverview(BaseModel):
    # Document the contract for the surrounding module or callable.
    """The summary at the top: what was scanned, the one-sentence verdict, counts and the confidence with its limits."""

    # Declare target with type str | None.
    # Use None to represent an absent value as its initial value.
    target: str | None = None
    # Declare commit with type str | None.
    # Use None to represent an absent value as its initial value.
    commit: str | None = None
    # Declare status with type str | None.
    # Use None to represent an absent value as its initial value.
    status: str | None = None
    # Declare scanned_at with type str | None.
    # Use None to represent an absent value as its initial value.
    scanned_at: str | None = None
    # Declare generated_at with type str | None.
    # Use None to represent an absent value as its initial value.
    generated_at: str | None = None
    # Declare packages with type dict[str, int].
    # Use a mapping keyed by the fields below as its initial value.
    packages: dict[str, int] = {}  # components / direct / transitive
    # Declare verdict with type str.
    # Use '' as its initial value.
    verdict: str = ""
    # Declare counts with type ReportCounts.
    # Use the result of ReportCounts as its initial value.
    counts: ReportCounts = ReportCounts()
    # Declare confidence with type str.
    # Use 'low' as its initial value.
    confidence: str = "low"
    # Declare confidence_limits with type list[str].
    # Use an ordered collection as its initial value.
    confidence_limits: list[str] = []
    # Declare key_points with type list[str].
    # Use an ordered collection as its initial value.
    key_points: list[str] = []  # ADDITIVE: the few things a reader should know first, in plain sentences
    # Declare key_points with type list[str].
    # Use an ordered collection as its initial value.
    key_points: list[str] = []  # ADDITIVE: the three or four things a reader should know first, in plain sentences


# Define ReportFix for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportFix(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One verified fix in plain words: what it changes, what it resolves, how it was checked, where it lives."""

    # Declare title with type str.
    # The caller or container supplies the value.
    title: str
    # Declare plan_id with type str.
    # The caller or container supplies the value.
    plan_id: str
    # Declare attempt_id with type str | None.
    # Use None to represent an absent value as its initial value.
    attempt_id: str | None = None
    # Declare finding_ids with type list[str].
    # Use an ordered collection as its initial value.
    finding_ids: list[str] = []
    # Declare finding_count with type int.
    # Use 0 as its initial value.
    finding_count: int = 0
    # Declare top_titles with type list[str].
    # Use an ordered collection as its initial value.
    top_titles: list[str] = []
    # Declare level with type str.
    # Use 'unscored' as its initial value.
    level: str = "unscored"
    # Declare primary_finding_id with type str | None.
    # Use None to represent an absent value as its initial value.
    primary_finding_id: str | None = None
    # Declare checks with type list[str].
    # Use an ordered collection as its initial value.
    checks: list[str] = []
    # Declare tested_with with type list[str].
    # Use an ordered collection as its initial value.
    tested_with: list[str] = []  # titles of the other fixes validated in the same attempt
    # Declare score_before with type float | None.
    # Use None to represent an absent value as its initial value.
    score_before: float | None = None  # highest-scored finding the fix covers, before / after the re-scan
    # Declare score_after with type float | None.
    # Use None to represent an absent value as its initial value.
    score_after: float | None = None
    # Declare location with type str.
    # Use '' as its initial value.
    location: str = ""
    # Declare branch with type str | None.
    # Use None to represent an absent value as its initial value.
    branch: str | None = None
    # Declare pr_markdown with type str | None.
    # Use None to represent an absent value as its initial value.
    pr_markdown: str | None = None
    # Declare approved_by with type str | None.
    # Use None to represent an absent value as its initial value.
    approved_by: str | None = None


# Define ReportDecision for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportDecision(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One decision a person took on a fix (approve / reject / accept risk), with the reason and what followed."""

    # Declare plan_id with type str.
    # The caller or container supplies the value.
    plan_id: str
    # Declare finding_id with type str | None.
    # Use None to represent an absent value as its initial value.
    finding_id: str | None = None
    # Declare what with type str.
    # Use '' as its initial value.
    what: str = ""
    # Declare finding_count with type int.
    # Use 1 as its initial value.
    finding_count: int = 1
    # Declare decision with type str.
    # The caller or container supplies the value.
    decision: str
    # Declare reason_type with type str | None.
    # Use None to represent an absent value as its initial value.
    reason_type: str | None = None
    # Declare reason_text with type str | None.
    # Use None to represent an absent value as its initial value.
    reason_text: str | None = None
    # Declare comment with type str | None.
    # Use None to represent an absent value as its initial value.
    comment: str | None = None
    # Declare decided_by with type str.
    # Use '' as its initial value.
    decided_by: str = ""
    # Declare decided_at with type str.
    # Use '' as its initial value.
    decided_at: str = ""
    # Declare result with type str.
    # Use '' as its initial value.
    result: str = ""
    # Declare plan_hash with type str | None.
    # Use None to represent an absent value as its initial value.
    plan_hash: str | None = None  # ADDITIVE: hash of the plan the person saw; the decision is bound to exactly this content
    # Declare plan_hash_ok with type bool | None.
    # Use None to represent an absent value as its initial value.
    plan_hash_ok: bool | None = None  # True when it equals the plan's current hash (None: plan file missing)
    # Declare plan_hash with type str | None.
    # Use None to represent an absent value as its initial value.
    plan_hash: str | None = None  # ADDITIVE: hash of the plan the person saw; the decision is bound to exactly this content
    # Declare plan_hash_ok with type bool | None.
    # Use None to represent an absent value as its initial value.
    plan_hash_ok: bool | None = None  # True when it equals the plan's current hash (None: plan file missing)


# Define OpenGroup for the report data contract.
# Inherit the class behavior from BaseModel.
class OpenGroup(BaseModel):
    # Document the contract for the surrounding module or callable.
    """Open findings of one package, grouped: worst level and score, how many, and the next step."""

    # Declare package with type str.
    # The caller or container supplies the value.
    package: str
    # Declare level with type str.
    # Use 'unscored' as its initial value.
    level: str = "unscored"
    # Declare score with type float.
    # Use 0 as its initial value.
    score: float = 0
    # Declare count with type int.
    # Use 0 as its initial value.
    count: int = 0
    # Declare next_step with type str.
    # Use '' as its initial value.
    next_step: str = ""
    # Declare finding_ids with type list[str].
    # Use an ordered collection as its initial value.
    finding_ids: list[str] = []
    # Declare titles with type list[str].
    # Use an ordered collection as its initial value.
    titles: list[str] = []


# Define AttentionItem for the report data contract.
# Inherit the class behavior from BaseModel.
class AttentionItem(BaseModel):
    # Document the contract for the surrounding module or callable.
    """An accepted risk (kind "accepted") or something only a person can settle (kind "needs_person"), with the reason."""

    # Declare kind with type str.
    # The caller or container supplies the value.
    kind: str
    # Declare title with type str.
    # The caller or container supplies the value.
    title: str
    # Declare level with type str.
    # Use 'unscored' as its initial value.
    level: str = "unscored"
    # Declare score with type float.
    # Use 0 as its initial value.
    score: float = 0
    # Declare finding_ids with type list[str].
    # Use an ordered collection as its initial value.
    finding_ids: list[str] = []
    # Declare finding_count with type int.
    # Use 1 as its initial value.
    finding_count: int = 1
    # Declare top_titles with type list[str].
    # Use an ordered collection as its initial value.
    top_titles: list[str] = []
    # Declare plan_id with type str | None.
    # Use None to represent an absent value as its initial value.
    plan_id: str | None = None
    # Declare reason with type str.
    # Use '' as its initial value.
    reason: str = ""
    # Declare decided_by with type str | None.
    # Use None to represent an absent value as its initial value.
    decided_by: str | None = None
    # Declare decided_at with type str | None.
    # Use None to represent an absent value as its initial value.
    decided_at: str | None = None
    # Declare note with type str | None.
    # Use None to represent an absent value as its initial value.
    note: str | None = None


# Define ScoreGuide for the report data contract.
# Inherit the class behavior from BaseModel.
class ScoreGuide(BaseModel):
    # Document the contract for the surrounding module or callable.
    """How to read the 0-100 score: factor weights (read from core/scoring.py at build time), names, level ranges."""

    # Declare weights with type dict[str, float].
    # Use a mapping keyed by the fields below as its initial value.
    weights: dict[str, float] = {}
    # Declare factor_names with type dict[str, str].
    # Use a mapping keyed by the fields below as its initial value.
    factor_names: dict[str, str] = {}
    # Declare factor_help with type dict[str, str].
    # Use a mapping keyed by the fields below as its initial value.
    factor_help: dict[str, str] = {}
    # Declare bands with type dict[str, str].
    # Use a mapping keyed by the fields below as its initial value.
    bands: dict[str, str] = {}
    # Declare notes with type list[str].
    # Use an ordered collection as its initial value.
    notes: list[str] = []


# Define ReportMethod for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportMethod(BaseModel):
    # Document the contract for the surrounding module or callable.
    """What ran, how AI was used, what was not checked and which guardrails applied."""

    # Declare ran with type list[str].
    # Use an ordered collection as its initial value.
    ran: list[str] = []
    # Declare ai with type list[str].
    # Use an ordered collection as its initial value.
    ai: list[str] = []
    # Declare not_checked with type list[str].
    # Use an ordered collection as its initial value.
    not_checked: list[str] = []
    # Declare guardrails with type list[str].
    # Use an ordered collection as its initial value.
    guardrails: list[str] = []
    # Declare ai_mode with type str | None.
    # Use None to represent an absent value as its initial value.
    ai_mode: str | None = None
    # Declare ai_model with type str | None.
    # Use None to represent an absent value as its initial value.
    ai_model: str | None = None


# Define AppendixRow for the report data contract.
# Inherit the class behavior from BaseModel.
class AppendixRow(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One line of the full findings table; carries the technical ids."""

    # Declare finding_id with type str.
    # The caller or container supplies the value.
    finding_id: str
    # Declare level with type str.
    # Use 'unscored' as its initial value.
    level: str = "unscored"
    # Declare score with type float.
    # Use 0 as its initial value.
    score: float = 0
    # Declare title with type str.
    # Use '' as its initial value.
    title: str = ""
    # Declare package with type str.
    # Use '' as its initial value.
    package: str = ""
    # Declare kind with type str.
    # Use '' as its initial value.
    kind: str = ""
    # Declare state with type str.
    # Use 'open' as its initial value.
    state: str = "open"  # fixed|accepted|needs_person|open
    # Declare status with type str.
    # Use '' as its initial value.
    status: str = ""
    # Declare advisory_severity with type str | None.
    # Use None to represent an absent value as its initial value.
    advisory_severity: str | None = None
    # Declare plan_ids with type list[str].
    # Use an ordered collection as its initial value.
    plan_ids: list[str] = []


# Define FactorRow for the report data contract.
# Inherit the class behavior from BaseModel.
class FactorRow(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One line of a finding's score table: factor, value 0..1, weight, points it adds, and whether evidence backs it."""

    # Declare key with type str.
    # The caller or container supplies the value.
    key: str  # S|E|R|P|X
    # Declare name with type str.
    # The caller or container supplies the value.
    name: str
    # Declare value with type float.
    # The caller or container supplies the value.
    value: float
    # Declare tier with type str.
    # The caller or container supplies the value.
    tier: str  # why that value, e.g. "called", "kev"
    # Declare assumed with type bool.
    # Use False as its initial value.
    assumed: bool = False  # no evidence: a neutral default was used (lowers confidence)
    # Declare label with type str.
    # Use 'inferred' as its initial value.
    label: str = "inferred"  # verified|inferred
    # Declare weight with type float.
    # Use 0.0 as its initial value.
    weight: float = 0.0
    # Declare points with type float.
    # Use 0.0 as its initial value.
    points: float = 0.0  # 100 * weight * value


# Define ReportClaim for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportClaim(BaseModel):
    # Document the contract for the surrounding module or callable.
    """A statement kept in the report with its grounding label (verified = matches cited evidence, inferred = AI reading)."""

    # Declare text with type str.
    # The caller or container supplies the value.
    text: str
    # Declare label with type str.
    # The caller or container supplies the value.
    label: str
    # Declare evidence_ids with type list[str].
    # Use an ordered collection as its initial value.
    evidence_ids: list[str] = []


# Define RankedFinding for the report data contract.
# Inherit the class behavior from BaseModel.
class RankedFinding(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One row of the risk ranking with everything needed to recompute its score and read what to do about it."""

    # Declare rank with type int.
    # The caller or container supplies the value.
    rank: int
    # Declare finding_id with type str.
    # The caller or container supplies the value.
    finding_id: str
    # Declare title with type str.
    # The caller or container supplies the value.
    title: str
    # Declare package with type str.
    # Use '' as its initial value.
    package: str = ""
    # Declare version with type str | None.
    # Use None to represent an absent value as its initial value.
    version: str | None = None
    # Declare kind with type str.
    # Use '' as its initial value.
    kind: str = ""
    # Declare level with type str.
    # Use 'unscored' as its initial value.
    level: str = "unscored"
    # Declare score with type float.
    # Use 0 as its initial value.
    score: float = 0
    # Declare confidence with type str.
    # Use 'low' as its initial value.
    confidence: str = "low"
    # Declare state with type str.
    # Use 'open' as its initial value.
    state: str = "open"  # fixed|accepted|needs_person|open
    # Declare status with type str.
    # Use '' as its initial value.
    status: str = ""
    # Declare summary with type str.
    # Use '' as its initial value.
    summary: str = ""
    # Declare factors with type list[FactorRow].
    # Use an ordered collection as its initial value.
    factors: list[FactorRow] = []
    # Declare provenance_points with type float.
    # Use 0 as its initial value.
    provenance_points: float = 0  # added to the sum of factor points (failed provenance check)
    # Declare override with type str | None.
    # Use None to represent an absent value as its initial value.
    override: str | None = None
    # Declare recomputed_score with type float | None.
    # Use None to represent an absent value as its initial value.
    recomputed_score: float | None = None  # sum of points + provenance, capped at 100
    # Declare score_matches with type bool | None.
    # Use None to represent an absent value as its initial value.
    score_matches: bool | None = None
    # Declare action with type str.
    # Use '' as its initial value.
    action: str = ""  # recommended action in plain words
    # Declare decision with type str.
    # Use '' as its initial value.
    decision: str = ""  # what a person decided about it, or that nothing was decided yet
    # Declare paths with type list[list[str]].
    # Use an ordered collection as its initial value.
    paths: list[list[str]] = []  # dependency chains, root first, readable names (at most 3)
    # Declare path_count with type int.
    # Use 0 as its initial value.
    path_count: int = 0
    # Declare claims with type list[ReportClaim].
    # Use an ordered collection as its initial value.
    claims: list[ReportClaim] = []
    # Declare evidence_ids with type list[str].
    # Use an ordered collection as its initial value.
    evidence_ids: list[str] = []


# Define TestRun for the report data contract.
# Inherit the class behavior from BaseModel.
class TestRun(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One sandbox phase / container of a validation: install, build, unit tests, an integration shard."""

    # Declare name with type str.
    # The caller or container supplies the value.
    name: str  # install | build | test | integration | integration-2 ...
    # Declare label with type str.
    # Use '' as its initial value.
    label: str = ""  # "Integration tests (shard 2)"
    # Declare command with type str.
    # Use '' as its initial value.
    command: str = ""  # what ran inside the container (`sh -c` script), redacted; "" for older evidence
    # Declare network with type str.
    # Use 'none' as its initial value.
    network: str = "none"
    # Declare seconds with type float.
    # Use 0 as its initial value.
    seconds: float = 0
    # Declare exit_code with type int | None.
    # Use None to represent an absent value as its initial value.
    exit_code: int | None = None
    # Declare timed_out with type bool.
    # Use False as its initial value.
    timed_out: bool = False
    # Declare result with type str.
    # Use '' as its initial value.
    result: str = ""  # "passed" | "failed (exit 1)" | "timed out"
    # Declare tests with type str.
    # Use '' as its initial value.
    tests: str = ""  # "437 of 441 pass, 4 fail" when the output had a summary
    # Declare failing with type list[str].
    # Use an ordered collection as its initial value.
    failing: list[str] = []  # failing test names parsed from this phase's output
    # Declare output_tail with type str.
    # Use '' as its initial value.
    output_tail: str = ""  # last lines of output (redacted)
    # Declare log with type str | None.
    # Use None to represent an absent value as its initial value.
    log: str | None = None  # run-relative path of the full redacted log, when saved


# Define ReportValidation for the report data contract.
# Inherit the class behavior from BaseModel.
class ReportValidation(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One validation attempt (every attempt, passed or failed): build, tests, re-scan, new findings, SBOM diff."""

    # Declare attempt_id with type str.
    # The caller or container supplies the value.
    attempt_id: str
    # Declare plan_id with type str.
    # The caller or container supplies the value.
    plan_id: str
    # Declare finding_id with type str.
    # The caller or container supplies the value.
    finding_id: str
    # Declare title with type str.
    # Use '' as its initial value.
    title: str = ""  # the fix in plain words
    # Declare verdict with type str.
    # Use '' as its initial value.
    verdict: str = ""
    # Declare verdict_text with type str.
    # Use '' as its initial value.
    verdict_text: str = ""
    # Declare passed with type bool.
    # Use False as its initial value.
    passed: bool = False
    # Declare group_failure with type bool.
    # Use False as its initial value.
    group_failure: bool = False  # shared failure of a group run: not yet blamed on this fix
    # Declare build with type str.
    # Use '' as its initial value.
    build: str = ""  # passed | failed | not run
    # Declare unit_tests with type str.
    # Use '' as its initial value.
    unit_tests: str = ""
    # Declare integration_tests with type str.
    # Use '' as its initial value.
    integration_tests: str = ""
    # Declare baseline_note with type str.
    # Use '' as its initial value.
    baseline_note: str = ""
    # Declare resolved with type bool.
    # Use False as its initial value.
    resolved: bool = False
    # Declare new_findings with type list[str].
    # Use an ordered collection as its initial value.
    new_findings: list[str] = []  # what the fix introduced, in words
    # Declare risk_before with type float.
    # Use 0 as its initial value.
    risk_before: float = 0
    # Declare risk_after with type float.
    # Use 0 as its initial value.
    risk_after: float = 0
    # Declare confidence with type str.
    # Use 'low' as its initial value.
    confidence: str = "low"
    # Declare combined with type bool.
    # Use False as its initial value.
    combined: bool = False
    # Declare round with type int | None.
    # Use None to represent an absent value as its initial value.
    round: int | None = None
    # Declare sbom_added with type list[str].
    # Use an ordered collection as its initial value.
    sbom_added: list[str] = []
    # Declare sbom_removed with type list[str].
    # Use an ordered collection as its initial value.
    sbom_removed: list[str] = []
    # Declare sbom_changed with type list[str].
    # Use an ordered collection as its initial value.
    sbom_changed: list[str] = []  # "name: from -> to"
    # Declare sbom_components with type list[int].
    # Use an ordered collection as its initial value.
    sbom_components: list[int] = []  # [before, after] or []
    # Declare image_rescanned with type str | None.
    # Use None to represent an absent value as its initial value.
    image_rescanned: str | None = None
    # ADDITIVE: what actually ran in the sandbox, phase by phase, and which tests failed (and why that matters)
    # Declare test_runs with type list[TestRun].
    # Use an ordered collection as its initial value.
    test_runs: list[TestRun] = []
    # Declare newly_failing with type list[str].
    # Use an ordered collection as its initial value.
    newly_failing: list[str] = []  # tests that pass on the unchanged project but fail with the fix
    # Declare expected_failures with type list[str].
    # Use an ordered collection as its initial value.
    expected_failures: list[str] = []  # newly failing tests that assert an attack works: expected once it is fixed
    # Declare already_failing with type list[str].
    # Use an ordered collection as its initial value.
    already_failing: list[str] = []  # failed on the unchanged project too: not caused by the fix
    # Declare sandbox_notes with type list[str].
    # Use an ordered collection as its initial value.
    sandbox_notes: list[str] = []  # e.g. integration suite split over N containers, suites not runnable


# Define BeforeAfter for the report data contract.
# Inherit the class behavior from BaseModel.
class BeforeAfter(BaseModel):
    # Document the contract for the surrounding module or callable.
    """Run-wide comparison: findings by level before the run and after verified fixes only, SBOM and new findings."""

    # Declare levels_before with type dict[str, int].
    # Use a mapping keyed by the fields below as its initial value.
    levels_before: dict[str, int] = {}
    # Declare levels_after with type dict[str, int].
    # Use a mapping keyed by the fields below as its initial value.
    levels_after: dict[str, int] = {}
    # Declare top_before with type float.
    # Use 0 as its initial value.
    top_before: float = 0
    # Declare top_after with type float.
    # Use 0 as its initial value.
    top_after: float = 0
    # Declare fixed with type int.
    # Use 0 as its initial value.
    fixed: int = 0
    # Declare sbom_components with type list[int].
    # Use an ordered collection as its initial value.
    sbom_components: list[int] = []  # [before, after] over the verified attempts, else []
    # Declare sbom_added with type int.
    # Use 0 as its initial value.
    sbom_added: int = 0
    # Declare sbom_removed with type int.
    # Use 0 as its initial value.
    sbom_removed: int = 0
    # Declare sbom_changed with type int.
    # Use 0 as its initial value.
    sbom_changed: int = 0
    # Declare new_findings with type list[str].
    # Use an ordered collection as its initial value.
    new_findings: list[str] = []  # introduced by any validation attempt
    # Declare note with type str.
    # Use '' as its initial value.
    note: str = ""


# Define GuardrailRow for the report data contract.
# Inherit the class behavior from BaseModel.
class GuardrailRow(BaseModel):
    # Document the contract for the surrounding module or callable.
    """A safety rule that fired during the run, in words (rule code kept for reference, e.g. G4.6)."""

    # Declare rule with type str.
    # The caller or container supplies the value.
    rule: str
    # Declare agent with type str.
    # The caller or container supplies the value.
    agent: str
    # Declare text with type str.
    # The caller or container supplies the value.
    text: str
    # Declare ts with type str.
    # Use '' as its initial value.
    ts: str = ""
    # Declare finding_id with type str | None.
    # Use None to represent an absent value as its initial value.
    finding_id: str | None = None


# Define AuditRow for the report data contract.
# Inherit the class behavior from BaseModel.
class AuditRow(BaseModel):
    # Document the contract for the surrounding module or callable.
    """One step of the condensed audit trail: a person's decision, a gate wait/resume, an error or a guardrail hit."""

    # Declare ts with type str.
    # Use '' as its initial value.
    ts: str = ""
    # Declare agent with type str.
    # The caller or container supplies the value.
    agent: str
    # Declare kind with type str.
    # The caller or container supplies the value.
    kind: str
    # Declare text with type str.
    # The caller or container supplies the value.
    text: str


# Define Report for the report data contract.
# Inherit the class behavior from BaseModel.
class Report(BaseModel):
    # Document the contract for the surrounding module or callable.
    """The whole report.json document. `ranking` lists finding ids highest risk first; `findings` holds details."""

    # Declare run_id with type str.
    # The caller or container supplies the value.
    run_id: str
    # Declare target with type str | None.
    # Use None to represent an absent value as its initial value.
    target: str | None = None
    # Declare commit with type str | None.
    # Use None to represent an absent value as its initial value.
    commit: str | None = None
    # Declare generated_at with type str.
    # The caller or container supplies the value.
    generated_at: str
    # Declare summary with type dict[str, Any].
    # Use a mapping keyed by the fields below as its initial value.
    summary: dict[str, Any] = {}
    # Declare inventory with type Inventory.
    # Use the result of Inventory as its initial value.
    inventory: Inventory = Inventory()
    # Declare findings with type list[ReportFinding].
    # Use an ordered collection as its initial value.
    findings: list[ReportFinding] = []
    # Declare ranking with type list[str].
    # Use an ordered collection as its initial value.
    ranking: list[str] = []
    # Declare actions with type list[ReportAction].
    # Use an ordered collection as its initial value.
    actions: list[ReportAction] = []
    # Declare remaining_risk with type list[RemainingRisk].
    # Use an ordered collection as its initial value.
    remaining_risk: list[RemainingRisk] = []
    # Declare final_confidence with type str.
    # Use 'low' as its initial value.
    final_confidence: str = "low"  # high|medium|low
    # Declare guardrail_events with type list[AgentEvent].
    # Use an ordered collection as its initial value.
    guardrail_events: list[AgentEvent] = []
    # Declare audit with type Audit.
    # Use the result of Audit as its initial value.
    audit: Audit = Audit()
    # ADDITIVE: the readable report. Older report.json files lack these; readers must fall back to the fields above.
    # Declare overview with type ReportOverview | None.
    # Use None to represent an absent value as its initial value.
    overview: ReportOverview | None = None
    # Declare fixes with type list[ReportFix].
    # Use an ordered collection as its initial value.
    fixes: list[ReportFix] = []
    # Declare decisions with type list[ReportDecision].
    # Use an ordered collection as its initial value.
    decisions: list[ReportDecision] = []
    # Declare open_groups with type list[OpenGroup].
    # Use an ordered collection as its initial value.
    open_groups: list[OpenGroup] = []
    # Declare attention with type list[AttentionItem].
    # Use an ordered collection as its initial value.
    attention: list[AttentionItem] = []
    # Declare score_guide with type ScoreGuide | None.
    # Use None to represent an absent value as its initial value.
    score_guide: ScoreGuide | None = None
    # Declare method with type ReportMethod | None.
    # Use None to represent an absent value as its initial value.
    method: ReportMethod | None = None
    # Declare appendix with type list[AppendixRow].
    # Use an ordered collection as its initial value.
    appendix: list[AppendixRow] = []
    # Declare ranked with type list[RankedFinding].
    # Use an ordered collection as its initial value.
    ranked: list[RankedFinding] = []  # ADDITIVE: the risk ranking with factor tables, actions and decisions
    # Declare validations with type list[ReportValidation].
    # Use an ordered collection as its initial value.
    validations: list[ReportValidation] = []  # ADDITIVE: every validation attempt
    # Declare before_after with type BeforeAfter | None.
    # Use None to represent an absent value as its initial value.
    before_after: BeforeAfter | None = None
    # Declare guardrails_triggered with type list[GuardrailRow].
    # Use an ordered collection as its initial value.
    guardrails_triggered: list[GuardrailRow] = []
    # Declare audit_trail with type list[AuditRow].
    # Use an ordered collection as its initial value.
    audit_trail: list[AuditRow] = []
    # Declare ranked with type list[RankedFinding].
    # Use an ordered collection as its initial value.
    ranked: list[RankedFinding] = []  # ADDITIVE: the risk ranking with factor tables, actions and decisions
    # Declare validations with type list[ReportValidation].
    # Use an ordered collection as its initial value.
    validations: list[ReportValidation] = []  # ADDITIVE: every validation attempt
    # Declare before_after with type BeforeAfter | None.
    # Use None to represent an absent value as its initial value.
    before_after: BeforeAfter | None = None
    # Declare guardrails_triggered with type list[GuardrailRow].
    # Use an ordered collection as its initial value.
    guardrails_triggered: list[GuardrailRow] = []
    # Declare audit_trail with type list[AuditRow].
    # Use an ordered collection as its initial value.
    audit_trail: list[AuditRow] = []
