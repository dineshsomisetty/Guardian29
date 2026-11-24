"""Guardian report schema (D4-06): `report.json` must validate against `Report` (docs/day2_contracts.md).

Pydantic models only, no logic. `build_report` (build.py) fills a `Report`, `write_reports` (render.py) dumps it
to report.json and feeds the HTML template, and the UI/API read that JSON back. Fields marked ADDITIVE were
added after the contract was first agreed and are optional, so older readers keep working.
"""
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
    """Size of the dependency inventory (SBOM): all components, and how many are direct vs transitive."""

    components: int = 0
    direct: int = 0
    transitive: int = 0


class ReportFinding(BaseModel):
    """One finding with everything needed to read it alone: its risk assessment, evidence and dependency paths."""

    finding: Finding
    risk: RiskAssessment | None = None
    evidence: list[Evidence] = []  # excerpt truncated to 2000 chars
    paths: list[list[str]] = []  # dependency chains root -> ... -> vulnerable package


class ReportAction(BaseModel):
    """One remediation plan with the human decision on it and the validation attempts that tested it."""

    plan: RemediationPlan
    approval: Approval | None = None
    validations: list[ValidationResult] = []
    pr_markdown: str | None = None  # ADDITIVE (D2-10): run-relative path of PR.md for a verified attempt


class RemainingRisk(BaseModel):
    """A finding still not fixed at the end of the run (rejected, accepted risk, no fix found, unverified)."""

    finding_id: str
    status: str  # accepted|escalated|assessed|...
    score: float = 0
    note: str | None = None  # ADDITIVE: e.g. an accepted mitigation (nothing was fixed)


class Audit(BaseModel):
    """Counters taken from trace.jsonl: how much the agents did (events, model calls, tool calls)."""

    events: int = 0
    llm_calls: int = 0
    tool_calls: int = 0


# ---- ADDITIVE: plain-language sections (built by reporting/narrative.py; all optional so old report.json files load)

class ReportCounts(BaseModel):
    """How the findings split: by risk level, and by what became of them (the four states add up to `total`)."""

    total: int = 0
    by_level: dict[str, int] = {}
    fixed: int = 0  # a fix was built, tested and verified
    accepted: int = 0  # a person accepted the risk
    open: int = 0  # not fixed, not accepted
    needs_person: int = 0  # Guardian has no safe automatic option
    awaiting_decision: int = 0  # ADDITIVE: suggested fixes still waiting for a person (a subset of `open`, not a fifth state)
    awaiting_decision: int = 0  # ADDITIVE: suggested fixes still waiting for a person (a subset of `open`, not a fifth state)


class ReportOverview(BaseModel):
    """The summary at the top: what was scanned, the one-sentence verdict, counts and the confidence with its limits."""

    target: str | None = None
    commit: str | None = None
    status: str | None = None
    scanned_at: str | None = None
    generated_at: str | None = None
    packages: dict[str, int] = {}  # components / direct / transitive
    verdict: str = ""
    counts: ReportCounts = ReportCounts()
    confidence: str = "low"
    confidence_limits: list[str] = []
    key_points: list[str] = []  # ADDITIVE: the few things a reader should know first, in plain sentences
    key_points: list[str] = []  # ADDITIVE: the three or four things a reader should know first, in plain sentences


class ReportFix(BaseModel):
    """One verified fix in plain words: what it changes, what it resolves, how it was checked, where it lives."""

    title: str
    plan_id: str
    attempt_id: str | None = None
    finding_ids: list[str] = []
    finding_count: int = 0
    top_titles: list[str] = []
    level: str = "unscored"
    primary_finding_id: str | None = None
    checks: list[str] = []
    tested_with: list[str] = []  # titles of the other fixes validated in the same attempt
    score_before: float | None = None  # highest-scored finding the fix covers, before / after the re-scan
    score_after: float | None = None
    location: str = ""
    branch: str | None = None
    pr_markdown: str | None = None
    approved_by: str | None = None


class ReportDecision(BaseModel):
    """One decision a person took on a fix (approve / reject / accept risk), with the reason and what followed."""

    plan_id: str
    finding_id: str | None = None
    what: str = ""
    finding_count: int = 1
    decision: str
    reason_type: str | None = None
    reason_text: str | None = None
    comment: str | None = None
    decided_by: str = ""
    decided_at: str = ""
    result: str = ""
    plan_hash: str | None = None  # ADDITIVE: hash of the plan the person saw; the decision is bound to exactly this content
    plan_hash_ok: bool | None = None  # True when it equals the plan's current hash (None: plan file missing)
    plan_hash: str | None = None  # ADDITIVE: hash of the plan the person saw; the decision is bound to exactly this content
    plan_hash_ok: bool | None = None  # True when it equals the plan's current hash (None: plan file missing)


class OpenGroup(BaseModel):
    """Open findings of one package, grouped: worst level and score, how many, and the next step."""

    package: str
    level: str = "unscored"
    score: float = 0
    count: int = 0
    next_step: str = ""
    finding_ids: list[str] = []
    titles: list[str] = []


class AttentionItem(BaseModel):
    """An accepted risk (kind "accepted") or something only a person can settle (kind "needs_person"), with the reason."""

    kind: str
    title: str
    level: str = "unscored"
    score: float = 0
    finding_ids: list[str] = []
    finding_count: int = 1
    top_titles: list[str] = []
    plan_id: str | None = None
    reason: str = ""
    decided_by: str | None = None
    decided_at: str | None = None
    note: str | None = None


class ScoreGuide(BaseModel):
    """How to read the 0-100 score: factor weights (read from core/scoring.py at build time), names, level ranges."""

    weights: dict[str, float] = {}
    factor_names: dict[str, str] = {}
    factor_help: dict[str, str] = {}
    bands: dict[str, str] = {}
    notes: list[str] = []


class ReportMethod(BaseModel):
    """What ran, how AI was used, what was not checked and which guardrails applied."""

    ran: list[str] = []
    ai: list[str] = []
    not_checked: list[str] = []
    guardrails: list[str] = []
    ai_mode: str | None = None
    ai_model: str | None = None


class AppendixRow(BaseModel):
    """One line of the full findings table; carries the technical ids."""

    finding_id: str
    level: str = "unscored"
    score: float = 0
    title: str = ""
    package: str = ""
    kind: str = ""
    state: str = "open"  # fixed|accepted|needs_person|open
    status: str = ""
    advisory_severity: str | None = None
    plan_ids: list[str] = []


class FactorRow(BaseModel):
    """One line of a finding's score table: factor, value 0..1, weight, points it adds, and whether evidence backs it."""

    key: str  # S|E|R|P|X
    name: str
    value: float
    tier: str  # why that value, e.g. "called", "kev"
    assumed: bool = False  # no evidence: a neutral default was used (lowers confidence)
    label: str = "inferred"  # verified|inferred
    weight: float = 0.0
    points: float = 0.0  # 100 * weight * value


class ReportClaim(BaseModel):
    """A statement kept in the report with its grounding label (verified = matches cited evidence, inferred = AI reading)."""

    text: str
    label: str
    evidence_ids: list[str] = []


class RankedFinding(BaseModel):
    """One row of the risk ranking with everything needed to recompute its score and read what to do about it."""

    rank: int
    finding_id: str
    title: str
    package: str = ""
    version: str | None = None
    kind: str = ""
    level: str = "unscored"
    score: float = 0
    confidence: str = "low"
    state: str = "open"  # fixed|accepted|needs_person|open
    status: str = ""
    summary: str = ""
    factors: list[FactorRow] = []
    provenance_points: float = 0  # added to the sum of factor points (failed provenance check)
    override: str | None = None
    recomputed_score: float | None = None  # sum of points + provenance, capped at 100
    score_matches: bool | None = None
    action: str = ""  # recommended action in plain words
    decision: str = ""  # what a person decided about it, or that nothing was decided yet
    paths: list[list[str]] = []  # dependency chains, root first, readable names (at most 3)
    path_count: int = 0
    claims: list[ReportClaim] = []
    evidence_ids: list[str] = []


class TestRun(BaseModel):
    """One sandbox phase / container of a validation: install, build, unit tests, an integration shard."""

    name: str  # install | build | test | integration | integration-2 ...
    label: str = ""  # "Integration tests (shard 2)"
    command: str = ""  # what ran inside the container (`sh -c` script), redacted; "" for older evidence
    network: str = "none"
    seconds: float = 0
    exit_code: int | None = None
    timed_out: bool = False
    result: str = ""  # "passed" | "failed (exit 1)" | "timed out"
    tests: str = ""  # "437 of 441 pass, 4 fail" when the output had a summary
    failing: list[str] = []  # failing test names parsed from this phase's output
    output_tail: str = ""  # last lines of output (redacted)
    log: str | None = None  # run-relative path of the full redacted log, when saved


class ReportValidation(BaseModel):
    """One validation attempt (every attempt, passed or failed): build, tests, re-scan, new findings, SBOM diff."""

    attempt_id: str
    plan_id: str
    finding_id: str
    title: str = ""  # the fix in plain words
    verdict: str = ""
    verdict_text: str = ""
    passed: bool = False
    group_failure: bool = False  # shared failure of a group run: not yet blamed on this fix
    build: str = ""  # passed | failed | not run
    unit_tests: str = ""
    integration_tests: str = ""
    baseline_note: str = ""
    resolved: bool = False
    new_findings: list[str] = []  # what the fix introduced, in words
    risk_before: float = 0
    risk_after: float = 0
    confidence: str = "low"
    combined: bool = False
    round: int | None = None
    sbom_added: list[str] = []
    sbom_removed: list[str] = []
    sbom_changed: list[str] = []  # "name: from -> to"
    sbom_components: list[int] = []  # [before, after] or []
    image_rescanned: str | None = None
    # ADDITIVE: what actually ran in the sandbox, phase by phase, and which tests failed (and why that matters)
    test_runs: list[TestRun] = []
    newly_failing: list[str] = []  # tests that pass on the unchanged project but fail with the fix
    expected_failures: list[str] = []  # newly failing tests that assert an attack works: expected once it is fixed
    already_failing: list[str] = []  # failed on the unchanged project too: not caused by the fix
    sandbox_notes: list[str] = []  # e.g. integration suite split over N containers, suites not runnable


class BeforeAfter(BaseModel):
    """Run-wide comparison: findings by level before the run and after verified fixes only, SBOM and new findings."""

    levels_before: dict[str, int] = {}
    levels_after: dict[str, int] = {}
    top_before: float = 0
    top_after: float = 0
    fixed: int = 0
    sbom_components: list[int] = []  # [before, after] over the verified attempts, else []
    sbom_added: int = 0
    sbom_removed: int = 0
    sbom_changed: int = 0
    new_findings: list[str] = []  # introduced by any validation attempt
    note: str = ""


class GuardrailRow(BaseModel):
    """A safety rule that fired during the run, in words (rule code kept for reference, e.g. G4.6)."""

    rule: str
    agent: str
    text: str
    ts: str = ""
    finding_id: str | None = None


class AuditRow(BaseModel):
    """One step of the condensed audit trail: a person's decision, a gate wait/resume, an error or a guardrail hit."""

    ts: str = ""
    agent: str
    kind: str
    text: str


class Report(BaseModel):
    """The whole report.json document. `ranking` lists finding ids highest risk first; `findings` holds details."""

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
    # ADDITIVE: the readable report. Older report.json files lack these; readers must fall back to the fields above.
    overview: ReportOverview | None = None
    fixes: list[ReportFix] = []
    decisions: list[ReportDecision] = []
    open_groups: list[OpenGroup] = []
    attention: list[AttentionItem] = []
    score_guide: ScoreGuide | None = None
    method: ReportMethod | None = None
    appendix: list[AppendixRow] = []
    ranked: list[RankedFinding] = []  # ADDITIVE: the risk ranking with factor tables, actions and decisions
    validations: list[ReportValidation] = []  # ADDITIVE: every validation attempt
    before_after: BeforeAfter | None = None
    guardrails_triggered: list[GuardrailRow] = []
    audit_trail: list[AuditRow] = []
    ranked: list[RankedFinding] = []  # ADDITIVE: the risk ranking with factor tables, actions and decisions
    validations: list[ReportValidation] = []  # ADDITIVE: every validation attempt
    before_after: BeforeAfter | None = None
    guardrails_triggered: list[GuardrailRow] = []
    audit_trail: list[AuditRow] = []
