"""Plain-language sections of the report (summary, fixes, decisions, open groups, score guide, method, appendix).

Owner: Dev1. Called by `build_report` (build.py) with data it already loaded from the run directory; nothing here
reads the network or calls a model. Every function is pure (inputs in, schema objects out) so it can be tested
with small hand-made runs. Internal ids stay in id fields (and the appendix), never in the sentences.

Input: findings, risks, plans, approvals (all decisions, in order), validations, recommendations (batch runs only,
else an empty list), trace events, run summary and the run directory (for PR.md and sandbox_baseline.json).
Output: the additive Report fields defined in schema.py.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import unquote

from guardian.core import scoring
from guardian.core.models import (
    Approval,
    Finding,
    FindingStatus,
    RemediationPlan,
    RiskAssessment,
    ValidationResult,
)
from guardian.core.recs import Recommendation
from guardian.reporting.schema import (
    AppendixRow,
    AttentionItem,
    AuditRow,
    BeforeAfter,
    FactorRow,
    GuardrailRow,
    OpenGroup,
    RankedFinding,
    ReportClaim,
    ReportCounts,
    ReportDecision,
    ReportFix,
    ReportMethod,
    ReportOverview,
    ReportValidation,
    ScoreGuide,
    TestRun,
)

LEVELS = ["critical", "high", "medium", "low"]
CATEGORY_WORD = {
    "cve": "Known vulnerability", "typosquat": "Look-alike package name", "install_script": "Install script",
    "unpinned_ci": "CI step not pinned", "untrusted_image": "Container image not pinned", "lockfile": "No lockfile",
    "unexpected_change": "Unexpected change", "provenance_gap": "Unknown provenance", "policy_violation": "Policy rule broken",
    "maintainer_change": "Maintainer change", "dependency_confusion": "Dependency confusion",
    "malicious_indicator": "Malicious indicator", "integrity_change": "Integrity change", "major_jump": "Major version jump",
    "outdated": "Outdated package",
}
REASON_WORD = {"too_big": "too big a change", "breaks_app": "would break the app",
               "different_approach": "prefers a different approach", "other": "other reason"}
VERDICT_WORD = {"failed_build": "the build failed", "failed_tests": "tests that passed before now fail",
                "regressed": "the fix introduced new problems", "not_resolved": "the problem was still there after the fix",
                "timeout": "a sandbox step ran out of time", "still_imported": "the package is still imported by the source code",
                "mitigated": "risk reduced but the vulnerable code stays"}
FACTOR_NAMES = {"S": "Severity", "E": "Exploitability", "R": "Reachability", "P": "Used in production", "X": "Exposure"}
FACTOR_HELP = {
    "S": "How damaging the flaw is on paper (the advisory's CVSS score, or a fixed value for a kind of problem).",
    "E": "How likely attackers are to use it: exploit probability (EPSS) and the known-exploited list (KEV).",
    "R": "Whether your own code imports or calls the vulnerable package.",
    "P": "Whether the package ships to production or is only a development tool.",
    "X": "Whether the running service can be reached from outside.",
}
_CONF = ["low", "medium", "high"]


# ------------------------------------------------------------------ small helpers

def level_of(f: Finding, risk: RiskAssessment | None) -> str:
    if risk is not None:
        return risk.band.value
    return f.initial_risk.value if f.initial_risk else "unscored"


def package_of(f: Finding) -> str:
    """The package a finding is about (name without version); for findings without one, the file or the kind."""
    p = f.component_purl
    if p:
        body = unquote(p.removeprefix("pkg:").split("?")[0].split("#")[0])
        _, _, rest = body.partition("/")
        name = rest.rsplit("@", 1)[0] if "@" in rest else rest
        if name:
            return name
    word = CATEGORY_WORD.get(f.category.value, f.category.value.replace("_", " ").capitalize())
    return f"{word} ({f.file_path})" if f.file_path else word


def _version_of(f: Finding) -> str | None:
    if f.component_purl and "@" in f.component_purl:
        return unquote(f.component_purl.split("?")[0].rsplit("@", 1)[1])
    return None


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _names(items: list[str], limit: int = 3) -> str:
    items = list(dict.fromkeys(items))
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def _verdict_word(v: str) -> str:
    return VERDICT_WORD.get(v, v.replace("_", " "))


def _strip_no_alt(reason: str) -> str:
    return re.sub(r"^No alternatives?:\s*", "", reason).strip()


# ------------------------------------------------------------------ plain-words title of a fix

def describe_plan(plan: RemediationPlan, finding: Finding | None) -> str:
    """One line a non-specialist can read, e.g. "Replace ngy-cookie with ngx-cookie"."""
    ops = plan.ops
    names = [str(o.args.get("name")) for o in ops if o.op in ("set_dependency_version", "remove_dependency",
                                                              "replace_dependency", "block_package") and o.args.get("name")]
    title = finding.title if finding else "this finding"
    if plan.action == "upgrade" and names:
        ver = plan.target_version or next((str(o.args.get("version")) for o in ops if o.op == "set_dependency_version"), None)
        cur = _version_of(finding) if finding and package_of(finding) == names[0] else None
        out = f"Upgrade {_names(names)}"
        if len(set(names)) == 1 and cur and ver:
            return f"{out} from {cur} to {ver}"
        return f"{out} to {ver}" if ver and len(set(names)) == 1 else out
    if plan.action == "replace" and names:
        new = next((str(o.args.get("new_name")) for o in ops if o.op == "replace_dependency" and o.args.get("new_name")), None)
        return f"Replace {names[0]} with {new}" if new else f"Replace {names[0]}"
    if plan.action == "remove" and names:
        return f"Remove {_names(names)} from the dependencies"
    if plan.action == "block" and names:
        return f"Block {_names(names)} from being installed"
    if plan.action == "pin":
        for o in ops:
            if o.op == "pin_action_sha":
                return f"Pin GitHub Action {o.args.get('action')} ({o.args.get('ref')}) to a fixed commit"
            if o.op == "pin_image_digest":
                return f"Pin base image {o.args.get('image') or o.args.get('name') or ''} to a fixed digest".replace("  ", " ")
            if o.op == "generate_lockfile":
                return f"Generate a lockfile for {_names([str(p) for p in o.args.get('projects', [])]) or 'the project'}"
    if plan.action == "update_base_image":
        return "Update the container base image"
    if plan.action == "mitigate":
        return f"Reduce the risk without changing the package: {title}"
    if plan.action == "escalate":
        return f"Ask a person to review: {title}"
    return f"{plan.action.capitalize()}: {title}"


# ------------------------------------------------------------------ run-wide lookup tables

class Ctx:
    """Everything the section builders share: lookups by finding and plan, and the derived state of each finding."""

    def __init__(self, run_dir: Path, findings: list[Finding], risks: dict[str, RiskAssessment],
                 plans: list[RemediationPlan], approvals: list[Approval], validations: list[ValidationResult],
                 recs: list[Recommendation]):
        self.run_dir = run_dir
        self.findings = findings
        self.by_id = {f.finding_id: f for f in findings}
        self.risks = risks
        self.plans = {p.plan_id: p for p in plans}
        self.approvals = approvals
        self.last_approval: dict[str, Approval] = {}
        for a in approvals:
            self.last_approval[a.plan_id] = a
        self.vals: dict[str, list[ValidationResult]] = {}
        for v in validations:
            self.vals.setdefault(v.plan_id, []).append(v)
        self.recs = recs
        self.rec_of = {fid: r for r in recs for fid in r.finding_ids}
        # which findings each plan covers: batch items name them all, sequential plans cover one finding
        self.plan_findings: dict[str, list[str]] = {}
        for r in recs:
            if r.plan_id:
                self.plan_findings[r.plan_id] = list(r.finding_ids)
            if r.previous:
                self.plan_findings.setdefault(r.previous.plan_id, list(r.finding_ids))
        for p in plans:
            self.plan_findings.setdefault(p.plan_id, [p.finding_id])
        self.verified_plans = {pid for pid, vs in self.vals.items() if vs and vs[-1].verdict == "verified"}
        for r in recs:  # batch runs: the item's outcome is the authority
            if r.plan_id and r.outcome == "verified":
                self.verified_plans.add(r.plan_id)
            elif r.plan_id and r.outcome != "verified":
                self.verified_plans.discard(r.plan_id)
        fixed = {fid for pid in self.verified_plans for fid in self.plan_findings.get(pid, [])}
        self.state: dict[str, str] = {}
        for f in findings:
            r = self.rec_of.get(f.finding_id)
            if f.status is FindingStatus.VERIFIED or f.finding_id in fixed:
                s = "fixed"
            elif f.status is FindingStatus.ACCEPTED:
                s = "accepted"
            elif (f.status is FindingStatus.ESCALATED or (r and r.outcome == "needs_person")
                  or (r and r.outcome == "no_alternative" and "needs a person" in (r.reason or "").lower())):
                s = "needs_person"
            else:
                s = "open"
            self.state[f.finding_id] = s

    def score(self, fid: str) -> float:
        r = self.risks.get(fid)
        return r.score if r else 0.0

    def plan_title(self, plan_id: str) -> str:
        p = self.plans.get(plan_id)
        if not p:
            return "a suggested fix"
        return describe_plan(p, self.by_id.get(p.finding_id))

    def ordered(self, fids: list[str]) -> list[Finding]:
        return sorted((self.by_id[i] for i in fids if i in self.by_id), key=lambda f: (-self.score(f.finding_id), f.finding_id))


# ------------------------------------------------------------------ what happens next for a finding

def next_step(c: Ctx, f: Finding) -> str:
    r = c.rec_of.get(f.finding_id)
    if r:
        if r.outcome == "no_alternative":
            return "No fix available: " + _strip_no_alt(r.reason or "no safe change exists")
        if r.outcome in ("awaiting_decision", "approved", "validating") and r.plan_id:
            return f"Fix suggested, waiting for a decision: {c.plan_title(r.plan_id)}"
        if r.outcome == "rejected":
            why = f" ({REASON_WORD.get(r.previous.reason_type or '', r.previous.reason_type)})" if r.previous and r.previous.reason_type else ""
            return f"Earlier fix was rejected{why}; a different option is pending"
        if r.outcome == "failed":
            return "The suggested fix failed its checks" + (f" ({r.previous.detail})" if r.previous and r.previous.detail else "") \
                + "; another option may be tried"
    else:
        mine = [p for p in c.plans.values() if p.finding_id == f.finding_id]
        if mine:
            p = max(mine, key=lambda x: x.attempt)
            vs = c.vals.get(p.plan_id, [])
            a = c.last_approval.get(p.plan_id)
            if vs and vs[-1].verdict not in ("verified", "mitigated"):
                return f"The suggested fix ({c.plan_title(p.plan_id)}) failed its checks: {_verdict_word(vs[-1].verdict)}"
            if a is None:
                return f"Fix suggested, waiting for a decision: {c.plan_title(p.plan_id)}"
            if a.decision == "reject":
                return f"Fix rejected by a person: {c.plan_title(p.plan_id)}"
    if f.fixed_versions:
        return f"No fix was proposed in this run; a fixed version ({f.fixed_versions[-1]}) exists"
    return "No fix available: no fixed version has been published"


def open_groups(c: Ctx) -> list[OpenGroup]:
    groups: dict[str, list[Finding]] = {}
    for f in c.findings:
        if c.state[f.finding_id] == "open":
            groups.setdefault(package_of(f), []).append(f)
    out = []
    for pkg, fs in groups.items():
        fs.sort(key=lambda f: (-c.score(f.finding_id), f.finding_id))
        steps = list(dict.fromkeys(next_step(c, f) for f in fs))
        if len(steps) > 1 and all(x.startswith("No fix was proposed") for x in steps):
            steps = steps[:1]  # same advice for every finding, only the fixed version differs
        step = " Also: ".join(steps[:2]) + (f" (and {len(steps) - 2} more)" if len(steps) > 2 else "")
        out.append(OpenGroup(package=pkg, level=level_of(fs[0], c.risks.get(fs[0].finding_id)), score=c.score(fs[0].finding_id),
                             count=len(fs), next_step=step, finding_ids=[f.finding_id for f in fs],
                             titles=[f.title for f in fs[:3]]))
    out.sort(key=lambda g: (-g.score, g.package))
    return out


# ------------------------------------------------------------------ fixes verified

def _baseline(run_dir: Path) -> dict | None:
    p = run_dir / "sandbox_baseline.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else None
    except ValueError:
        return None


def _tests_sentence(label: str, after: dict[str, int], base: dict[str, int] | None) -> str | None:
    if not after:
        return None
    s = f"{label}: {after.get('passed', 0)} of {after.get('total', 0)} pass"
    if base:
        s += (" (same as the unchanged project, no new failures)" if after.get("failed", 0) <= base.get("failed", 0)
              else f" (the unchanged project passes {base.get('passed', 0)} of {base.get('total', 0)})")
    return s + "."


def _branch_of(run_dir: Path, attempt_id: str) -> tuple[str | None, str | None]:
    pr = run_dir / "attempts" / attempt_id / "PR.md"
    if not pr.is_file():
        return None, None
    m = re.search(r"Branch `([^`]+)`", pr.read_text(encoding="utf-8", errors="replace")[:600])
    return (m.group(1) if m else None), f"attempts/{attempt_id}/PR.md"


def fixes(c: Ctx) -> list[ReportFix]:
    base = _baseline(c.run_dir)
    by_attempt: dict[str, list[ValidationResult]] = {}
    for vs in c.vals.values():
        for v in vs:
            by_attempt.setdefault(v.attempt_id, []).append(v)
    out = []
    for pid in c.verified_plans:
        plan, vs = c.plans.get(pid), c.vals.get(pid, [])
        if not plan:
            continue
        v = next((x for x in reversed(vs) if x.verdict == "verified"), None)
        covered = c.ordered(c.plan_findings.get(pid, [plan.finding_id]))
        if not covered:
            continue
        primary = c.by_id.get(plan.finding_id) or covered[0]
        checks: list[str] = []
        together: list[str] = []
        score_before = score_after = None
        attempt_id = branch = pr_md = None
        if v:
            attempt_id, score_before, score_after = v.attempt_id, v.risk_before, v.risk_after
            if v.build_ok is True:
                checks.append("Built successfully in an isolated sandbox with no network access.")
            elif v.build_ok is False:
                checks.append("The sandbox build failed.")
            else:
                checks.append("The sandbox build and tests were not run (sandbox unavailable); only the re-scan below confirms this fix.")
            for t in (_tests_sentence("Unit tests", v.unit_tests, (base or {}).get("unit_tests")),
                      _tests_sentence("Integration tests", v.integration_tests, (base or {}).get("integration_tests"))):
                if t:
                    checks.append(t)
            checks.append("Re-scan of the patched project: " + ("the problem no longer appears" if v.target_finding_resolved
                                                                else "the problem still appears")
                          + (f"; {_plural(len(v.new_findings), 'new finding')} appeared." if v.new_findings else "; no new findings appeared."))
            together = [c.plan_title(o.plan_id) for o in by_attempt.get(v.attempt_id, []) if o.plan_id != pid]
            if v.combined and together:
                checks.append(f"Tested together with {_plural(len(together), 'other fix', 'other fixes')}: {_names(together, 4)}.")
            elif v.combined:
                checks.append("Tested as one change set with the other approved fixes of that round.")
            else:
                checks.append("Tested on its own.")
            tries = [x for x in vs if x.attempt_id != v.attempt_id and x.verdict != "verified" and not x.group_failure]
            if tries:
                checks.append(f"Needed {len(tries) + 1} attempts; an earlier one failed ({_verdict_word(tries[-1].verdict)}).")
            branch, pr_md = _branch_of(c.run_dir, v.attempt_id)
        if branch:
            where = f"Local branch {branch} in the attempt's work copy; description in {pr_md}. Nothing was pushed or merged."
        else:
            where = "No local branch was written for this fix; the exact edit is saved in the run's plans folder. Nothing was pushed or merged."
        a = c.last_approval.get(pid)
        out.append(ReportFix(
            title=c.plan_title(pid), plan_id=pid, attempt_id=attempt_id, finding_ids=[f.finding_id for f in covered],
            finding_count=len(covered), top_titles=[f.title for f in covered[:3]],
            level=level_of(covered[0], c.risks.get(covered[0].finding_id)), primary_finding_id=primary.finding_id,
            checks=checks, tested_with=together, score_before=score_before, score_after=score_after,
            location=where, branch=branch, pr_markdown=pr_md,
            approved_by=a.decided_by if a and a.decision == "approve" else None))
    out.sort(key=lambda x: (-(x.score_before or 0), x.title))
    return out


# ------------------------------------------------------------------ decisions, accepted risks, people needed

def decisions(c: Ctx) -> list[ReportDecision]:
    out = []
    for a in c.approvals:
        plan = c.plans.get(a.plan_id)
        fids = c.plan_findings.get(a.plan_id, [plan.finding_id] if plan else [])
        vs = c.vals.get(a.plan_id, [])
        if a.decision == "approve":
            result = ("Fix verified" if a.plan_id in c.verified_plans
                      else f"Fix failed its checks: {_verdict_word(vs[-1].verdict)}" if vs else "Approved, not yet validated")
        elif a.decision == "accept_risk":
            result = "Risk accepted, nothing was changed"
        else:
            result = "Fix rejected, nothing was changed"
        out.append(ReportDecision(
            plan_id=a.plan_id, finding_id=plan.finding_id if plan else (fids[0] if fids else None),
            what=c.plan_title(a.plan_id) if plan else "a suggested fix", finding_count=len(fids) or 1, decision=a.decision,
            reason_type=a.reason_type, reason_text=REASON_WORD.get(a.reason_type or "", a.reason_type) if a.reason_type else None,
            comment=a.comment, decided_by=a.decided_by, decided_at=a.ts.isoformat(timespec="seconds"), result=result,
            plan_hash=a.plan_hash, plan_hash_ok=(a.plan_hash == plan.plan_hash) if plan else None))
    return out


def attention(c: Ctx) -> list[AttentionItem]:
    """Accepted risks (one per accepted fix, with the person's reason) and findings that need a person."""
    out: list[AttentionItem] = []
    seen: set[str] = set()
    for pid, a in c.last_approval.items():
        if a.decision != "accept_risk":
            continue
        fids = [i for i in c.plan_findings.get(pid, []) if c.state.get(i) == "accepted"]
        covered = c.ordered(fids)
        if not covered:
            continue
        seen.update(f.finding_id for f in covered)
        plan = c.plans.get(pid)
        out.append(AttentionItem(
            kind="accepted", title=c.plan_title(pid), level=level_of(covered[0], c.risks.get(covered[0].finding_id)),
            score=c.score(covered[0].finding_id), finding_ids=[f.finding_id for f in covered], finding_count=len(covered),
            top_titles=[f.title for f in covered[:3]], plan_id=pid,
            reason=a.comment or "No reason was recorded.", decided_by=a.decided_by, decided_at=a.ts.isoformat(timespec="seconds"),
            note=plan.expected_risk_reduction if plan and plan.action == "mitigate" else None))
    for f in c.findings:  # accepted without a recorded decision (e.g. an accepted mitigation)
        if c.state[f.finding_id] == "accepted" and f.finding_id not in seen:
            out.append(AttentionItem(kind="accepted", title=f.title, level=level_of(f, c.risks.get(f.finding_id)),
                                     score=c.score(f.finding_id), finding_ids=[f.finding_id], finding_count=1,
                                     top_titles=[f.title], reason="Accepted without a recorded comment."))
    for f in c.ordered([x.finding_id for x in c.findings if c.state[x.finding_id] == "needs_person"]):
        out.append(AttentionItem(kind="needs_person", title=f.title, level=level_of(f, c.risks.get(f.finding_id)),
                                 score=c.score(f.finding_id), finding_ids=[f.finding_id], finding_count=1, top_titles=[f.title],
                                 reason=next_step_reason(c, f)))
    out.sort(key=lambda i: (i.kind, -i.score, i.title))
    return out


def next_step_reason(c: Ctx, f: Finding) -> str:
    r = c.rec_of.get(f.finding_id)
    if r and r.reason:
        return _strip_no_alt(r.reason)
    if r and r.outcome == "needs_person":
        return "Guardian ran out of safe attempts (fixes were rejected or failed) and needs a person to decide."
    return "Guardian could not find a safe automatic change; a person has to decide."


# ------------------------------------------------------------------ score guide

def score_guide(c: Ctx) -> ScoreGuide:
    lows = {b: min(x / 10 for x in range(0, 1001, 5) if scoring.band(x / 10).value == b) for b in LEVELS}
    band_text = {"critical": f"{lows['critical']:g} and above"}
    for hi, lo in zip(LEVELS, LEVELS[1:]):  # each band runs up to the start of the one above it
        band_text[lo] = f"{lows[lo]:g} to under {lows[hi]:g}" if lows[lo] else f"under {lows[hi]:g}"
    differ = sum(1 for f in c.findings if f.severity and f.finding_id in c.risks
                 and f.severity.lower() != c.risks[f.finding_id].band.value)
    with_sev = sum(1 for f in c.findings if f.severity and f.finding_id in c.risks)
    notes = [
        "Each finding gets a score from 0 to 100. Five factors, each between 0 and 1, are multiplied by the weights below "
        f"and added up; a failed provenance check adds {scoring.PROVENANCE_BONUS:g} points (the score never exceeds 100).",
        "For CI, lockfile and image findings there is no 'reachability'; its weight moves to severity.",
        "The score is a ranking aid for deciding what to look at first, not a probability of being attacked. "
        "The weights are Guardian's own choice.",
        "A finding that is on the known-exploited list, reachable and in production is never below High.",
        f"Guardian's level can differ from the severity printed in the advisory: it also weighs whether the code reaches the "
        f"package, whether it ships to production and whether the service is exposed. "
        + (f"Here {differ} of {with_sev} advisories with a severity were placed in a different level." if with_sev else ""),
    ]
    return ScoreGuide(weights={k: float(v) for k, v in scoring.WEIGHTS.items()}, factor_names=dict(FACTOR_NAMES),
                      factor_help=dict(FACTOR_HELP), bands=band_text, notes=[n.strip() for n in notes])


# ------------------------------------------------------------------ method and limits

TOOL_PLAIN = {
    "sbom": "Software inventory (SBOM) of every package, direct and indirect",
    "grype": "Grype scanner: known vulnerabilities in the inventory",
    "osv": "OSV database lookup: a second source of known vulnerabilities",
    "graph_build": "Dependency graph: which package pulls in which",
    "reachability": "Static code check: does the application import or call the vulnerable package",
    "threat_intel": "Exploit data: exploit probability (EPSS) and the known-exploited list (KEV)",
    "exposure_signals": "Whether the running service is reachable from outside",
    "package_scope": "Whether each package is used in production or only in development",
    "npm_signatures": "npm registry signature check",
    "provenance_signals": "Build provenance check of packages",
    "registry_metadata": "Package registry metadata (age, maintainers, releases)",
    "policy_check": "Project policy rules (guardian.yaml)",
    "changes": "Comparison with earlier scans of the same project",
    "detector:typosquat": "Detector: look-alike (typosquat) package names",
    "detector:ci_pin": "Detector: CI actions not pinned to a fixed commit",
    "detector:image_pin": "Detector: container images not pinned by digest",
    "detector:lockfile": "Detector: missing or unreliable lockfiles",
    "detector:install_scripts": "Detector: packages that run code when installed",
    "detector:package_risk": "Detector: risky package signals",
    "detector:outdated": "Detector: outdated packages",
    "detector:unexpected_change": "Detector: unexpected dependency changes",
    "detector:similarity": "Detector: similar package names",
}
AGENT_PLAIN = {
    "evidence_analyst": "explained each finding in plain words and gave a first risk level",
    "risk_analyst": "wrote the risk summaries for the ranking",
    "investigator": "checked suspicious packages against registry facts",
    "remediation": "chose between fix options that tools had already verified",
    "validator": "summarised fix checks",
    "reporter": "wrote report text",
}
GUARDRAILS = [
    "Builds and tests run in a throw-away sandbox with no network, as a non-root user, with CPU, memory and time limits.",
    "No fix is applied until a person approves that exact plan (the approval is tied to the plan's content); "
    "nothing is pushed, merged or deployed.",
    "Statements by the AI model must point to evidence; anything else is labelled as inferred.",
    "Text taken from packages and scanners is treated as data; instructions hidden in it are ignored.",
    "Secrets are masked before text reaches the AI model, the logs or this report.",
    "Outbound network access is limited to an allow-list, and each agent has tool-call, time and token budgets.",
]


def method(c: Ctx, trace: list[dict], summary: dict, validations: list[ValidationResult]) -> ReportMethod:
    tools = [e.get("data", {}).get("tool") or e.get("summary") for e in trace if e.get("type") == "tool_call"]
    seen = set(t for t in tools if t)
    ran = [text for key, text in TOOL_PLAIN.items() if key in seen]
    ran += [f"Detector: {t.split(':', 1)[1].replace('_', ' ')}" for t in sorted(seen)
            if t.startswith("detector:") and t not in TOOL_PLAIN]
    if not ran:  # older runs without tool events: fall back to what produced the findings
        ran = [f"Detector or scanner: {d}" for d in sorted({f.detector for f in c.findings})]
    sandbox_ran = "sandbox_validate" in seen or bool(validations and any(v.build_ok is not None for v in validations))
    if sandbox_ran:
        ran.append("Fix checks: each approved fix was applied to a copy, built and tested in a Docker sandbox with no network, "
                   "then the copy was re-scanned.")
    if "safe_version_lookup" in seen:
        ran.append("Fix options: safe versions and compatibility were looked up from the package registry, not guessed by the AI.")

    llm = summary.get("llm") or {}
    calls: dict[tuple, int] = {}
    for e in trace:
        if e.get("type") == "llm_call":
            d = e.get("data") or {}
            k = (e.get("agent") or "agent", d.get("mode") or llm.get("mode"), d.get("model") or llm.get("model"))
            calls[k] = calls.get(k, 0) + 1
    ai: list[str] = []
    for (agent, mode, model), n in sorted(calls.items()):
        how = {"replay": "replayed from a recorded earlier run (no live model call)", "record": "called live and recorded",
               "live": "called live"}.get(mode or "", mode or "mode unknown")
        ai.append(f"{agent.replace('_', ' ').capitalize()} ({_plural(n, 'call')}, {model or 'model unknown'}, {how}): "
                  f"{AGENT_PLAIN.get(agent, 'supported the analysis')}.")
    if not ai:
        ai = ["No AI model was used."] if not llm else [f"AI model {llm.get('model')} in {llm.get('mode')} mode."]
    ai.append("AI is used only to explain and to choose between options that tools produced. Versions, scores, test results "
              "and decisions come from tools and people.")

    base = _baseline(c.run_dir)
    no_check = ["Nothing was pushed, merged or deployed; no real repository was changed."]
    if not (c.run_dir / "sbom.image.cdx.json").exists():
        no_check.append("Container images were not rebuilt and re-scanned; the re-scan covers the patched source tree only.")
    if base:
        n_u = (base.get("unit_tests") or {}).get("failed", 0)
        n_i = (base.get("integration_tests") or {}).get("failed", 0)
        if n_u or n_i:
            no_check.append(f"{_plural(n_u, 'unit test')} and {_plural(n_i, 'integration test')} already fail on the unchanged "
                            "project (possibly because they need network access or external services, which the sandbox does not have); "
                            "fixes are judged against that baseline, so those areas are not proven by the tests.")
    if not sandbox_ran:
        no_check.append("The sandbox did not run, so no fix was built or tested.")
    untested = sum(1 for p in c.plans if not c.vals.get(p) and c.last_approval.get(p) and c.last_approval[p].decision != "approve")
    if untested:
        no_check.append(f"{_plural(untested, 'suggested fix', 'suggested fixes')} that people rejected or accepted the risk for "
                        "were never built or tested.")
    no_check.append("Reachability is a static code check; no attack was run against the application to prove a flaw can be exploited.")
    events = [e for e in trace if e.get("type") == "guardrail"]
    guard = list(GUARDRAILS)
    guard.append(f"{_plural(len(events), 'guardrail event')} triggered during this run." if events
                 else "No guardrail had to block anything during this run.")
    return ReportMethod(ran=ran, ai=ai, not_checked=no_check, guardrails=guard, ai_mode=llm.get("mode"), ai_model=llm.get("model"))


# ------------------------------------------------------------------ overview and appendix

STATE_TEXT = {"fixed": "Fixed and verified", "accepted": "Risk accepted", "needs_person": "Needs a person", "open": "Open"}


def counts(c: Ctx) -> ReportCounts:
    by_level = {lv: 0 for lv in LEVELS}
    for f in c.findings:
        lv = level_of(f, c.risks.get(f.finding_id))
        if lv in by_level:
            by_level[lv] += 1
    st = list(c.state.values())
    waiting = sum(1 for pid, p in c.plans.items() if pid not in c.last_approval
                  and any(c.state.get(i) == "open" for i in c.plan_findings.get(pid, [p.finding_id])))
    return ReportCounts(total=len(c.findings), by_level=by_level, fixed=st.count("fixed"), accepted=st.count("accepted"),
                        open=st.count("open"), needs_person=st.count("needs_person"), awaiting_decision=waiting)


def overview(c: Ctx, summary: dict, inv: dict, target: str | None, commit: str | None, generated_at: str,
             confidence: str, m: ReportMethod) -> ReportOverview:
    n = counts(c)
    lv = n.by_level
    top = c.ordered([f.finding_id for f in c.findings if c.state[f.finding_id] != "fixed"])[:1]
    verdict = (f"Guardian found {_plural(n.total, 'supply-chain issue')} in {target or 'the project'}: {lv['critical']} critical, "
               f"{lv['high']} high, {lv['medium']} medium and {lv['low']} low. "
               f"{_plural(n.fixed, 'issue')} now {'has' if n.fixed == 1 else 'have'} a verified fix, "
               f"{n.accepted} {'was' if n.accepted == 1 else 'were'} accepted as a risk by people, "
               f"{n.open} {'remains' if n.open == 1 else 'remain'} open and {n.needs_person} need a person.")
    if top and n.total:
        verdict += f" The highest risk still present is '{top[0].title}' (score {c.score(top[0].finding_id):g})."
    if n.awaiting_decision:
        verdict += (f" {_plural(n.awaiting_decision, 'suggested fix', 'suggested fixes')} still "
                    f"{'waits' if n.awaiting_decision == 1 else 'wait'} for a person to approve, reject or accept the risk; "
                    "nothing has been changed yet.")
    if not n.total:
        verdict = "Guardian found no supply-chain issues in this project."
    limits = []
    mode = (summary.get("llm") or {}).get("mode")
    if mode == "replay":
        limits.append("The AI explanations were replayed from a recorded run, not generated live.")
    risk_conf = [r.confidence.value for r in c.risks.values()]
    weak = sum(1 for x in risk_conf if x != "high")
    if weak:
        limits.append(f"{_plural(weak, 'risk score')} rest{'s' if weak == 1 else ''} partly on assumed inputs (lower confidence).")
    tested = len({v.finding_id for vs in c.vals.values() for v in vs})
    limits.insert(0, (f"The rating reflects the fixes that were built and tested ({_plural(tested, 'finding')}); the other "
                      f"{max(n.total - tested, 0)} findings rest on scanners and scoring only.") if tested
                  else "No fix was built or tested in this run, so the rating rests on scanners and scoring only.")
    limits += [x for x in m.not_checked[1:3]]
    return ReportOverview(
        target=target, commit=commit, status=summary.get("status"),
        scanned_at=summary.get("finished_at") or summary.get("started_at") or generated_at, generated_at=generated_at,
        packages=inv, verdict=verdict, counts=n, confidence=confidence, confidence_limits=limits,
        key_points=key_points(c, n, top))


def appendix(c: Ctx) -> list[AppendixRow]:
    rows = []
    for f in c.findings:
        r = c.risks.get(f.finding_id)
        rows.append(AppendixRow(
            finding_id=f.finding_id, level=level_of(f, r), score=r.score if r else 0.0, title=f.title, package=package_of(f),
            state=c.state[f.finding_id], status=STATE_TEXT[c.state[f.finding_id]], advisory_severity=f.severity,
            kind=CATEGORY_WORD.get(f.category.value, f.category.value), plan_ids=[p for p, fs in c.plan_findings.items()
                                                                                   if f.finding_id in fs and p in c.plans]))
    rows.sort(key=lambda x: (-x.score, x.finding_id))
    return rows


# ------------------------------------------------------------------ key points (top of the report)

def key_points(c: Ctx, n: ReportCounts, top: list[Finding]) -> list[str]:
    """Three or four plain sentences for a reader who stops after the first screen."""
    if not n.total:
        return ["No supply-chain issue was found, so there is nothing to fix or decide."]
    pts = []
    worst = c.ordered([f.finding_id for f in c.findings])[:1]
    if worst and not (top and worst[0].finding_id == top[0].finding_id):  # the verdict already names it
        w = worst[0]
        pts.append(f"Biggest risk found: {w.title} (score {c.score(w.finding_id):g} of 100, "
                   f"{level_of(w, c.risks.get(w.finding_id))}).")
    if n.fixed:
        pts.append(f"{_plural(n.fixed, 'issue')} {'was' if n.fixed == 1 else 'were'} fixed on a copy of the project and passed "
                   "the build, tests and a re-scan. The real repository was not changed.")
    else:
        pts.append("No issue has a verified fix yet.")
    if n.awaiting_decision:
        pts.append(f"Decision needed: {_plural(n.awaiting_decision, 'suggested fix', 'suggested fixes')} "
                   f"{'is' if n.awaiting_decision == 1 else 'are'} waiting for a person.")
    elif n.accepted:
        pts.append(f"{_plural(n.accepted, 'issue')} {'stays' if n.accepted == 1 else 'stay'} in the project because a person "
                   "accepted the risk; this is not a fix.")
    rest = n.open + n.needs_person
    if rest and not n.awaiting_decision:
        pts.append(f"{_plural(rest, 'issue')} remain without a fix (see sections 8 and 9).")
    return pts


# ------------------------------------------------------------------ risk ranking with factor tables

def _node_label(node: str, root: str) -> str:
    if node == "root":
        return root
    if node.startswith("pkg:"):
        body = unquote(node.removeprefix("pkg:").split("?")[0].split("#")[0])
        _, _, rest = body.partition("/")
        return rest or body
    return node


def plan_for(c: Ctx, fid: str) -> RemediationPlan | None:
    """The latest plan that covers a finding (a verified one wins), or None."""
    mine = [p for pid, p in c.plans.items() if fid in c.plan_findings.get(pid, [])]
    if not mine:
        return None
    return max(mine, key=lambda p: (p.plan_id in c.verified_plans, p.attempt, p.plan_id))


def _action_and_decision(c: Ctx, f: Finding) -> tuple[str, str]:
    plan = plan_for(c, f.finding_id)
    st = c.state[f.finding_id]
    if plan is None:
        if st == "fixed":
            return "Fixed (verified)", "No decision recorded"
        return next_step(c, f), "No fix was proposed, so there is nothing to decide"
    title = c.plan_title(plan.plan_id)
    a = c.last_approval.get(plan.plan_id)
    if a is None:
        return title, "Waiting for a person to decide"
    who = f"{a.decided_by}, {a.ts.strftime('%Y-%m-%d %H:%M')} UTC"
    word = {"approve": "Approved", "reject": "Rejected", "accept_risk": "Risk accepted"}.get(a.decision, a.decision)
    text = f"{word} by {who}"
    if a.comment:
        text += f": {a.comment}"
    if a.decision == "approve":
        vs = c.vals.get(plan.plan_id, [])
        text += (" - fix verified" if plan.plan_id in c.verified_plans
                 else f" - fix failed its checks ({_verdict_word(vs[-1].verdict)})" if vs else " - not yet validated")
    return title, text


_ID_REF = re.compile(r"\b(?:fd|ev|pl|at|rc|bt)_[0-9A-Za-z]{6,}\b|\bF\d{1,3}\b")


def _plain(text: str) -> str:
    """Model-written prose with internal ids removed ("same as F1" and the like): ids belong in id fields only."""
    t = _ID_REF.sub("another finding", text or "")
    return re.sub(r"(another finding)(,? ?\(?another finding\)?)+", r"\1", t)


def _visible_claims(claims) -> list[ReportClaim]:
    """Only claims that survived grounding; anything labelled unsupported is dropped (G4.6) and never shown."""
    return [ReportClaim(text=_plain(x.text), label=x.label.value, evidence_ids=list(x.evidence_ids))
            for x in claims if x.label.value != "unsupported"]


def ranked(c: Ctx) -> list[RankedFinding]:
    """The full risk ranking, highest score first, each with its factor table (so the score can be recomputed)."""
    out = []
    for i, f in enumerate(c.ordered([x.finding_id for x in c.findings]), 1):
        r = c.risks.get(f.finding_id)
        rows: list[FactorRow] = []
        prov = 0.0
        recomputed = matches = None
        if r is not None:
            w = scoring.weights_for(r.factors)
            for k in scoring.WEIGHTS:
                fv = getattr(r.factors, k)
                rows.append(FactorRow(key=k, name=FACTOR_NAMES[k], value=fv.value, tier=fv.tier, assumed=fv.unknown,
                                      label=fv.label.value, weight=w[k], points=round(100 * w[k] * fv.value, 2)))
            prov = r.factors.provenance_modifier
            recomputed = round(min(100.0, sum(x.points for x in rows) + prov), 2)
            matches = abs(recomputed - r.score) < 0.1
        action, decision = _action_and_decision(c, f)
        claims = _visible_claims((r.claims if r else []) + f.claims)
        paths = [[_node_label(n, "project") for n in p] for p in f.dependency_paths[:3]]
        out.append(RankedFinding(
            rank=i, finding_id=f.finding_id, title=f.title, package=package_of(f), version=_version_of(f),
            kind=CATEGORY_WORD.get(f.category.value, f.category.value), level=level_of(f, r), score=r.score if r else 0.0,
            confidence=r.confidence.value if r else "low", state=c.state[f.finding_id], status=STATE_TEXT[c.state[f.finding_id]],
            summary=_plain((r.summary if r else "") or ""), factors=rows, provenance_points=prov,
            override=r.override_applied if r else None, recomputed_score=recomputed, score_matches=matches,
            action=action, decision=decision, paths=paths, path_count=len(f.dependency_paths), claims=claims,
            evidence_ids=list(f.evidence_ids)))
    return out


# ------------------------------------------------------------------ validation results, before/after

def _new_finding_text(x: str) -> str:
    if x.startswith("vuln:"):
        return f"New known vulnerability {x[5:]}"
    if x.startswith("dep:"):
        return f"Unexpected new package {x[4:]}"
    return x


def _counts_text(d: dict[str, int]) -> str:
    if not d:
        return "not run"
    t = d.get("total", d.get("passed", 0) + d.get("failed", 0))
    return f"{d.get('passed', 0)} of {t} pass" + (f", {d['failed']} fail" if d.get("failed") else "")


_PHASE_HEAD = re.compile(r"^\$ .*? \[([\w-]+)\] exit=\S*$", re.M)  # "$ docker run [test] exit=1" in old excerpts
_PHASE_WORD = {"install": "Installing dependencies", "build": "Build", "test": "Unit tests", "integration": "Integration tests",
               "image_build": "Building the image"}


def _phase_word(name: str) -> str:
    m = re.fullmatch(r"(.+?)-(\d+)", name)
    base, shard = (m.group(1), m.group(2)) if m else (name, None)
    return _PHASE_WORD.get(base, base.replace("_", " ").capitalize()) + (f" (shard {shard})" if shard else "")


def _split_excerpt(text: str) -> dict[str, str]:
    """Older evidence keeps one combined output tail for all its phases, each introduced by "$ ... [name] exit=N":
    split it back into per-phase text (a phase whose head was cut off by the tail limit is simply absent)."""
    heads = list(_PHASE_HEAD.finditer(text or ""))
    return {m.group(1): text[m.end():(heads[i + 1].start() if i + 1 < len(heads) else len(text))].strip("\n")
            for i, m in enumerate(heads)}


def _test_runs(v, store) -> dict:
    """Phase-by-phase sandbox detail for one validation, from its log evidence: what ran, how long, exit code, test
    counts, failing names and output tail; plus which failures are new / expected / already there before the fix."""
    runs: list[TestRun] = []
    newly: list[str] = []
    expected: list[str] = []
    failing_all: set[str] = set()
    notes: list[str] = []
    for eid in v.log_evidence_ids or []:
        ev = store.get_evidence(eid) if store is not None else None
        if ev is None:
            continue
        f = ev.facts or {}
        if ev.source_tool == "validator" and str(getattr(ev.kind, "value", ev.kind)) == "test_result":
            newly = list(f.get("newly_failing_tests") or newly)
            expected = list(f.get("expected_failures") or expected)
            continue
        if not str(ev.source_tool).startswith("sandbox") or "phases" not in f:
            continue
        old = _split_excerpt(ev.excerpt or "")
        if not old and ev.excerpt and f["phases"]:  # the tail starts inside the last phase: it is that phase's output
            old = {f["phases"][-1].get("name", ""): ev.excerpt.strip("\n")}
        by_kind = f.get("failing_tests") or {}
        newly = newly or list(by_kind.get("new_vs_baseline") or [])
        for n in (f.get("notes") or []):
            notes.append(n)
        # suite-level failing names count even when the phase list cannot say which shard they came from
        for k in ("test", "integration"):
            failing_all.update(by_kind.get(k) or [])
        if f.get("integration_shards", 1) and f.get("integration_shards", 1) > 1:
            total = f.get("integration_tests")
            notes.append(f"The integration suite was split over {f['integration_shards']} containers run side by side"
                         + (f"; together: {_counts_text(total)}." if isinstance(total, dict) and total else "."))
        elif f.get("shard_note"):
            notes.append(f"The integration suite ran in one container ({f['shard_note']}).")
        for ph in f["phases"]:
            name = ph.get("name", "")
            kind = re.sub(r"-\d+$", "", name)
            failing = list(ph.get("failing") if "failing" in ph else
                           (by_kind.get(kind) or [] if kind in ("test", "integration") and kind == name else []))
            failing_all.update(failing)
            tests = ph.get("tests")
            if tests is None and kind == name:  # older evidence: suite totals live on the evidence
                tests = f.get("unit_tests") if kind == "test" else f.get("integration_tests") if kind == "integration" else None
            code = ph.get("exit_code")
            result = ("timed out" if ph.get("timed_out") else "passed" if code == 0 else f"failed (exit {code})")
            runs.append(TestRun(
                name=name, label=ph.get("label") or _phase_word(name), command=ph.get("command") or "",
                network=ph.get("network") or "none", seconds=ph.get("seconds") or 0, exit_code=code,
                timed_out=bool(ph.get("timed_out")), result=result,
                tests=_counts_text(tests) if isinstance(tests, dict) and tests else "",
                failing=failing, output_tail=ph.get("output_tail") or old.get(name, ""), log=ph.get("log")))
    for n in (*newly, *expected):
        failing_all.discard(n)
    newly = [n for n in newly if n not in expected]
    # a test phase that exits non-zero only because of failures the unchanged project has too is not a regression:
    # say so instead of showing a bare "failed" next to a verified fix
    for t in runs:
        own = set(t.failing)
        if (t.exit_code not in (0, None) and not t.timed_out and re.sub(r"-\d+$", "", t.name) in ("test", "integration")
                and failing_all and not newly and not (own - failing_all - set(expected))):
            t.result = f"same failures as before the fix (exit {t.exit_code})"
    seen: set[str] = set()
    notes = [n for n in notes if not (n in seen or seen.add(n))]
    return {"test_runs": runs, "newly_failing": newly, "expected_failures": expected,
            "already_failing": sorted(failing_all), "sandbox_notes": notes}


def validations(c: Ctx, store=None) -> list[ReportValidation]:
    """Every validation attempt, passed or failed, with build/test counts, re-scan result, new findings and SBOM diff."""
    base = _baseline(c.run_dir) or {}
    out = []
    allv = sorted((v for vs in c.vals.values() for v in vs), key=lambda v: (v.attempt_id, v.plan_id))
    for v in allv:
        sb = None
        if v.sbom_diff_evidence_id and store is not None:
            ev = store.get_evidence(v.sbom_diff_evidence_id)
            sb = ev.facts if ev else None
        notes = []
        for lab, got, b in (("Unit", v.unit_tests, base.get("unit_tests")),
                            ("Integration", v.integration_tests, base.get("integration_tests"))):
            if got and b:
                same = "no new failures versus" if got.get("failed", 0) <= b.get("failed", 0) else "more failures than"
                notes.append(f"{lab} tests: {same} the unchanged project ({_counts_text(b)}).")
        sb = sb or {}
        verdict_text = ("Verified" if v.verdict == "verified" else "Risk reduced, vulnerable code stays" if v.verdict == "mitigated"
                        else "Tested only as part of a group that failed" if v.group_failure
                        else "Failed: " + _verdict_word(v.verdict))
        out.append(ReportValidation(
            attempt_id=v.attempt_id, plan_id=v.plan_id, finding_id=v.finding_id, title=c.plan_title(v.plan_id), verdict=v.verdict,
            verdict_text=verdict_text, passed=v.verdict == "verified",
            build="not run" if v.build_ok is None else ("passed" if v.build_ok else "failed"),
            unit_tests=_counts_text(v.unit_tests), integration_tests=_counts_text(v.integration_tests),
            baseline_note=" ".join(notes), resolved=v.target_finding_resolved,
            new_findings=[_new_finding_text(x) for x in v.new_findings], risk_before=v.risk_before, risk_after=v.risk_after,
            confidence=v.final_confidence.value, combined=v.combined, round=v.round, group_failure=v.group_failure,
            sbom_added=list(sb.get("added", [])), sbom_removed=list(sb.get("removed", [])),
            sbom_changed=[f"{x['name']}: {x['from']} -> {x['to']}" for x in sb.get("changed", [])],
            sbom_components=[sb["components_before"], sb["components_after"]] if "components_before" in sb else [],
            image_rescanned=v.artifact_rescanned, **_test_runs(v, store)))
    return out


def before_after(c: Ctx, vals: list[ReportValidation]) -> BeforeAfter:
    """Findings by level before the run and after verified fixes only, plus SBOM change and new findings."""
    before = {lv: 0 for lv in LEVELS}
    after = {lv: 0 for lv in LEVELS}
    top_b = top_a = 0.0
    for f in c.findings:
        lv = level_of(f, c.risks.get(f.finding_id))
        sc = c.score(f.finding_id)
        top_b = max(top_b, sc)
        if lv in before:
            before[lv] += 1
        if c.state[f.finding_id] != "fixed":
            top_a = max(top_a, sc)
            if lv in after:
                after[lv] += 1
    ok = [v for v in vals if v.passed]
    comps = [v.sbom_components for v in ok if v.sbom_components]
    # package changes over all verified attempts (the same change seen in two attempts counts once)
    added = {x for v in ok for x in v.sbom_added}
    removed = {x for v in ok for x in v.sbom_removed}
    changed = {x for v in ok for x in v.sbom_changed}
    seen: list[str] = []
    for v in vals:
        for t in v.new_findings:
            if t not in seen:
                seen.append(t)
    note = ("'After' counts only fixes that were built, tested and re-scanned; accepted risks and open findings are still counted. "
            "The SBOM comparison is of the original project against the patched copy.")
    if not vals:
        note = "No fix was validated in this run, so nothing changed: the 'after' column equals 'before'."
    return BeforeAfter(levels_before=before, levels_after=after, top_before=top_b, top_after=top_a,
                       fixed=sum(1 for s in c.state.values() if s == "fixed"),
                       sbom_components=[comps[0][0], comps[-1][1]] if comps else [],
                       sbom_added=len(added), sbom_removed=len(removed), sbom_changed=len(changed), new_findings=seen, note=note)


# ------------------------------------------------------------------ guardrail events and audit trail

_RULE = re.compile(r"\bG\d\.\d+\b")
GUARDRAIL_WORD = {
    "G4.6": "A statement by the AI was removed because no evidence supported it",
    "G4.1": "AI output did not match the required format and was repaired or discarded",
    "G2.3": "Text from a package or scanner looked like an instruction to the AI and was ignored",
    "G3.6": "A token, time or tool budget ran out and Guardian fell back to rules",
    "G5.1": "A decision was refused because it did not match the plan's content",
}


def guardrails(trace: list[dict]) -> list[GuardrailRow]:
    """Safety rules that fired, in words, with the rule code kept for reference."""
    out = []
    for e in trace:
        if e.get("type") != "guardrail":
            continue
        text = e.get("summary") or ""
        m = _RULE.search(text)
        rule = m.group(0) if m else "-"
        gist = GUARDRAIL_WORD.get(rule)
        out.append(GuardrailRow(rule=rule, agent=e.get("agent") or "guardrail",
                                text=f"{gist}. Detail: {text}" if gist else text,
                                ts=str(e.get("ts") or "")[:19], finding_id=e.get("finding_id")))
    return out


AUDIT_KINDS = {"gate_wait": "Waiting for a person", "gate_resume": "Person decided", "error": "Error", "guardrail": "Safety rule"}


def audit_trail(trace: list[dict], limit: int = 120) -> list[AuditRow]:
    """Condensed trail: human gate events, errors, guardrail hits and the validator's decisions (not every tool call)."""
    rows = []
    for e in trace:
        t = e.get("type")
        if t in AUDIT_KINDS or (t == "decision" and e.get("agent") in ("validator", "human_gate")):
            rows.append(AuditRow(ts=str(e.get("ts") or "")[:19], agent=e.get("agent") or "", kind=AUDIT_KINDS.get(t, "Decision"),
                                 text=e.get("summary") or ""))
    if len(rows) > limit:
        extra = len(rows) - limit
        rows = rows[:limit] + [AuditRow(agent="report", kind="Note", text=f"{extra} more steps are in trace.jsonl")]
    return rows
