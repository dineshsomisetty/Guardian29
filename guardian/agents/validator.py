"""Validator (Day-1 form): apply the approved plan to a fresh copy and re-run the detectors (C4). Owner: Dev1.

Verdict (D2-08 adds the Docker sandbox: build, tests, SBOM rescan + diff; see tools/sandbox.py):
  verified      the target finding is gone from its detector's re-run and no detector reports anything new
  regressed     a re-run detector reports a finding the original run did not have (never verified)
  not_resolved  the target finding is still reported
  still_imported  pre-flight: a remove/block/replace plan drops a package the source still imports (no sandbox run)
  failed_build  the patch could not be applied, or the sandbox install/build failed
  failed_tests  the sandbox test run failed
  timeout       a sandbox phase exceeded GUARDIAN_SANDBOX_TIMEOUT
  mitigated     a `mitigate` plan (no ops): NOTHING was applied or tested and the vulnerability is NOT fixed; the
                finding becomes ACCEPTED with the approval and the report lists it as accepted risk
Without Docker (or GUARDIAN_SANDBOX=off) build/tests are recorded as not run (`build_ok: null`,
`checks_skipped`) and a `verified` carries MEDIUM confidence; HIGH needs build+tests passed and a clean rescan.
After a `verified` attempt the patched files are committed on a local branch in the attempt copy and PR.md is
written (D2-10, tools/local_pr.py; nothing is pushed or merged, G5.5).
A failed attempt goes back to remediation for a *different* plan; after 3 attempts the finding is escalated.

Batch mode (`validate_plans`): every approved plan of a round is applied onto ONE attempt copy (each plan's ops under
its own approval, G3.3) and built/tested once; the plans share the attempt_id. A build/test failure or a new
vulnerability cannot be blamed on one plan, so that result is marked `group_failure` and the set is bisected (halves
tested together, recursing into failing halves) to find the culprit. A plan that drops a package the source still
imports fails at once in a cheap pre-flight (verdict `still_imported`) and never enters the sandbox. A plan that verifies alone while the combination failed says so in its
evidence: the combination is NOT verified. A plan whose target findings are still reported is `not_resolved`.

Where it sits in the pipeline
  Sequential mode: record_decision (approve) -> `validator_node` -> next finding | replan | reporter. Batch mode:
  recommend -> batch_gate -> record_batch -> `validate_batch_node` (agents/batch.py) -> `validate_plans` (here) ->
  recommend (next round) | reporter. This is the only agent that applies a plan to anything, and only to a copy.

Inputs
  Graph state (sequential): run_id, plan_id, decision (the approval). Batch: `Item`s handed in by batch.py (plan,
  its recorded approval, its findings) plus the already-verified `carried` items. Files: plans/<plan_id>.json,
  risk.json (risk before / after), discovery's resolved lockfiles under runs/<id>/work. Store: findings and the
  evidence of the original detector runs (the baseline a re-run is compared with).

Outputs
  Files under runs/<id>/: attempts/<attempt_id>/work (the patched copy; the target repo is never touched, and
  nothing is pushed or merged, G5.5), attempts/<attempt_id>/PR.md and a local fix branch (local_fix_branch),
  validation/<attempt_id>[.<plan_id>].json (one ValidationResult per plan), sbom.after.cdx.json from the rescan.
  Evidence: test_result (verdict, limits, skipped checks) plus whatever the tools record (patch diff, detector
  re-runs, SBOM diff, sandbox logs). State keys (sequential): route ("next" | "replan"), current, attempt, plan_id,
  last_validation. Finding status: VERIFIED, ACCEPTED (mitigated), PLANNED (another try) or ESCALATED.
  Audit events: agent_start / agent_end, decision (isolation, conflicts, expected failures, sandbox not run).

Tools (all through `call_tool`, allow-listed for this agent)
  apply_plan (write the plan's ops into the copy), the file detectors and a finding's own detector (re-run on the
  copy), policy_check, resolve_lockfiles (lockfiles for the patched manifests), rescan_patched (new SBOM + vulns +
  diff), sandbox_validate (install / build / tests in Docker), local_fix_branch (commit + PR.md, local only).

LLM use
  None. Every verdict comes from tool results and code, so a model can never declare a fix verified.

Guardrails
  G3.3 apply_plan and local_fix_branch run only with the plan AND an approval that matches it (check_write).
  G3.6 the tool-call / wall-clock budget is reset per validation (`budget.window`). G5.4 the 3-attempt limit decides
  between replan and ESCALATED after a failure. G5.5 the fix branch exists only inside the attempt copy.
  G6.7 when an image was built, the rescan result of that image (not of the manifests) is what counts.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass

from guardian.agents.remediation import DEP_OPS, dep_keys
from guardian.core.models import (
    Approval,
    Confidence,
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    Priority,
    RemediationPlan,
    RiskAssessment,
    ValidationResult,
    new_id,
)
from guardian.core.plans import list_validations, load_plan, save_validation
from guardian.graph.state import GraphState, RunContext, get_ctx
from guardian.guardrails.approval import check_write
from guardian.tools import sandbox
from guardian.tools.registry import EXTRA_ALLOW, ToolContext, call_tool
from guardian.tools.threat_intel import version_key

AGENT = "validator"
MAX_ATTEMPTS = 3  # G5.4: same limit as remediation; the third failed attempt escalates instead of re-planning
# detectors re-run on every patched copy because they read plain files (no network, no build): they show cheaply
# whether a fix removed a problem or introduced a new one. A finding's own detector is added on top (see below).
FILE_DETECTORS = ["detector:lockfile", "detector:typosquat", "detector:ci_pin", "detector:image_pin"]
# stand-in risk score (0-100) per priority band, used only when risk.json has no assessment for the finding;
# the values are band midpoints, and 50 covers a finding without any initial risk
BAND_SCORE = {Priority.CRITICAL: 90.0, Priority.HIGH: 70.0, Priority.MEDIUM: 50.0, Priority.LOW: 20.0, None: 50.0}


def _skipped(sb, rescanned: str | None) -> list[str]:
    """Names of the checks that did NOT run, for the test_result evidence (so "verified" never hides a gap).

    `sb` is the SandboxResult, `rescanned` the artifact that was rescanned (None when no rescan happened).
    Possible names: build, unit_tests, integration_tests, image_rescan, sbom_diff."""
    out = [] if sb.ran and sb.build_ok is not None else ["build"]
    if not sb.tests_ran:
        out.append("unit_tests")
    if not sb.integration_tests:
        out.append("integration_tests")
    if rescanned is None:
        out += ["image_rescan", "sbom_diff"]
    return out


def finding_key(f: Finding) -> str:
    """Identity of a finding across runs of a detector (ids differ per run)."""
    if f.category is FindingCategory.LOCKFILE:
        return f.category.value  # one per repo; its title lists what is still missing
    return f"{f.category.value}|{f.file_path}|{f.title}"


def _purl_name(purl: str) -> str:
    """Package name of a purl without type or version: "pkg:npm/%40scope/x@1.0" -> "@scope/x"; a purl with no
    version stays as is. Used to compare SBOM additions with the names a plan mentions."""
    base = purl.split("/", 1)[-1]
    return base.rsplit("@", 1)[0].replace("%40", "@") if "@" in base[1:] else base


def _npm_subtree(work, roots: set[str]) -> set[str]:
    """Package names reachable from `roots` in the patched copy's npm lockfiles (an upgrade brings its own
    dependencies: they are expected, not 'unexpected new packages')."""
    import json as _json

    deps: dict[str, set[str]] = {}
    for lock in [work / "package-lock.json", *work.glob("*/package-lock.json")]:
        try:
            pk = _json.loads(lock.read_text(encoding="utf-8")).get("packages") or {}
        except (OSError, ValueError):
            continue
        for key, entry in pk.items():
            if "node_modules/" in key and isinstance(entry, dict):
                name = key.rsplit("node_modules/", 1)[1]
                deps.setdefault(name, set()).update((entry.get("dependencies") or {}).keys())
                deps[name].update((entry.get("optionalDependencies") or {}).keys())
    seen, todo = set(), [r for r in roots if r in deps]
    while todo:
        n = todo.pop()
        if n not in seen:
            seen.add(n)
            todo.extend(deps.get(n, ()))
    return seen


def _unexpected_added(plan, added: list[str], work=None) -> list[str]:
    """New components the plan (or, in a combined run, a list of plans) did not ask for. A generate_lockfile plan
    legitimately adds the whole tree, and an upgraded or replacement package legitimately adds its own dependency
    subtree. New *vulnerabilities* are judged separately and always count.

    `added` are purls the SBOM diff reports as new; `work` is the patched copy (to read its lockfiles for the subtree).
    Returns the purls that no plan value names, directly or as a dependency of a named package: those are suspicious
    (something was pulled in that nobody approved) and make the verdict `regressed`."""
    plans = plan if isinstance(plan, (list, tuple)) else [plan]
    if any(o.op == "generate_lockfile" for p in plans for o in p.ops):
        return []
    wanted = {str(v) for p in plans for o in p.ops for v in o.args.values() if isinstance(v, str)}
    if work is not None:
        wanted |= _npm_subtree(work, wanted)
    return [a for a in added if _purl_name(a) not in wanted]


def _mitigated(rc, plan, approval: Approval, f: Finding, attempt_id: str) -> dict:
    """A mitigate plan has no ops: record the accepted mitigation, never claim a fix.

    Writes a test_result evidence that says outright "nothing applied, built or tested; still installed", saves a
    ValidationResult with verdict "mitigated" (target_finding_resolved False, confidence LOW), sets the finding to
    ACCEPTED, and emits an agent_end line. Returns the sequential-mode state that moves on to the next finding.
    Used by both modes; batch mode ignores the returned state."""
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    before, after = _risk_scores(ctx.run_dir, f, plan, True)
    ev = Evidence(run_id=ctx.run_id, kind="test_result", source_tool="validator",
                  facts={"attempt_id": attempt_id, "plan_id": plan.plan_id, "verdict": "mitigated",
                         "target_finding_resolved": False, "new_findings": [],
                         "checks_skipped": ["build", "unit_tests", "integration_tests", "image_rescan", "sbom_diff"],
                         "known_limitations": ["no-op plan: nothing was applied, built or tested; the vulnerable "
                                               "package is still installed. This is an accepted risk, not a fix"],
                         "approved_by": approval.decided_by})
    store.add_evidence(ev)
    save_validation(ctx.run_dir, ValidationResult(
        attempt_id=attempt_id, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=None,
        target_finding_resolved=False, risk_before=before, risk_after=after, verdict="mitigated",
        final_confidence=Confidence.LOW, log_evidence_ids=[ev.evidence_id]))
    f.status = FindingStatus.ACCEPTED
    store.update_finding(f)
    audit.emit(AGENT, "agent_end", f"MITIGATED (accepted risk, NOT fixed): {f.title[:70]} -> {f.status.value}",
               finding_id=f.finding_id, evidence_ids=[ev.evidence_id], data={"attempt_id": attempt_id,
                                                                            "verdict": "mitigated"})
    return {"route": "next", "current": None, "attempt": 0, "plan_id": None, "last_validation": None}


def _risk_scores(run_dir, f: Finding, plan, resolved: bool) -> tuple[float, float]:
    """(risk before, risk after) on the 0-100 scale for the ValidationResult.

    Before = the finding's score in risk.json, else the midpoint of its initial band. After = the same unless the fix
    verified (`resolved`), in which case it is `simulate_after` for the plan's action (section 7 of the spec), or 0.0
    if the scoring module is unavailable. An unresolved or failed fix therefore never shows a risk reduction."""
    before = BAND_SCORE[f.initial_risk]
    assessment = None
    path = run_dir / "risk.json"
    if path.exists():
        try:
            for r in json.loads(path.read_text(encoding="utf-8")):
                if r.get("finding_id") == f.finding_id:
                    assessment = RiskAssessment.model_validate(r)
        except (ValueError, OSError):
            assessment = None
    if assessment is not None:
        before = assessment.score
    if not resolved:
        return before, before
    try:
        from guardian.core.scoring import simulate_after
        return before, float(simulate_after(assessment, plan.action)[0])
    except ImportError:
        return before, 0.0


def _policy_counts(evidence) -> dict[str, int]:
    """{policy rule: number of violations} from policy_result evidence; None entries and rule-less rows are ignored."""
    return {e.facts["rule"]: int(e.facts.get("count", 0)) for e in evidence
            if e is not None and e.kind == "policy_result" and e.facts.get("rule")}


def _policy_regressions(store, after_evidence) -> list[str]:
    """Rules violated more often after the patch than in the original run ("policy:<rule>").
    The baseline is the policy_check findings of the original scan; a rule that was already violated N times only
    counts as a regression if the patched copy violates it more than N times."""
    before_ev = [store.get_evidence(i) for g in store.list_findings() if g.detector == "detector:policy_check"
                 for i in g.evidence_ids]
    before, after = _policy_counts(before_ev), _policy_counts(after_evidence)
    return [f"policy:{r}" for r, n in sorted(after.items()) if n > before.get(r, 0)]


# ---------------------------------------------------------------- tests that assert the vulnerability

# Deliberately vulnerable apps (Juice Shop, NodeGoat, ...) ship tests that check an attack still works, e.g.
# "GET basket should accept forged JWTs". Closing the hole makes them fail, which is the fix working, not
# breaking the app. A name counts only with an attack word AND a permissive verb and no protective verb, so
# "rejects forged tokens" failing after a fix is still a real regression.
_ATTACK = re.compile(r"forg(e|ed|ery|eable)|bypass|inject|\bxss\b|tamper|unsigned|spoof|traversal|exploit|"
                     r"\bcsrf\b|\bssrf\b|\bredos\b|pollut|without (a )?(valid )?(signature|token|auth)", re.I)
# a verb that says the attack is possible ("accepts", "allows", "works") ...
_PERMIT = re.compile(r"\b(accept|accepts|allow|allows|succeed|succeeds|works?|is solved|solves?|can|possible|"
                     r"able to|let|lets)\b", re.I)
# ... and a verb that says the app defends against it ("rejects", "blocks", "escapes"): such a test is a real guard
# "cannot be bypassed" is a guard; "lack of sanitization" names the hole, so only the verb forms ("sanitizes",
# "sanitized", "is sanitizing") count as protective, never the noun "sanitization"
_PROTECT = re.compile(r"\b(reject|rejects|deny|denies|block|blocks|prevent|prevents|refuse|refuses|throw|throws|"
                      r"cannot|can ?not|can't|not (be )?(accept|allow)|sanitiz(e|es|ed|ing)\b|escap)", re.I)


def asserts_exploit(test_name: str) -> bool:
    """True when a test's name says it checks that an attack works (see above). Such a test failing after a fix is
    expected, so `_validate_run` does not count it against the fix (it is still flagged for review).
    Purely lexical on the test name; deliberately conservative (all three conditions must hold)."""
    return bool(_ATTACK.search(test_name) and _PERMIT.search(test_name) and not _PROTECT.search(test_name))




@dataclass
class Item:
    """One approved plan to validate and the findings it is meant to resolve (the primary one first)."""

    plan: RemediationPlan
    approval: Approval  # the recorded human decision this plan is applied under (G3.3)
    findings: list[Finding]  # findings the fix should clear; a merged batch fix lists several, primary first


# Callback the batch node passes in: settle(item, result[, interaction=True | dropped=True]) records one item's outcome.
Settle = Callable[..., None]


def _still_reported(f: Finding, sb) -> bool:
    """For an image artifact: is the finding's advisory still reported on that package in the rebuilt image?
    `sb.image_vulns` is the (vuln id, package name) list from scanning the built image; matching on the id or one of
    its aliases AND the package name avoids blaming a fix for an unrelated advisory on another package."""
    return bool(f.vuln_id and any(v in (f.vuln_id, *f.aliases) and n == _purl_name(f.component_purl or "")
                                  for v, n in sb.image_vulns))


def _regenerate_stale_lockfiles(rc: RunContext, ok: list[Item], attempt_dir) -> None:
    """A generate_lockfile plan copies the lockfiles discovery resolved for the ORIGINAL manifests. When another plan
    in the same run (or one carried underneath) edits a manifest, those are stale and `npm ci` fails. Remove them
    from the attempt copy so resolve_lockfiles re-resolves from the patched manifests (seeded from discovery's
    locks, then `npm install --package-lock-only --ignore-scripts`). The lockfile plan was applied under its own
    approval; this only replaces the copied files inside the attempt. (Lockfile plans are applied last for the same
    reason: their lockfiles must describe the manifests the other plans patched.)"""
    from guardian.tools.patching import confined  # refuses paths that escape the attempt copy

    lock_items = [it for it in ok if any(o.op == "generate_lockfile" for o in it.plan.ops)]
    editors = [it for it in ok if it not in lock_items
               and any(o.op in DEP_OPS or o.file_path.endswith(("package.json", "requirements.txt"))
                       for o in it.plan.ops)]
    if not lock_items or not editors:
        return
    removed = []
    for it in lock_items:
        for o in it.plan.ops:
            if o.op != "generate_lockfile":
                continue
            for proj in o.args.get("projects") or ["root"]:
                rel = "package-lock.json" if proj == "root" else f"{proj}/package-lock.json"
                path = confined(attempt_dir, rel)
                if path.exists():
                    path.unlink()
                    removed.append(rel)
    rc.audit.emit(AGENT, "decision",
                  f"Lockfile plan combined with {len(editors)} manifest-editing plan(s): its copied lockfiles "
                  f"({', '.join(removed) or 'none'}) would be stale, so they are re-resolved from the patched "
                  f"manifests instead", data={"lockfile_plans": [i.plan.plan_id for i in lock_items],
                                              "editing_plans": [i.plan.plan_id for i in editors]})


def _validate_run(rc: RunContext, items: list[Item], *, combined: bool, round_no: int | None = None,
                  settle: Settle | None = None, limitation: str | None = None
                  ) -> tuple[list[tuple[Item, ValidationResult, bool]], bool]:
    """Apply `items` onto one fresh copy of the target, test once, and judge each plan.

    Returns ([(item, result, applied)], isolate): `isolate` is True when the run failed for a reason no single
    plan can be blamed for and more than one plan was applied; the caller then validates the applied plans
    alone, and `settle` / the PR branch are held back for those.

    `combined` marks a run of several plans together (False: one plan tested alone). `limitation` is a note added to
    a verified result (used when a plan verifies alone but its combination failed).

    Phases: (1) apply every plan's ops to one fresh copy, each under its own approval; (2) re-run the detectors and
    policy check on the copy and diff the findings against the original run; (3) unless the sandbox is off, resolve
    lockfiles for the patched manifests, rescan the SBOM, then build / test in the sandbox; (4) turn all of that into
    one verdict per plan; (5) for verified plans create the local fix branch + PR.md (never pushed, G5.5).

    Verdict precedence, per plan: not applied -> failed_build; else a failure the whole run shares (build / tests /
    timeout, then new findings = regressed) is blamed on every applied plan alike, because one run cannot say which
    plan caused it; else an image that still reports the advisory -> not_resolved; else verified when the target
    findings are gone, not_resolved when they are not. Confidence is HIGH only with a passing build and tests,
    no new test failures and a clean rescan; anything less is MEDIUM (LOW for a non-verified verdict).

    Side effects: attempts/<attempt_id>/ on disk, evidence rows, one ValidationResult file per plan, `settle` calls,
    audit events. The target repository itself is only read.
    """
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    if ctx.budget is not None:
        ctx.budget.window(AGENT)  # G3.6: the tool-call and wall-clock budget applies per validation
    attempt_id = new_id("at")  # one id per run; the plans of a combined run share it and differ by plan_id
    for it in items:
        audit.emit(AGENT, "agent_start",
                   f"Validating plan {it.plan.plan_id} (attempt {it.plan.attempt}) for: {it.findings[0].title[:80]}",
                   finding_id=it.findings[0].finding_id, evidence_ids=it.plan.evidence_ids)
    if combined and len(items) > 1:
        audit.emit(AGENT, "decision",
                   f"Applying {len(items)} approved plans together onto one copy (attempt {attempt_id}): this is "
                   f"what would be merged", data={"attempt_id": attempt_id, "plan_ids": [i.plan.plan_id for i in items]})
    work = ctx.run_dir / "attempts" / attempt_id / "work"  # the patched copy; the first apply_plan call creates it
    applied_out: dict[str, object] = {}  # plan_id -> apply_plan output, None when that plan could not be applied
    # a generate_lockfile plan goes LAST: its lockfiles must describe the manifests the other plans patched
    for it in sorted(items, key=lambda i: any(o.op == "generate_lockfile" for o in i.plan.ops)):
        applied_out[it.plan.plan_id] = call_tool(
            AGENT, "apply_plan", None, ctx, store, audit,
            # "extend": add to the copy the previous plan already made instead of creating a new one
            args={"plan_id": it.plan.plan_id, "attempt_id": attempt_id, "extend": work.exists(),
                  "ops": [o.model_dump(mode="json") for o in it.plan.ops]},
            plan=it.plan, approval=it.approval)  # G3.3: each plan's ops under that plan's own approval
    ok = [it for it in items if applied_out[it.plan.plan_id] is not None]  # plans whose ops were applied cleanly
    for it in items:
        if it not in ok:
            audit.emit(AGENT, "decision", f"Plan {it.plan.plan_id} could not be applied to the copy (failed_build)",
                       finding_id=it.findings[0].finding_id)

    # the file detectors plus each target finding's own detector, in order, without repeats; the allow-list
    # (EXTRA_ALLOW) keeps this agent to detectors it may run on the copy
    detectors = [d for d in dict.fromkeys([*FILE_DETECTORS, *(g.detector for it in ok for g in it.findings)])
                 if d in EXTRA_ALLOW[AGENT]]
    # Collected results of the shared run: findings re-detected on the patched copy, evidence ids, SBOM diff, ...
    after: list[Finding] = []
    det_ev: list[str] = []
    log_ev: list[str] = []
    sb = sandbox.SandboxResult(reason="patch not applied")
    rescanned: str | None = None
    diff_ev_id: str | None = None
    new_vulns: list[str] = []
    new: list[str] = []
    expected_failures: list[str] = []
    resolved: dict[str, bool] = {}  # plan_id -> its target findings are gone from the detectors' re-run
    still: dict[str, bool] = {}  # plan_id -> its advisory is still reported in the rebuilt image (image targets only)
    attempt_dir = work
    actx = None
    shared: str | None = None  # a verdict the whole run failed with (build/tests/timeout/regressed), else None
    if ok:
        actx = ToolContext(run_id=ctx.run_id, run_dir=ctx.run_dir, repo=attempt_dir, settings=ctx.settings,
                           work_dir=attempt_dir, budget=ctx.budget,
                           artifacts={"attempt_id": attempt_id, "target_name": ctx.repo.name, "target_repo": ctx.repo})
        for d in detectors:
            out = call_tool(AGENT, d, None, actx, store, audit)
            if out is not None:
                after += out.findings
                det_ev += [e.evidence_id for e in out.evidence]
        # finding ids differ per run, so findings are compared by finding_key (category + file + title)
        before = {finding_key(g) for g in store.list_findings() if g.detector in detectors}
        now = {finding_key(g) for g in after}
        # a plan is resolved only when EVERY finding it targets is gone (a merged fix targets several)
        resolved = {it.plan.plan_id: all(finding_key(g) not in now for g in it.findings) for it in ok}
        new = sorted(now - before)  # reported on the patched copy but not in the original run: regressions
        # policy-as-code on the patched copy: a fix must not add a policy violation (new rule, or more of one)
        if "policy_check" in EXTRA_ALLOW[AGENT]:
            actx.artifacts["policy_lock_root"] = attempt_dir
            pol = call_tool(AGENT, "policy_check", None, actx, store, audit)
            if pol is not None:
                det_ev += [e.evidence_id for e in pol.evidence]
                new = sorted({*new, *_policy_regressions(store, pol.evidence)})
        if ctx.settings.demo_validator:
            sb = sandbox.SandboxResult(reason="demo mode (GUARDIAN_DEMO_VALIDATOR=1): Docker sandbox not run; the "
                                              "pre-approval sandbox run was simulated")
        elif sandbox.mode() == "off":
            sb = sandbox.SandboxResult(reason="GUARDIAN_SANDBOX=off")
        else:
            # The attempt is a fresh copy of the target, which may ship without lockfiles (Juice Shop:
            # .npmrc package-lock=false). Resolve them for the *patched* manifests before the rescan, else the
            # SBOM diff compares a full tree with a manifest-only one and the upgrade is never actually seen.
            # the baseline lets resolve_lockfiles do a minimal update from discovery's locks instead of a full re-resolve
            actx.artifacts["baseline_lock_root"] = ctx.run_dir / "work"
            _regenerate_stale_lockfiles(rc, ok, attempt_dir)
            rl = call_tool(AGENT, "resolve_lockfiles", "guardian.tools.resolve:resolve_lockfiles", actx, store, audit)
            if rl is not None:
                log_ev += [e.evidence_id for e in rl.evidence]
            rs = call_tool(AGENT, "rescan_patched", None, actx, store, audit)
            if rs is not None:
                rescanned = "sbom.after.cdx.json"
                diff_ev_id = rs.evidence[0].evidence_id
                new_vulns = rs.artifacts.get("new_vulns", [])  # vulnerabilities in the patched SBOM that were not before
                unexpected = _unexpected_added([it.plan for it in ok], rs.artifacts["sbom_diff"]["added"], attempt_dir)
                new = sorted({*new, *(f"vuln:{v}" for v in new_vulns), *(f"dep:{a}" for a in unexpected)})
            # fast path: plans that only pin CI actions / image digests in .github/, Dockerfile*, .gitlab-ci.yml or
            # docker-compose* cannot change what the application builds or tests, so install/build/tests are skipped
            # (and reported as "not run", never "passed"); the detectors, policy check and rescan above still ran
            fast_files = sandbox.fast_path_files([it.plan for it in ok])
            if fast_files is not None:
                sb = sandbox.fast_path_validate(attempt_dir, ctx.run_dir, ctx.run_id, attempt_id,
                                                sandbox._runner or sandbox.default_runner, fast_files)
                audit.emit(AGENT, "decision", f"Fast path: {sb.reason}", finding_id=ok[0].findings[0].finding_id,
                           data={"fast_path": True, "files": fast_files, "phases_skipped": sb.skipped})
            else:
                sv = call_tool(AGENT, "sandbox_validate", None, actx, store, audit)
                if sv is not None:
                    sb = sv.artifacts["sandbox_result"]  # build / test outcome, baseline comparison, failed test names
                    log_ev += [e.evidence_id for e in sv.evidence]
                else:
                    sb = sandbox.SandboxResult(reason="sandbox tool failed")
        if not sb.ran and not sb.fast_path:
            audit.emit(AGENT, "decision", f"Sandbox build/tests not run: {sb.reason}",
                       finding_id=ok[0].findings[0].finding_id,
                       data={"sandbox_mode": sandbox.mode(), "reason": sb.reason})
        if sb.artifact_image:  # G6.7: the built image is the artifact that was rescanned
            rescanned = f"image:{sb.artifact_image}"
            still = {it.plan.plan_id: any(_still_reported(g, sb) for g in it.findings) for it in ok}
        # tests that pass on the unpatched project but fail now. If every one of them asserts that an attack works
        # (see asserts_exploit), the fix is what broke them: the verdict is cleared, the names are disclosed.
        newly_failing = list(sb.failed_names.get("new_vs_baseline") or [])
        if (sb.verdict == "failed_tests" and all(resolved.values()) and sb.build_ok is not False and not new
                and newly_failing and all(asserts_exploit(n) for n in newly_failing)):
            expected_failures = newly_failing
            sb.verdict = None
            audit.emit(AGENT, "decision",
                       f"{len(newly_failing)} newly failing test(s) check that the attack works "
                       f"({'; '.join(n[:80] for n in newly_failing[:3])}): expected once the hole is closed, so "
                       f"not counted against the fix; flagged for review", finding_id=ok[0].findings[0].finding_id,
                       data={"expected_failures": newly_failing})
        # precedence: a build / test / timeout failure outranks "regressed", which outranks everything else, since a
        # broken build makes the detector comparison meaningless
        if sb.verdict in ("failed_build", "failed_tests", "timeout"):
            shared = sb.verdict
        elif new:
            shared = "regressed"
    # a shared failure cannot be blamed on one plan: the caller re-runs each plan alone (isolation) to find the culprit
    isolate = combined and len(ok) > 1 and shared is not None

    # a clean rescan = it happened and found no new vulnerability
    clean = rescanned is not None and not new_vulns
    # HIGH needs build + tests + a clean rescan; failures that already happen on the unpatched project
    # (sandbox baseline) do not count against the fix, they are disclosed in the test_result evidence
    no_new_failures = sb.unit_tests.get("failed", 0) == 0 or (
        sb.baseline is not None and not sb.failed_names.get("new_vs_baseline"))
    pending_pr: list[Item] = []  # verified items that go onto the local fix branch
    # (item, its result, was it applied) for every plan of this run, returned to the caller
    done: list[tuple[Item, ValidationResult, bool]] = []
    for it in items:
        plan, f = it.plan, it.findings[0]
        was_applied = it in ok
        if not was_applied:
            res_ok, verdict = False, "failed_build"
        elif shared is not None:
            res_ok, verdict = resolved[plan.plan_id], shared
        elif still.get(plan.plan_id):
            res_ok, verdict = False, "not_resolved"
        else:
            res_ok = resolved[plan.plan_id]
            verdict = "verified" if res_ok else "not_resolved"
        risk_before, risk_after = _risk_scores(ctx.run_dir, f, plan, res_ok and verdict == "verified")
        # HIGH confidence needs all of: verified, build passed, tests ran and showed no new failures, rescan clean
        high = verdict == "verified" and sb.build_ok is True and sb.tests_ran and no_new_failures and clean
        limits = sandbox.known_limitations(sb, attempt_dir) if was_applied else []
        if limitation and verdict == "verified":
            limits = [*limits, limitation]
        summary_ev = Evidence(run_id=ctx.run_id, kind="test_result", source_tool="validator",
                              facts={"attempt_id": attempt_id, "plan_id": plan.plan_id, "verdict": verdict,
                                     "target_finding_resolved": res_ok, "new_findings": new,
                                     "newly_failing_tests": list(sb.failed_names.get("new_vs_baseline") or []),
                                     "expected_failures": expected_failures,
                                     "detectors_rerun": detectors, "checks_skipped": _skipped(sb, rescanned),
                                     "known_limitations": limits,
                                     "sandbox": sb.reason or ("ran" if sb.ran else "skipped"),
                                     "fast_path": sb.fast_path, "phases_skipped": sb.skipped,
                                     "combined": combined, "round": round_no, "group_failure": isolate and was_applied,
                                     "plan_ids": [i.plan.plan_id for i in items] if combined else [plan.plan_id],
                                     "risk_scale": "risk.json score + simulate_after when available, else band midpoint"})
        store.add_evidence(summary_ev)
        patch_ev = [e.evidence_id for e in (applied_out[plan.plan_id].evidence if was_applied else [])]
        result = ValidationResult(
            attempt_id=attempt_id, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=sb.build_ok,
            unit_tests=sb.unit_tests, integration_tests=sb.integration_tests, artifact_rescanned=rescanned,
            sbom_diff_evidence_id=diff_ev_id, target_finding_resolved=res_ok, new_findings=new,
            detector_evidence_ids=det_ev, risk_before=risk_before, risk_after=risk_after,
            verdict=verdict, final_confidence=(Confidence.HIGH if high else Confidence.MEDIUM)
            if verdict == "verified" else Confidence.LOW,
            log_evidence_ids=[summary_ev.evidence_id, *log_ev, *patch_ev], combined=combined, round=round_no,
            group_failure=isolate and was_applied)  # a shared verdict nobody was blamed for yet
        save_validation(ctx.run_dir, result)
        # when the run is being isolated its shared verdict is provisional: the per-plan isolation runs settle instead,
        # so a plan is never recorded as failed for something another plan broke
        held = isolate and was_applied
        if settle is not None and not held:
            settle(it, result)
        if verdict == "verified":
            pending_pr.append(it)
        done.append((it, result, was_applied))

    pr_rel = None  # relative path of PR.md when a local fix branch was created
    if pending_pr and not isolate and actx is not None:  # D2-10: local branch + PR.md, never pushed (G5.5)
        first = pending_pr[0]
        # only plans whose approval still matches (G3.3) may be committed onto the branch next to the first one
        extra = [it.plan.plan_id for it in pending_pr[1:] if check_write(it.plan, it.approval) is None]
        pr = call_tool(AGENT, "local_fix_branch", None, actx, store, audit,
                       args={"plan_id": first.plan.plan_id, "attempt_id": attempt_id,
                             "finding_id": first.findings[0].finding_id, "also_plan_ids": extra},
                       plan=first.plan, approval=first.approval)
        if pr is not None:
            pr_rel = f"attempts/{attempt_id}/PR.md"
    for it, result, _ in done:
        f = store.get_finding(it.findings[0].finding_id)
        audit.emit(AGENT, "agent_end",
                   f"{result.verdict.upper()}: {f.title[:70]} (target resolved={result.target_finding_resolved}, "
                   f"new findings={len(result.new_findings)}; build={sb.build_ok}, tests_ran={sb.tests_ran}) "
                   f"-> {f.status.value}",
                   finding_id=f.finding_id, evidence_ids=[result.log_evidence_ids[0], *det_ev][:50],
                   data={"attempt_id": attempt_id, "verdict": result.verdict,
                         **({"pr_markdown": pr_rel} if pr_rel and result.verdict == "verified" else {})})
    return done, isolate


def drop_conflicts(new: list[Item], carried: list[Item]) -> tuple[list[Item], list[tuple[Item, Item]]]:
    """Two plans editing the same (manifest, dependency) must never share a combined run (the last edit would win and
    the result would test neither). Keep the one with the higher target version; a carried (already verified) plan
    always stays. Returns (kept new items in their order, [(dropped, the item kept instead)]).
    "Higher version wins" because the higher fix normally also covers what the lower one fixed. Pure function."""
    taken = {k: c for c in carried for k in dep_keys(c.plan.ops)}  # (manifest, dependency) -> the item that owns it
    keep: set[int] = set()
    dropped: list[tuple[Item, Item]] = []
    # highest target first, so the first claimant of a dependency is the one that stays
    for it in sorted(new, key=lambda i: version_key(i.plan.target_version or "0"), reverse=True):
        clash = next((taken[k] for k in dep_keys(it.plan.ops) if k in taken), None)
        if clash is not None:
            dropped.append((it, clash))
            continue
        keep.add(id(it))
        taken.update({k: it for k in dep_keys(it.plan.ops)})
    return [i for i in new if id(i) in keep], dropped


_NPM_DROP_OPS = {"remove_dependency", "block_package", "replace_dependency"}


def _nearest_manifest(repo, rel: str) -> str:
    """Directory (posix, '' for the repo root) of the package.json that owns source file `rel`."""
    from pathlib import PurePosixPath
    d = PurePosixPath(rel).parent
    while True:
        if (repo / d / "package.json").is_file() or str(d) in ("", "."):
            return "" if str(d) == "." else str(d)
        d = d.parent


def still_imported(repo, plan: RemediationPlan) -> str | None:
    """Cheap pre-flight (no sandbox): does a plan that DROPS an npm package leave source code importing it?

    Covers remove_dependency / block_package / replace_dependency. For a replace, the files the plan itself renames
    (rename_import ops) do not count. Only production source owned by the same package.json counts (tests are
    skipped by reachability; a sub-project with its own manifest is judged by that manifest). Returns the reason
    text naming the first import site, or None (also when nothing could be scanned: unknown never blocks)."""
    from pathlib import PurePosixPath

    from guardian.tools.reachability import import_index

    index = None
    for o in plan.ops:
        name = str(o.args.get("name") or "")
        if o.op not in _NPM_DROP_OPS or not name or PurePosixPath(o.file_path).name != "package.json":
            continue
        if index is None:
            index = import_index(repo, "npm")[0]
        renamed = {r.file_path for r in plan.ops if r.op == "rename_import" and r.args.get("name") == name}
        owner = str(PurePosixPath(o.file_path).parent)
        owner = "" if owner == "." else owner
        for h in index.get(name, []):
            if h["file"] not in renamed and _nearest_manifest(repo, h["file"]) == owner:
                return (f"the package '{name}' is still imported by {h['file']}:{h['line']}; remove or replace the "
                        f"imports first")
    return None


def _preflight_failure(rc: RunContext, it: Item, reason: str, round_no: int | None, settle: Settle) -> ValidationResult:
    """Record an approved plan as failed WITHOUT a sandbox run (verdict still_imported) and settle it, so it comes back
    with another alternative like any failed fix. Nothing is applied; build / tests are recorded as not run."""
    ctx, store = rc.tool_ctx, rc.store
    plan, f = it.plan, it.findings[0]
    attempt_id = new_id("at")
    rc.audit.emit(AGENT, "agent_start", f"Validating plan {plan.plan_id} (attempt {plan.attempt}) for: {f.title[:80]}",
                  finding_id=f.finding_id, evidence_ids=plan.evidence_ids)
    ev = Evidence(run_id=ctx.run_id, kind="test_result", source_tool="validator",
                  facts={"attempt_id": attempt_id, "plan_id": plan.plan_id, "verdict": "still_imported",
                         "target_finding_resolved": False, "new_findings": [], "newly_failing_tests": [],
                         "expected_failures": [], "detectors_rerun": [], "known_limitations": [reason],
                         "checks_skipped": ["pre-flight failed: sandbox not started"], "sandbox": "skipped (pre-flight)",
                         "combined": False, "round": round_no, "plan_ids": [plan.plan_id], "reason": reason})
    store.add_evidence(ev)
    before, after = _risk_scores(ctx.run_dir, f, plan, False)
    res = ValidationResult(attempt_id=attempt_id, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=None,
                           target_finding_resolved=False, risk_before=before, risk_after=after,
                           verdict="still_imported", final_confidence=Confidence.LOW,
                           log_evidence_ids=[ev.evidence_id], combined=False, round=round_no, reason=reason)
    save_validation(ctx.run_dir, res)
    rc.audit.emit(AGENT, "decision", f"Pre-flight: {reason} (plan {plan.plan_id} not sent to the sandbox)",
                  finding_id=f.finding_id, data={"plan_id": plan.plan_id, "reason": reason})
    settle(it, res)
    f = store.get_finding(f.finding_id)
    rc.audit.emit(AGENT, "agent_end", f"STILL_IMPORTED: {f.title[:70]} ({reason}) -> {f.status.value}",
                  finding_id=f.finding_id, evidence_ids=[ev.evidence_id],
                  data={"attempt_id": attempt_id, "verdict": "still_imported"})
    return res


def validate_plans(rc: RunContext, items: list[Item], round_no: int, settle: Settle,
                   carried: list[Item] | None = None) -> dict[str, ValidationResult]:
    """Batch validation of a round's approved plans. Returns the final ValidationResult per plan_id.

    Mitigate plans change nothing and are recorded on their own. The rest are applied together and tested once;
    if the combination fails for a reason no plan can be blamed for, the set is bisected to find the culprit(s).

    `carried` are plans already verified in earlier rounds: they are applied underneath this round's plans (each under
    its own recorded approval) so the final set is tested as one. They get a result in the combined run, but
    `settle` must only change their outcome when it is shown that one of them is the culprit. If the search clears
    everything, the carried plans stay verified and the new plans are sent back (`settle(..., interaction=True)`).
    Plans that clash on one dependency are dropped first (`drop_conflicts`) and reported via `settle(dropped=True)`.

    Order of work: mitigate plans -> drop clashes -> pre-flight (a plan that drops a package the source still
    imports fails at once, verdict still_imported, and never enters the sandbox) -> one combined run (carried plans
    first) -> if that failed for a shared reason, bisection: split the new plans in halves, test each half together
    (carried plans stay underneath), recurse only into a failing half. A failing group of one plan is the culprit
    (with carried plans underneath it is first run alone: if it verifies alone it is an *interaction*). Plans in
    passing groups are verified. When every part passes but the whole failed, that is an interaction between the
    parts: each is reported verified on its own with a note that the combination is NOT verified (with carried
    plans the new ones are sent back instead). A shared failure result carries `group_failure=True`: it says
    nothing about one plan. Returns {plan_id: final ValidationResult}."""
    audit = rc.audit
    carried = carried or []
    final: dict[str, ValidationResult] = {}
    real = []  # plans that change files (mitigate plans change nothing, so they skip the sandbox)
    # the per-validation tool budget window (G3.6) is reset for each mitigate plan here and inside _validate_run
    for it in items:
        if it.plan.action == "mitigate":
            if rc.tool_ctx.budget is not None:
                rc.tool_ctx.budget.window(AGENT)
            attempt_id = new_id("at")
            audit.emit(AGENT, "agent_start", f"Recording mitigation plan {it.plan.plan_id} for: "
                       f"{it.findings[0].title[:80]}", finding_id=it.findings[0].finding_id)
            _mitigated(rc, it.plan, it.approval, it.findings[0], attempt_id)
            res = next((v for v in list_validations(rc.tool_ctx.run_dir) if v.attempt_id == attempt_id), None)
            if res is not None:
                final[it.plan.plan_id] = res
                settle(it, res)
        else:
            real.append(it)
    real, dropped = drop_conflicts(real, carried)
    for it, kept in dropped:
        audit.emit(AGENT, "decision",
                   f"Plan {it.plan.plan_id} edits the same dependency as plan {kept.plan.plan_id}: only the higher "
                   f"version is validated, this one goes back for another alternative",
                   finding_id=it.findings[0].finding_id,
                   data={"dropped": it.plan.plan_id, "kept": kept.plan.plan_id})
        settle(it, None, dropped=True)
    # pre-flight: an approved plan that removes a package the source still imports cannot build; fail it now (it
    # needs no sandbox) and keep it out of the combined run so it cannot sink the other plans
    kept_real = []
    for it in real:
        reason = still_imported(rc.tool_ctx.repo, it.plan)
        if reason is None:
            kept_real.append(it)
        else:
            final[it.plan.plan_id] = _preflight_failure(rc, it, reason, round_no, settle)
    real = kept_real
    if not real:
        return final
    n_new = len(real)
    # carried plans go first: they are the base the new ones are applied on (and the lockfile plan still goes last,
    # which _validate_run sorts out itself)
    all_items = [*carried, *real]
    carried_ids = {c.plan.plan_id for c in carried}
    if carried:
        audit.emit(AGENT, "decision", f"Round {round_no}: {len(carried)} fix(es) verified earlier are applied underneath "
                   f"the {n_new} new one(s), so the final set is tested as one")
    done, isolate = _validate_run(rc, all_items, combined=len(all_items) > 1, round_no=round_no, settle=settle)
    for it, res, _ in done:
        final[it.plan.plan_id] = res
    combined_id = done[0][1].attempt_id
    if not isolate:
        if len(all_items) > 1:
            bad = [r.verdict for _, r, _ in done if r.verdict != "verified"]
            audit.emit(AGENT, "decision",
                       f"Combined validation of {len(all_items)} plans (attempt {combined_id}): "
                       + ("all verified together" if not bad else
                          f"{len(bad)} not verified ({', '.join(sorted(set(bad)))})"),
                       data={"attempt_id": combined_id,
                             "verdicts": {i.plan.plan_id: r.verdict for i, r, _ in done}})
        return final
    shared = next(r.verdict for _, r, was in done if was)  # every applied plan got the same shared verdict
    suspects = [it for it, _r, was in done if was and it.plan.plan_id not in carried_ids]  # the new, applied plans
    audit.emit(AGENT, "decision",
               f"Combined validation of {len(all_items)} plans failed ({shared}): bisecting the {len(suspects)} new "
               f"plan(s) (testing halves together) to find which one(s) break it",
               data={"attempt_id": combined_id, "verdict": shared, "runs": "bisection"})
    note = (f"verified in a smaller group, but the combined run of {len(all_items)} approved plans (attempt "
            f"{combined_id}) failed ({shared}): this combination is NOT verified")
    if carried:
        note += (f"; it includes {len(carried)} fix(es) verified in earlier rounds and the interaction was "
                 f"not resolved")
    held: list[tuple[Item, ValidationResult]] = []  # results settled only once every group was tried (carried plans)
    runs = 0

    def test(group: list[Item], alone: bool = False) -> tuple[list[tuple[Item, ValidationResult, bool]], bool]:
        """One sandbox run of `group` on top of the carried plans (or truly alone)."""
        nonlocal runs
        runs += 1
        base = [] if alone else carried
        # with carried plans the outcome is decided after ALL runs (see the end), so settle is held back
        out, iso = _validate_run(rc, [*base, *group], combined=len(base) + len(group) > 1, round_no=round_no,
                                 settle=None if carried else settle, limitation=note)
        for it, res, _ in out:
            if it.plan.plan_id not in carried_ids:
                final[it.plan.plan_id] = res
        return out, iso

    def search(group: list[Item]) -> None:
        """`group` failed: test its halves, recurse only into a failing half."""
        if len(group) == 1:  # the failed run already was this plan on top of the carried ones: only "alone" is left
            held.append((group[0], test(group, alone=True)[0][0][1]))
            return
        mid = len(group) // 2
        for half in (group[:mid], group[mid:]):
            if not half:
                continue
            out, iso = test(half)
            if iso and len(half) > 1:
                search(half)
            elif iso:  # one new plan fails on top of the carried ones: does it also fail on its own?
                alone_out, _ = test(half, alone=True)
                held.append((half[0], alone_out[0][1]))
            else:
                held.extend((it, res) for it, res, _ in out if it.plan.plan_id not in carried_ids)

    search(suspects)
    culprits = [it.plan.plan_id for it in suspects if final[it.plan.plan_id].verdict != "verified"]
    if carried:  # decide after every group was tried: only then is it known whether an interaction is the cause
        for it, res in held:
            if culprits:
                settle(it, res)
            else:  # everything verifies, yet together with the earlier fixes it fails
                settle(it, res, interaction=True)
    audit.emit(AGENT, "decision",
               (f"Isolation: {len(culprits)} plan(s) fail alone ({', '.join(culprits)}); the rest verify "
                f"({runs} group runs instead of {len(suspects)} runs alone)"
                if culprits else
                f"Isolation: every plan verifies alone but the combination with the earlier fixes failed "
                f"({shared}): interaction NOT resolved, earlier fixes stay verified, the new fix(es) go back"
                if carried else
                f"Isolation: every plan verifies alone but the combination failed ({shared}): an interaction "
                f"between the plans, reported as verified individually and NOT as a verified combination"),
               data={"culprits": culprits, "combined_attempt_id": combined_id, "group_runs": runs})
    return final


def validator_node(state: GraphState) -> dict:
    """Sequential mode: validate the one approved plan of the current finding and decide where the run goes next.

    Reads state: plan_id and decision (the approval). A `mitigate` plan is only recorded (`_mitigated`). Any other plan
    is validated alone through `_validate_run`; its `settle` callback sets the finding's status: verified -> next
    finding; failed with attempts left -> "replan" with last_validation = {verdict, attempt_id, new findings} so
    remediation picks a different plan; failed at MAX_ATTEMPTS (G5.4) -> ESCALATED. Returns the state update."""
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    if ctx.budget is not None:
        ctx.budget.window(AGENT)  # G3.6: the tool-call and wall-clock budget applies per validation
    plan = load_plan(ctx.run_dir, state["plan_id"])
    approval = Approval.model_validate(state["decision"])
    f = store.get_finding(plan.finding_id)
    if plan.action == "mitigate":
        audit.emit(AGENT, "agent_start", f"Validating plan {plan.plan_id} (attempt {plan.attempt}) for: {f.title[:80]}",
                   finding_id=f.finding_id, evidence_ids=plan.evidence_ids)
        return _mitigated(rc, plan, approval, f, new_id("at"))
    out: dict = {}  # filled by settle() below with the routing state the graph needs

    def settle(it: Item, result: ValidationResult) -> None:
        """Callback from _validate_run: set the finding's final status and the next route from the verdict."""
        if result.verdict == "verified":
            f.status = FindingStatus.VERIFIED
            out.update({"route": "next", "current": None, "attempt": 0, "plan_id": None, "last_validation": None})
        elif plan.attempt >= MAX_ATTEMPTS:
            f.status = FindingStatus.ESCALATED
            out.update({"route": "next", "current": None, "attempt": 0, "plan_id": None, "last_validation": None})
        else:
            f.status = FindingStatus.PLANNED
            out.update({"route": "replan", "last_validation": {"verdict": result.verdict,
                                                               "attempt_id": result.attempt_id,
                                                               "new": result.new_findings}})
        store.update_finding(f)

    _validate_run(rc, [Item(plan, approval, [f])], combined=False, settle=settle)
    return out
