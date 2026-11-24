"""Validator (Day-1 form): apply the approved plan to a fresh copy and re-run the detectors (C4). Owner: Dev1.

Verdict (D2-08 adds the Docker sandbox: build, tests, SBOM rescan + diff; see tools/sandbox.py):
  verified      the target finding is gone from its detector's re-run and no detector reports anything new
  regressed     a re-run detector reports a finding the original run did not have (never verified)
  not_resolved  the target finding is still reported
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
"""

from __future__ import annotations

import json

from guardian.core.models import (
    Approval,
    Confidence,
    Evidence,
    Finding,
    FindingCategory,
    FindingStatus,
    Priority,
    RiskAssessment,
    ValidationResult,
    new_id,
)
from guardian.core.plans import load_plan, save_validation
from guardian.graph.state import GraphState, get_ctx
from guardian.tools import sandbox
from guardian.tools.registry import EXTRA_ALLOW, ToolContext, call_tool

AGENT = "validator"
MAX_ATTEMPTS = 3
FILE_DETECTORS = ["detector:lockfile", "detector:typosquat", "detector:ci_pin", "detector:image_pin"]
BAND_SCORE = {Priority.CRITICAL: 90.0, Priority.HIGH: 70.0, Priority.MEDIUM: 50.0, Priority.LOW: 20.0, None: 50.0}


def _skipped(sb, rescanned: str | None) -> list[str]:
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
    base = purl.split("/", 1)[-1]
    return base.rsplit("@", 1)[0].replace("%40", "@") if "@" in base[1:] else base


def _unexpected_added(plan, added: list[str]) -> list[str]:
    """New components the plan did not ask for. A generate_lockfile plan legitimately adds the whole tree."""
    if any(o.op == "generate_lockfile" for o in plan.ops):
        return []
    wanted = {str(v) for o in plan.ops for v in o.args.values() if isinstance(v, str)}
    return [a for a in added if _purl_name(a) not in wanted]


def _mitigated(rc, plan, approval: Approval, f: Finding, attempt_id: str) -> dict:
    """A mitigate plan has no ops: record the accepted mitigation, never claim a fix."""
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
    return {e.facts["rule"]: int(e.facts.get("count", 0)) for e in evidence
            if e is not None and e.kind == "policy_result" and e.facts.get("rule")}


def _policy_regressions(store, after_evidence) -> list[str]:
    """Rules violated more often after the patch than in the original run ("policy:<rule>")."""
    before_ev = [store.get_evidence(i) for g in store.list_findings() if g.detector == "detector:policy_check"
                 for i in g.evidence_ids]
    before, after = _policy_counts(before_ev), _policy_counts(after_evidence)
    return [f"policy:{r}" for r, n in sorted(after.items()) if n > before.get(r, 0)]


def validator_node(state: GraphState) -> dict:
    rc = get_ctx(state["run_id"])
    ctx, store, audit = rc.tool_ctx, rc.store, rc.audit
    plan = load_plan(ctx.run_dir, state["plan_id"])
    approval = Approval.model_validate(state["decision"])
    f = store.get_finding(plan.finding_id)
    attempt_id = new_id("at")
    audit.emit(AGENT, "agent_start", f"Validating plan {plan.plan_id} (attempt {plan.attempt}) for: {f.title[:80]}",
               finding_id=f.finding_id, evidence_ids=plan.evidence_ids)
    if plan.action == "mitigate":
        return _mitigated(rc, plan, approval, f, attempt_id)

    applied = call_tool(AGENT, "apply_plan", None, ctx, store, audit,
                        args={"plan_id": plan.plan_id, "attempt_id": attempt_id,
                              "ops": [o.model_dump(mode="json") for o in plan.ops]},
                        plan=plan, approval=approval)
    detectors = [d for d in dict.fromkeys([*FILE_DETECTORS, f.detector]) if d in EXTRA_ALLOW[AGENT]]
    after: list[Finding] = []
    det_ev: list[str] = []
    log_ev: list[str] = []
    sb = sandbox.SandboxResult(reason="patch not applied")
    rescanned: str | None = None
    diff_ev_id: str | None = None
    new_vulns: list[str] = []
    if applied is not None:
        attempt_dir = applied.artifacts["attempt_dir"]
        actx = ToolContext(run_id=ctx.run_id, run_dir=ctx.run_dir, repo=attempt_dir, settings=ctx.settings,
                           work_dir=attempt_dir, budget=ctx.budget,
                           artifacts={"attempt_id": attempt_id, "target_name": ctx.repo.name, "target_repo": ctx.repo})
        for d in detectors:
            out = call_tool(AGENT, d, None, actx, store, audit)
            if out is not None:
                after += out.findings
                det_ev += [e.evidence_id for e in out.evidence]
        before = {finding_key(g) for g in store.list_findings() if g.detector in detectors}
        now = {finding_key(g) for g in after}
        resolved = finding_key(f) not in now
        new = sorted(now - before)
        # policy-as-code on the patched copy: a fix must not add a policy violation (new rule, or more of one)
        if "policy_check" in EXTRA_ALLOW[AGENT]:
            actx.artifacts["policy_lock_root"] = attempt_dir
            pol = call_tool(AGENT, "policy_check", None, actx, store, audit)
            if pol is not None:
                det_ev += [e.evidence_id for e in pol.evidence]
                new = sorted({*new, *_policy_regressions(store, pol.evidence)})
        if sandbox.mode() == "off":
            sb = sandbox.SandboxResult(reason="GUARDIAN_SANDBOX=off")
        else:
            # The attempt is a fresh copy of the target, which may ship without lockfiles (Juice Shop:
            # .npmrc package-lock=false). Resolve them for the *patched* manifests before the rescan, else the
            # SBOM diff compares a full tree with a manifest-only one and the upgrade is never actually seen.
            actx.artifacts["baseline_lock_root"] = ctx.run_dir / "work"  # minimal update from discovery's locks
            rl = call_tool(AGENT, "resolve_lockfiles", "guardian.tools.resolve:resolve_lockfiles", actx, store, audit)
            if rl is not None:
                log_ev += [e.evidence_id for e in rl.evidence]
            rs = call_tool(AGENT, "rescan_patched", None, actx, store, audit)
            if rs is not None:
                rescanned = "sbom.after.cdx.json"
                diff_ev_id = rs.evidence[0].evidence_id
                new_vulns = rs.artifacts.get("new_vulns", [])
                unexpected = _unexpected_added(plan, rs.artifacts["sbom_diff"]["added"])
                new = sorted({*new, *(f"vuln:{v}" for v in new_vulns), *(f"dep:{a}" for a in unexpected)})
            sv = call_tool(AGENT, "sandbox_validate", None, actx, store, audit)
            if sv is not None:
                sb = sv.artifacts["sandbox_result"]
                log_ev += [e.evidence_id for e in sv.evidence]
            else:
                sb = sandbox.SandboxResult(reason="sandbox tool failed")
        if not sb.ran:
            audit.emit(AGENT, "decision", f"Sandbox build/tests not run: {sb.reason}",
                       finding_id=f.finding_id, data={"sandbox_mode": sandbox.mode(), "reason": sb.reason})
        if sb.artifact_image:  # G6.7: the built image is the artifact that was rescanned
            rescanned = f"image:{sb.artifact_image}"
            still = f.vuln_id and any(v in (f.vuln_id, *f.aliases) and n == _purl_name(f.component_purl or "")
                                      for v, n in sb.image_vulns)
        else:
            still = False
        if sb.verdict in ("failed_build", "failed_tests", "timeout"):
            verdict = sb.verdict
        elif new:
            verdict = "regressed"
        elif still:
            verdict, resolved = "not_resolved", False
        else:
            verdict = "verified" if resolved else "not_resolved"
    else:
        resolved, new, verdict = False, [], "failed_build"

    risk_before, risk_after = _risk_scores(ctx.run_dir, f, plan, resolved and verdict == "verified")
    clean = rescanned is not None and not new_vulns
    # HIGH needs build + tests + a clean rescan; failures that already happen on the unpatched project
    # (sandbox baseline) do not count against the fix, they are disclosed in the test_result evidence
    no_new_failures = sb.unit_tests.get("failed", 0) == 0 or (
        sb.baseline is not None and not sb.failed_names.get("new_vs_baseline"))
    high = verdict == "verified" and sb.build_ok is True and sb.tests_ran and no_new_failures and clean
    summary_ev = Evidence(run_id=ctx.run_id, kind="test_result", source_tool="validator",
                          facts={"attempt_id": attempt_id, "plan_id": plan.plan_id, "verdict": verdict,
                                 "target_finding_resolved": resolved, "new_findings": new,
                                 "detectors_rerun": detectors, "checks_skipped": _skipped(sb, rescanned),
                                 "known_limitations": sandbox.known_limitations(sb, applied.artifacts["attempt_dir"])
                                 if applied is not None else [],
                                 "sandbox": sb.reason or ("ran" if sb.ran else "skipped"),
                                 "risk_scale": "risk.json score + simulate_after when available, else band midpoint"})
    store.add_evidence(summary_ev)
    patch_ev = [e.evidence_id for e in (applied.evidence if applied else [])]
    result = ValidationResult(
        attempt_id=attempt_id, plan_id=plan.plan_id, finding_id=f.finding_id, build_ok=sb.build_ok,
        unit_tests=sb.unit_tests, integration_tests=sb.integration_tests, artifact_rescanned=rescanned,
        sbom_diff_evidence_id=diff_ev_id, target_finding_resolved=resolved, new_findings=new,
        detector_evidence_ids=det_ev, risk_before=risk_before, risk_after=risk_after,
        verdict=verdict, final_confidence=(Confidence.HIGH if high else Confidence.MEDIUM) if verdict == "verified" else Confidence.LOW,
        log_evidence_ids=[summary_ev.evidence_id, *log_ev, *patch_ev])
    save_validation(ctx.run_dir, result)

    if verdict == "verified":
        f.status = FindingStatus.VERIFIED
        out = {"route": "next", "current": None, "attempt": 0, "plan_id": None, "last_validation": None}
    elif plan.attempt >= MAX_ATTEMPTS:
        f.status = FindingStatus.ESCALATED
        out = {"route": "next", "current": None, "attempt": 0, "plan_id": None, "last_validation": None}
    else:
        f.status = FindingStatus.PLANNED
        out = {"route": "replan", "last_validation": {"verdict": verdict, "attempt_id": attempt_id, "new": new}}
    store.update_finding(f)
    pr_rel = None
    if verdict == "verified" and applied is not None:  # D2-10: local branch + PR.md, never pushed (G5.5)
        pr = call_tool(AGENT, "local_fix_branch", None, actx, store, audit,
                       args={"plan_id": plan.plan_id, "attempt_id": attempt_id, "finding_id": f.finding_id},
                       plan=plan, approval=approval)
        if pr is not None:
            pr_rel = f"attempts/{attempt_id}/PR.md"
    audit.emit(AGENT, "agent_end",
               f"{verdict.upper()}: {f.title[:70]} (target resolved={resolved}, new findings={len(new)}; "
               f"build={sb.build_ok}, tests_ran={sb.tests_ran}) -> {f.status.value}",
               finding_id=f.finding_id, evidence_ids=[summary_ev.evidence_id, *det_ev][:50],
               data={"attempt_id": attempt_id, "verdict": verdict, **({"pr_markdown": pr_rel} if pr_rel else {})})
    return out
