/**
 * Validation page: did each approved fix work in the sandbox? Shows the verdict, what was tested together, the
 * attempt timeline, risk before and after, the checks, the package changes and raw logs.
 */
import { AlertTriangle, Check, CheckCircle2, ChevronDown, ChevronRight, Circle, Search, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { Evidence, Finding, RemediationPlan, ValidationResult } from "../api/types";
import { bandOf, plural } from "../lib/format";
import { evidenceTitle, failLine, plainTitle, verdictFail } from "../lib/labels";
import { decisionOf, planSummary } from "../lib/plan";
import { useStore } from "../store";
import { useCountTween, useEvidence, useEvidenceMany } from "./hooks";
import { Callout, EmptyState, Json, Section, Skeleton } from "./ui";

// One proposed plan and its sandbox result. val is undefined until the plan has been validated, or when it
// never ran (rejected or risk accepted).
interface Attempt {
  plan: RemediationPlan;
  val: ValidationResult | undefined;
}

// Plain-words reason for a failed verdict.
const failWord = verdictFail;

/**
 * The result that speaks for a plan: its latest one that is not just a shared group failure (a smaller group, the plan
 * alone, or a pre-flight verdict), else the latest group failure (not isolated yet).
 */
function resultFor(planId: string, all: ValidationResult[]): ValidationResult | undefined {
  // Attempt IDs are time-ordered ULIDs. Do not depend on API response order.
  const mine = all.filter((v) => v.plan_id === planId)
    .sort((a, b) => a.attempt_id < b.attempt_id ? -1 : a.attempt_id > b.attempt_id ? 1 : 0);
  return [...mine].reverse().find((v) => !v.group_failure) ?? mine[mine.length - 1];
}

/** "Round 2: 5 fixes tested together" for a combined run, "tested alone" for an isolation run, nothing for older runs. */
function testedLabel(v: ValidationResult, all: ValidationResult[]): { text: string; cls: string } | null {
  if (v.combined) {
    const n = all.filter((x) => x.attempt_id === v.attempt_id).length;
    return { text: `${v.round != null ? `Round ${v.round}: ` : ""}${plural(n, "fix", "fixes")} tested together`, cls: "info" };
  }
  if (v.combined === false && all.some((x) => x.combined)) return { text: `${v.round != null ? `Round ${v.round}: ` : ""}tested alone`, cls: "" };
  return null;
}

/** Which fixes were tested in the same sandbox run, so a combined result is not mistaken for one fix's result. */
function Rounds({ onPick, current }: { onPick: (findingId: string) => void; current: string }) {
  const { data, findingsById, riskById, plansById } = useStore();
  // Results grouped by sandbox run (attempt_id), in round order.
  const groups = useMemo(() => {
    const by = new Map<string, ValidationResult[]>();
    for (const v of data.validation) (by.get(v.attempt_id) ?? by.set(v.attempt_id, []).get(v.attempt_id)!).push(v);
    return [...by.values()].sort((a, b) => (a[0].round ?? 0) - (b[0].round ?? 0));
  }, [data.validation]);
  // Runs from before combined testing have no `combined` flag: nothing to explain.
  if (!data.validation.some((v) => v.combined)) return null;
  return (
    <Section title="What was tested together" lead="Approved fixes are applied to one sandbox copy and tested once, because that is what would be merged. If that fails, each fix is tested alone to find the one that broke it.">
      <div className="rounds">
        {groups.map((g) => {
          const lab = testedLabel(g[0], data.validation);
          const failed = g.some((v) => v.verdict !== "verified");
          return (
            <div key={g[0].attempt_id} className="round">
              <p className="round-head">
                <b>{lab?.text ?? "Tested"}</b>{" "}
                <span className={`pill ${failed ? "bad" : "ok"}`}>{failed ? (g.length > 1 ? "Some did not pass" : "Did not pass") : g.length > 1 ? "All passed" : "Passed"}</span>
              </p>
              <ul className="plain round-list">
                {g.map((v) => {
                  const plan = plansById.get(v.plan_id);
                  const f = findingsById.get(v.finding_id);
                  const band = f ? bandOf(f, riskById) : null;
                  return (
                    <li key={v.plan_id}>
                      <button type="button" className={`linkish${v.finding_id === current ? " on" : ""}`} aria-current={v.finding_id === current ? "true" : undefined} onClick={() => onPick(v.finding_id)}>
                        {plan ? planSummary(plan, f, band).change : v.plan_id}
                      </button>
                      <span className={`pill ${v.verdict === "verified" ? "ok" : v.group_failure ? "" : "bad"}`}>{v.verdict === "verified" ? "Verified" : failLine(v)}</span>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </div>
    </Section>
  );
}

/** Picks a finding (default: the first with a result) and lays out its verdict, timeline and attempt detail. */
export default function ValidationView() {
  const { data, findingsById, riskById } = useStore();
  // Findings with at least one plan (a valid pick from the rounds list below) ...
  const ids = useMemo(() => [...new Set(data.plans.map((p) => p.finding_id))], [data.plans]);
  // ... but the picker lists only findings whose fix was actually tried in the sandbox, most recent attempt first
  // (attempt ids are ULIDs, so they sort by time). Fixes still waiting for a decision live on the Remediation page.
  const tested = useMemo(() => {
    const last = new Map<string, string>();
    for (const v of data.validation) {
      if ((last.get(v.finding_id) ?? "") < v.attempt_id) last.set(v.finding_id, v.attempt_id);
    }
    return [...last.entries()].sort((a, b) => (a[1] < b[1] ? 1 : -1)).map(([i]) => i);
  }, [data.validation]);
  const [fid, setFid] = useState<string | null>(null);
  // The selected finding, or the most recently tested one.
  const current = fid && ids.includes(fid) ? fid : (tested[0] ?? ids[0]);
  const waiting = ids.length - tested.length;

  if (!ids.length)
    return (
      <EmptyState title="Nothing has been validated yet" center>
        After you approve a fix, Guardian applies it to a sandbox copy, builds, tests and re-scans it. The result appears here.
      </EmptyState>
    );

  // This finding's plans in order, each paired with its validation result if there is one.
  const attempts: Attempt[] = data.plans
    .filter((p) => p.finding_id === current)
    .map((plan) => ({ plan, val: resultFor(plan.plan_id, data.validation) }));
  const f = findingsById.get(current);

  return (
    <div className="val">
      <div className="val-in">
        <header className="page-head">
          <h1>Validation</h1>
          <p className="muted">Did the fix work? Guardian tries every fix on a sandbox copy before anyone relies on it.</p>
          {tested.length > 0 && (
            <label className="select-row">
              <span className="muted">Tested fix</span>
              <select value={current} onChange={(e) => setFid(e.target.value)}>
                {/* a fix picked from the rounds list that has no result yet still needs an option to show */}
                {!tested.includes(current) && <option value={current}>{(() => { const g = findingsById.get(current); return g ? plainTitle(g, bandOf(g, riskById)) : current; })()}</option>}
                {tested.map((i, n) => {
                  const g = findingsById.get(i);
                  return (
                    <option key={i} value={i}>
                      {g ? plainTitle(g, bandOf(g, riskById)) : i}{n === 0 ? " (latest)" : ""}
                    </option>
                  );
                })}
              </select>
            </label>
          )}
          {waiting > 0 && (
            <p className="muted" style={{ fontSize: "var(--fs-sm)", marginTop: "var(--s2)" }}>
              {tested.length} {tested.length === 1 ? "fix has" : "fixes have"} been tested. {waiting} other suggested{" "}
              {waiting === 1 ? "fix is" : "fixes are"} not tested yet: approve them on the Remediation page.
            </p>
          )}
        </header>
        <Rounds current={current} onPick={setFid} />
        <Verdict attempts={attempts} title={f ? plainTitle(f, bandOf(f, riskById)) : ""} finding={f} />
        <Timeline attempts={attempts} />
        <AttemptDetail key={current} attempts={attempts} />
      </div>
    </div>
  );
}

/** Headline banner for a finding: verified, rejected, risk accepted, waiting, or failed. */
function Verdict({ attempts, title, finding }: { attempts: Attempt[]; title: string; finding: Finding | undefined }) {
  const { riskById, data } = useStore();
  const last = attempts[attempts.length - 1];
  // Attempts that ran in the sandbox and did not verify.
  const failed = attempts.filter((a) => a.val && a.val.verdict !== "verified" && !a.val.group_failure);
  // Attempts rejected before any sandbox run, so they have no result.
  const turnedDown = attempts.filter((a) => !a.val && decisionOf(a.plan.plan_id, data.approvals) === "reject");
  const ok = attempts.find((a) => a.val?.verdict === "verified");
  const okEv = useEvidenceMany(ok?.val?.log_evidence_ids ?? []);
  // Number of expected-failure tests (they check the attack works, so they fail once it is fixed) that a person
  // should confirm before merging.
  const review = ((okEv.items.find((e) => e.source_tool === "validator")?.facts as ValidatorFacts | undefined)?.expected_failures ?? []).length;
  if (ok?.val) {
    const checksPassed = ok.val.build_ok === true
      && (ok.val.unit_tests.passed ?? 0) > 0 && (ok.val.unit_tests.failed ?? 0) === 0
      && (ok.val.integration_tests.passed ?? 0) > 0 && (ok.val.integration_tests.failed ?? 0) === 0;
    const sm = planSummary(ok.plan, finding, finding ? bandOf(finding, riskById) : null);
    const earlier = [
      failed.length ? `${failed.length} did not work` : "",
      turnedDown.length ? `${turnedDown.length} ${turnedDown.length === 1 ? "was" : "were"} rejected` : "",
    ].filter(Boolean);
    const heading = review && ok.val.build_ok === true
      ? `Verified, with ${review} test${review === 1 ? "" : "s"} to review: the vulnerability is gone and the build passed`
      : checksPassed
        ? "Validated: the targeted issue is gone, and the build and recorded tests passed"
        : "The targeted issue is gone; build or test checks are incomplete";
    return (
      <Callout tone={checksPassed || (review && ok.val.build_ok === true) ? "ok" : "info"} title={heading} icon={<CheckCircle2 size={20} aria-hidden />}>
        The fix that worked: {sm.change}. It resolves: {title}.
        {earlier.length ? ` It took ${attempts.length} attempts; of the earlier ones, ${earlier.join(" and ")}, and Guardian re-planned.` : ""}
      </Callout>
    );
  }
  const lastDecision = last && !last.val ? decisionOf(last.plan.plan_id, data.approvals) : null;
  if (lastDecision === "reject")
    return (
      <Callout tone="bad" title={`Fix rejected: attempt ${last.plan.attempt} was not tried in the sandbox`} icon={<XCircle size={20} aria-hidden />}>
        {failed.length ? `${failed.length} earlier ${failed.length === 1 ? "attempt" : "attempts"} failed validation, and ` : ""}
        the last proposed fix was rejected, so this finding is still open and needs a person to decide how to handle it. Nothing was changed in your repository.
      </Callout>
    );
  if (lastDecision === "accept_risk")
    return (
      <Callout tone="info" title="Risk accepted: no fix was applied" icon={<Circle size={20} aria-hidden />}>
        The risk was accepted instead of fixing it, so nothing ran in the sandbox. The decision and its reason are in the audit trail.
      </Callout>
    );
  if (last && !last.val)
    return (
      <Callout tone="gate" title="Waiting for validation" icon={<Circle size={20} aria-hidden />}>
        The fix has not been tried in the sandbox yet. It runs after the plan is approved.
      </Callout>
    );
  if (last?.val?.group_failure)
    return (
      <Callout tone="gate" title={`Attempt ${last.plan.attempt}: tested only as part of a group that failed`} icon={<Circle size={20} aria-hidden />}>
        The group of fixes failed together and this fix has not been tested on its own yet, so Guardian cannot say whether it is the cause.
      </Callout>
    );
  if (last?.val)
    return (
      <Callout tone="bad" title={`Failed attempt ${last.plan.attempt}: ${last.val.reason || failWord(last.val.verdict)}`} icon={<XCircle size={20} aria-hidden />}>
        Guardian re-plans after a failure, up to three attempts, and then hands the finding to a person. Nothing was changed in your repository.
      </Callout>
    );
  return null;
}

/** Attempts in order, with a 're-plans' step after each one that failed or was rejected. */
function Timeline({ attempts }: { attempts: Attempt[] }) {
  const { data } = useStore();
  // Suffix saying 'tested together' or 'tested alone', when the run mixes both.
  const how = (v: ValidationResult) => {
    const t = testedLabel(v, data.validation);
    return t ? `, ${t.text.replace(/^Round \d+: /, "")}` : "";
  };
  const steps: { key: string; title: string; sub: string; cls: string }[] = [];
  attempts.forEach((a, i) => {
    const what = planSummary(a.plan, undefined, null).change;
    const decision = decisionOf(a.plan.plan_id, data.approvals);
    const s = a.val
      ? a.val.verdict === "verified"
        ? { cls: "ok", label: `Verified${how(a.val)}` }
        : a.val.group_failure
          ? { cls: "", label: `${failLine(a.val)}${how(a.val)}` }
          : { cls: "bad", label: `${failLine(a.val)}${how(a.val)}` }
      : decision === "reject"
        ? { cls: "bad", label: "Rejected, so not tried in the sandbox" }
        : decision === "accept_risk"
          ? { cls: "", label: "Risk accepted, so not tried in the sandbox" }
          : decision === "approve"
            ? { cls: "gate", label: "Approved, waiting for validation" }
            : { cls: "gate", label: "Waiting for a decision" };
    steps.push({ key: a.plan.plan_id, title: `Attempt ${a.plan.attempt}: ${what}`, sub: s.label, cls: s.cls });
    const next = attempts[i + 1];
    // A failed or rejected attempt is followed by a re-plan step.
    const didNotStick = (a.val && a.val.verdict !== "verified" && !a.val.group_failure) || decision === "reject";
    if (next && didNotStick) steps.push({ key: `re-${i}`, title: "Guardian re-plans", sub: "Tries a different fix", cls: "" });
  });
  return (
    <ol className="timeline" aria-label="Attempts in order">
      {steps.map((s) => (
        <li key={s.key} className={`tl ${s.cls}`}>
          <span className="tl-dot" aria-hidden>
            {s.cls === "ok" ? <Check size={12} /> : s.cls === "bad" ? <XCircle size={12} /> : null}
          </span>
          <span className="tl-title">{s.title}</span>
          <span className="tl-sub">{s.sub}</span>
        </li>
      ))}
    </ol>
  );
}

/** Detail for one validated attempt, with tabs when there is more than one. */
function AttemptDetail({ attempts }: { attempts: Attempt[] }) {
  const { data } = useStore();
  const validated = attempts.filter((a) => a.val);
  // Selected attempt tab; starts on the latest.
  const [idx, setIdx] = useState(Math.max(0, validated.length - 1));
  const a = validated[Math.min(idx, validated.length - 1)];
  if (!a || !a.val) return null;
  const v = a.val;
  const lab = testedLabel(v, data.validation);
  return (
    <>
      {lab && (
        <p className="val-mode">
          <span className={`pill ${lab.cls}`}>{lab.text}</span>
          {v.combined && <span className="muted"> The test results below cover every fix in this run, not only this one.</span>}
        </p>
      )}
      {validated.length > 1 && (
        <div className="seg-tabs" role="tablist" aria-label="Attempt">
          {validated.map((x, i) => (
            <button key={x.plan.plan_id} role="tab" aria-selected={i === idx} className={i === idx ? "on" : ""} type="button" onClick={() => setIdx(i)}>
              Attempt {x.plan.attempt}
            </button>
          ))}
        </div>
      )}
      <div className="val-grid">
        <div className="val-col">
          <ScoreDrop key={v.attempt_id} v={v} />
          <Checks v={v} />
        </div>
        <div className="val-col">
          <SbomDiff id={v.sbom_diff_evidence_id} />
        </div>
      </div>
      <LogViewer ids={v.log_evidence_ids} />
    </>
  );
}

/** Risk score before and after, with the bar animating from the old value to the new one. */
function ScoreDrop({ v }: { v: ValidationResult }) {
  // Bar and number start at the 'before' score and move to 'after' on the next frame, so the CSS transition
  // plays.
  const [now, setNow] = useState(v.risk_before);
  useEffect(() => {
    const id = requestAnimationFrame(() => setNow(v.risk_after));
    return () => cancelAnimationFrame(id);
  }, [v.risk_after]);
  const shown = useCountTween(now);
  // the sentence uses the same rounded numbers the reader sees, so "68 to 8" always says "down 60"
  const dropped = Math.round(v.risk_before) - Math.round(v.risk_after);
  return (
    <Section title="Risk score before and after">
      <div className="drop-nums">
        <span className="num drop-before">{v.risk_before.toFixed(0)}</span>
        <span aria-hidden className="faint">to</span>
        <span className={`num drop-after ${dropped > 0 ? "good" : "bad"}`}>{shown.toFixed(0)}</span>
        <span className="muted">{dropped > 0 ? `down ${dropped.toFixed(0)} points` : dropped < 0 ? `up ${(-dropped).toFixed(0)} points` : "no change"}</span>
      </div>
      <div className="drop-track" role="img" aria-label={`Risk before ${v.risk_before}, after ${v.risk_after}`}>
        <span className="drop-ghost" style={{ width: `${v.risk_before}%` }} />
        <span className={`drop-fill${dropped > 0 ? "" : dropped < 0 ? " up" : " flat"}`} style={{ width: `${now}%` }} />
      </div>
      <div className="drop-scale mono"><span>0</span><span>50</span><span>100</span></div>
    </Section>
  );
}

// Test counts as '3 passed, 1 failed', or 'not run' when empty.
const tests = (t: Record<string, number>) => {
  const e = Object.entries(t);
  return e.length ? e.map(([k, n]) => `${n} ${k}`).join(", ") : "not run";
};

// Facts from the sandbox test run. failing_tests lists failing names per suite, plus new_vs_baseline: names
// that fail only after the patch. baseline holds the counts for the unpatched project.
interface SandboxTestFacts {
  failing_tests?: Record<string, string[]>;
  baseline?: { unit_tests?: Record<string, number>; integration_tests?: Record<string, number> } | null;
  notes?: string[];
}

// Facts from the validator. expected_failures are tests that assert the attack works, so they fail once the fix
// works.
interface ValidatorFacts {
  newly_failing_tests?: string[];
  expected_failures?: string[];
}

/**
 * One 'Unit tests' / 'Integration tests' row, judged against the unpatched project: failures that also happen
 * without the fix are not the fix's fault, and expected failures are flagged for review.
 * ok: true = good, false = problem, null = neutral (not run, or needs a look).
 */
function testRow(counts: Record<string, number>, phase: "test" | "integration", f: SandboxTestFacts | null, expected: Set<string>) {
  if (!Object.keys(counts).length) return { text: "Not run", ok: null as boolean | null };
  const base = phase === "test" ? f?.baseline?.unit_tests : f?.baseline?.integration_tests;
  const label = phase === "test" ? "unit" : "integration";
  if (f?.notes?.some((n) => n.startsWith(phase === "test" ? "test suite" : "integration suite")))
    return { text: `Not runnable in the sandbox (fails the same way without the fix)`, ok: null };
  const failed = counts.failed ?? 0;
  if (!failed) return { text: tests(counts), ok: true };
  const allNew = f?.failing_tests?.new_vs_baseline ?? null;
  // new_vs_baseline covers both suites: count only this suite's names
  const mine = new Set(f?.failing_tests?.[phase] ?? []);
  const newOnes = allNew ? (mine.size ? allNew.filter((n) => mine.has(n)) : allNew) : null;
  const real = newOnes ? newOnes.filter((n) => !expected.has(n)) : null;
  const exp = newOnes ? newOnes.length - (real?.length ?? 0) : 0;
  if (base && real && real.length === 0) {
    const tail = exp
      ? `: ${exp} fail${exp === 1 ? "s" : ""} because ${exp === 1 ? "it checks" : "they check"} that the attack works (expected once fixed), the rest already failed without the fix`
      : `: all ${failed} already fail without the fix, none caused by it`;
    return { text: `${tests(counts)}${tail}`, ok: exp ? null : true };
  }
  return { text: `${tests(counts)}${real?.length ? ` (${real.length} new ${label} failure${real.length === 1 ? "" : "s"})` : ""}`, ok: false };
}

/** The checklist: build, tests, re-scan result, new findings and confidence. */
function Checks({ v }: { v: ValidationResult }) {
  const ev = useEvidenceMany(v.log_evidence_ids);
  const facts = (ev.items.find((e) => e.kind === "test_result" && e.source_tool === "sandbox:docker")?.facts ??
    null) as SandboxTestFacts | null;
  const vfacts = (ev.items.find((e) => e.kind === "test_result" && e.source_tool === "validator")?.facts ?? null) as ValidatorFacts | null;
  // Tests that are expected to fail once the vulnerability is fixed.
  const expected = new Set(vfacts?.expected_failures ?? []);
  const newly = facts?.failing_tests?.new_vs_baseline ?? vfacts?.newly_failing_tests ?? [];
  // Real regressions: new failures that are not expected ones and not the validator's own 'failing after the
  // patch' marker.
  const broken = newly.filter((n) => !expected.has(n) && !/failing after the patch/.test(n));
  const unit = testRow(v.unit_tests, "test", facts, expected);
  const integ = testRow(v.integration_tests, "integration", facts, expected);
  const row = (k: string, val: string, ok?: boolean | null) => (
    <div>
      <dt>{k}</dt>
      <dd className={ok === true ? "good" : ok === false ? "bad" : ""}>
        {ok === true && <Check size={14} aria-hidden />}
        {ok === false && <AlertTriangle size={14} aria-hidden />} {val}
      </dd>
    </div>
  );
  return (
    <Section title="What was checked">
      <dl className="facts">
        {row("Build", v.build_ok == null ? "Not run" : v.build_ok ? "Passed" : "Failed", v.build_ok)}
        {row("Unit tests", unit.text, unit.ok)}
        {row("Integration tests", integ.text, integ.ok)}
        {row("Vulnerability gone after re-scan", v.target_finding_resolved ? "Yes" : "No", v.target_finding_resolved)}
        {row("New findings introduced", v.new_findings.length ? String(v.new_findings.length) : "None", v.new_findings.length === 0)}
        {row("Guardian's confidence", v.final_confidence)}
      </dl>
      {broken.length > 0 && (
        <div className="test-list">
          <h4 className="mini-h">Tests that passed before this fix and fail now</h4>
          <ul className="plain mono">
            {broken.map((n) => <li key={n}>{n}</li>)}
          </ul>
        </div>
      )}
      {expected.size > 0 && (
        <div className="test-list">
          <h4 className="mini-h">Tests to review: they check that the attack works</h4>
          <p className="muted">
            These tests expect the vulnerability to be exploitable, so they fail once it is fixed. That is the fix working, which is
            why they do not count against it. Confirm before merging.
          </p>
          <ul className="plain mono">
            {[...expected].map((n) => <li key={n}>{n}</li>)}
          </ul>
        </div>
      )}
      {facts?.notes?.length ? (
        <ul className="muted check-notes">
          {facts.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      ) : null}
    </Section>
  );
}

interface SbomFacts {
  added?: string[];
  removed?: string[];
  changed?: { name: string; from: string; to: string }[];
  components_before?: number;
  components_after?: number;
}

/** Package inventory before and after the fix (added, removed and updated components). */
function SbomDiff({ id }: { id: string | null }) {
  const st = useEvidence(id);
  const head = "Packages before and after";
  if (!id)
    return (
      <Section title={head}>
        <p className="muted">No comparison was recorded, because the build or re-scan did not run.</p>
      </Section>
    );
  if (st.status === "loading")
    return (
      <Section title={head}>
        <Skeleton h={120} />
      </Section>
    );
  if (st.status !== "ok")
    return (
      <Section title={head}>
        <p className="muted">The comparison record is not available.</p>
      </Section>
    );
  const f = st.ev.facts as SbomFacts;
  const rows: { kind: string; name: string; from: string; to: string }[] = [];
  // Turn a package URL like 'pkg:npm/name@1.0' into [name, version].
  const split = (p: string) => {
    const l = p.replace(/^pkg:[^/]+\//, "");
    const i = l.lastIndexOf("@");
    return i > 0 ? [decodeURIComponent(l.slice(0, i)), l.slice(i + 1)] : [l, ""];
  };
  for (const c of f.changed ?? []) rows.push({ kind: "changed", name: c.name, from: c.from, to: c.to });
  for (const p of f.removed ?? []) {
    const [n, ver] = split(p);
    rows.push({ kind: "removed", name: n, from: ver, to: "" });
  }
  for (const p of f.added ?? []) {
    const [n, ver] = split(p);
    rows.push({ kind: "added", name: n, from: "", to: ver });
  }
  const WORD: Record<string, string> = { changed: "Updated", removed: "Removed", added: "Added" };
  return (
    <Section title={head}>
      <p className="muted sbom-count">
        <span className="num">{f.components_before ?? "?"}</span> packages before, <span className="num">{f.components_after ?? "?"}</span> after.
      </p>
      <div className="sbom-scroll">
        <table className="sbom">
          <thead>
            <tr><th>Change</th><th>Package</th><th>Before</th><th>After</th></tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={4} className="muted">No packages changed.</td></tr>
            )}
            {rows.slice(0, 300).map((r, i) => (
              <tr key={`${r.kind}-${r.name}-${i}`} className={`sb-${r.kind}`}>
                <td>{WORD[r.kind]}</td>
                <td className="mono">{r.name}</td>
                <td className="mono">{r.from}</td>
                <td className="mono">{r.to}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

/**
 * Collapsed by default: build and test logs with a tab per log, line numbers, line search and error/warning
 * highlighting.
 */
function LogViewer({ ids }: { ids: string[] }) {
  const ev = useEvidenceMany(ids);
  const logs = ev.items.filter((e) => e.kind === "build_log" || e.kind === "test_result" || e.excerpt);
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState(0);
  const [q, setQ] = useState("");
  const cur: Evidence | undefined = logs[Math.min(tab, logs.length - 1)];
  const lines = useMemo(() => (cur?.excerpt ?? "").replace(/\r/g, "").split("\n"), [cur]);
  const t = q.trim().toLowerCase();
  const hits = t ? lines.filter((l) => l.toLowerCase().includes(t)).length : 0;
  return (
    <section className="sec logs">
      <button type="button" className="logs-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={16} aria-hidden /> : <ChevronRight size={16} aria-hidden />}
        <h3>Build and test logs</h3>
        <span className="faint">{ev.loaded ? `${logs.length} ${logs.length === 1 ? "log" : "logs"}` : "loading"}. For engineers: open to read the raw output.</span>
      </button>
      {open &&
        (!ev.loaded ? (
          <Skeleton h={160} />
        ) : !cur ? (
          <p className="muted">No logs were recorded for this attempt.</p>
        ) : (
          <>
            <div className="log-tools">
              <div className="seg-tabs" role="tablist" aria-label="Log">
                {logs.map((l, i) => (
                  <button key={l.evidence_id} role="tab" type="button" aria-selected={i === tab} className={i === tab ? "on" : ""} onClick={() => setTab(i)}>
                    {evidenceTitle(l)}
                  </button>
                ))}
              </div>
              <span className="searchbox">
                <Search size={16} aria-hidden />
                <input type="search" placeholder="Search this log" aria-label="Search this log" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 220 }} />
              </span>
              {t && <span className="muted">{hits} matching {hits === 1 ? "line" : "lines"}</span>}
            </div>
            {cur.excerpt ? (
              <pre className="log" tabIndex={0}>
                {lines.map((ln, i) => {
                  const hit = t && ln.toLowerCase().includes(t);
                  return (
                    <span key={i} className={`ll${hit ? " hit" : ""}${/\b(error|fail(ed|ure)?|fatal)\b/i.test(ln) ? " err" : /\bwarn(ing)?\b/i.test(ln) ? " warn" : ""}`}>
                      <span className="ln num">{i + 1}</span>
                      {ln || " "}
                    </span>
                  );
                })}
              </pre>
            ) : (
              <Json value={cur.facts} collapsedLines={14} />
            )}
            <p className="faint mono">Produced by {cur.source_tool}</p>
          </>
        ))}
    </section>
  );
}
