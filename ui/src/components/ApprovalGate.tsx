import { AlertTriangle, Check, CheckCircle2, Circle, Info, Loader2, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { postDecision } from "../api/client";
import type { Approval, Finding, RemediationPlan } from "../api/types";
import { bandOf, dateTime } from "../lib/format";
import { STEP_DOING, plainTitle } from "../lib/labels";
import { planSummary } from "../lib/plan";
import { useStore } from "../store";
import { useEvidenceMany, useStoredState } from "./hooks";
import { ScoreBar } from "./RiskTable";
import { Callout, ClaimList, DiffView, EmptyState, Json, Section, SevPill, Skeleton } from "./ui";

type Decision = "approve" | "reject" | "accept_risk";

function planState(p: RemediationPlan, pendingId: string | undefined, approvals: Approval[]) {
  if (p.plan_id === pendingId) return { key: "pending", label: "Waiting for your decision", cls: "gate" };
  const a = [...approvals].reverse().find((x) => x.plan_id === p.plan_id);
  if (a) {
    if (a.decision === "approve") return { key: "approved", label: "Approved", cls: "ok" };
    if (a.decision === "reject") return { key: "rejected", label: "Rejected", cls: "bad" };
    return { key: "accepted", label: "Risk accepted", cls: "info" };
  }
  return { key: "proposed", label: "Proposed", cls: "" };
}

const DECISION_WORD: Record<string, string> = { approve: "Approved", reject: "Rejected", accept_risk: "Accepted the risk" };

export default function ApprovalGate() {
  const { data, findingsById, riskById } = useStore();
  const pending = data.summary.pending_plan ?? undefined;
  const [sel, setSel] = useState<string | null>(null);
  const plans = data.plans;
  const current = plans.find((p) => p.plan_id === (sel ?? pending?.plan_id)) ?? plans[plans.length - 1];

  if (!plans.length)
    return (
      <EmptyState title="No fix has been proposed yet" center>
        {data.summary.status === "done"
          ? "This scan finished without proposing a fix, so there is nothing to approve."
          : "When Guardian has a fix to suggest for the riskiest finding, it will appear here and wait for your decision."}
      </EmptyState>
    );

  return (
    <div className={`gate-view${plans.length > 1 ? " with-list" : ""}`}>
      {plans.length > 1 && (
        <aside className="gate-list" aria-label="Proposed fixes">
          <h2>Proposed fixes</h2>
          <ul>
            {plans.map((p) => {
              const f = findingsById.get(p.finding_id);
              const st = planState(p, pending?.plan_id, data.approvals);
              const sm = planSummary(p, f, f ? bandOf(f, riskById) : null);
              return (
                <li key={p.plan_id}>
                  <button type="button" className={`plan-item${current?.plan_id === p.plan_id ? " on" : ""}`} onClick={() => setSel(p.plan_id)}>
                    <span className="plan-item-top">
                      <span className="faint">Attempt {p.attempt}</span>
                      <span className={`pill ${st.cls}`}>{st.label}</span>
                    </span>
                    <span className="plan-item-title">
                      {sm.change}
                    </span>
                    <span className="muted plan-item-sub">{f ? plainTitle(f, bandOf(f, riskById)) : ""}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </aside>
      )}
      {current && <PlanDetail key={current.plan_id} plan={current} finding={findingsById.get(current.finding_id)} />}
    </div>
  );
}

function PlanDetail({ plan, finding }: { plan: RemediationPlan; finding: Finding | undefined }) {
  const { data, riskById, src, kind, refresh, openEvidence, openFinding, status, me } = useStore();
  const pending = data.summary.pending_plan ?? undefined;
  const isPending = plan.plan_id === pending?.plan_id;
  const st = planState(plan, pending?.plan_id, data.approvals);
  const ev = useEvidenceMany(plan.evidence_ids);
  const diff = ev.items.find((e) => e.kind === "patch_diff" && e.excerpt);
  const risk = riskById.get(plan.finding_id);
  const band = finding ? bandOf(finding, riskById) : null;
  const sum = useMemo(() => planSummary(plan, finding, band), [plan, finding, band]);
  const approval = [...data.approvals].reverse().find((a) => a.plan_id === plan.plan_id);
  const c = plan.compatibility_impact;

  const missing = [
    !diff && (ev.loaded ? "the proposed change" : "the proposed change (loading)"),
    !risk && "the risk score",
    kind !== "api" && "a live connection to Guardian",
  ].filter(Boolean) as string[];
  const ready = isPending && missing.length === 0 && me.can_decide;

  const verified = plan.rationale.filter((r) => r.label === "verified");
  const inferred = plan.rationale.filter((r) => r.label !== "verified");

  // ---- decision state
  const [by, setBy] = useStoredState<string>("guardian.decider", "reviewer");
  const [comment, setComment] = useState("");
  const [pick, setPick] = useState<Decision | null>(null); // decision being confirmed or filled in
  const [needComment, setNeedComment] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [sent, setSent] = useState<Decision | null>(null);
  const commentRef = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    setErr(null);
    setPick(null);
  }, [plan.plan_id]);

  // after a decision, follow the run quickly until it has moved on
  useEffect(() => {
    if (!sent || status === "done" || status === "failed") return;
    const t = window.setInterval(() => void refresh(), 1500);
    return () => window.clearInterval(t);
  }, [sent, status, refresh]);

  const submit = async (decision: Decision) => {
    if (decision !== "approve" && !comment.trim()) {
      setNeedComment(true);
      setPick(decision);
      commentRef.current?.focus();
      return;
    }
    setBusy(true);
    setErr(null);
    const r = await postDecision(src, plan.plan_id, {
      plan_hash: plan.plan_hash,
      decision,
      comment: comment.trim() || null,
      decided_by: me.mode === "token" ? me.name : by.trim() || "reviewer",
    });
    setBusy(false);
    if (r.ok) {
      setSent(decision);
      setPick(null);
      void refresh();
    } else setErr(r.message);
  };

  return (
    <div className="gate-main">
      <div className="gate-scroll">
        <div className="gate-in">
          {/* ---- plain-language summary */}
          <section className={`gate-sum ${st.cls}`} aria-label="Summary of the proposed fix">
            <div className="gate-sum-top">
              <span className={`pill big ${st.cls}`}>
                <span className={`dot ${st.cls}`} aria-hidden />
                {st.label}
              </span>
              {finding && <SevPill risk={band} />}
              <span className="faint">Attempt {plan.attempt}</span>
            </div>
            <h1 className="gate-sentence">{sum.sentence}</h1>
            {finding && (
              <p className="muted">
                <button type="button" className="linkish inline" onClick={() => openFinding(finding.finding_id)}>
                  {plainTitle(finding, band)}
                </button>
                . Select it to see the evidence.
              </p>
            )}
            <div className="gate-happens">
              <ShieldCheck size={18} aria-hidden />
              <p>
                <b>If you approve:</b> the change is applied to an isolated copy of your project, built and tested in a sandbox with no network access, then
                re-scanned. <b>Nothing touches your repository.</b>
              </p>
            </div>
            {sum.major && (
              <Callout tone="gate" title={`Major version jump${sum.from && sum.to ? `: ${sum.from} to ${sum.to}` : ""}`}>
                Major releases are allowed to change how a package behaves, so this upgrade could break code that relies on the old version. That is exactly what the
                sandbox build and tests will check. Compatibility risk is rated <b>{c?.level ?? "high"}</b>
                {c && c.engines_ok === false ? ", and the target does not support your Node version" : ""}
                {c && c.peer_dep_changes.length ? `. Peer dependency changes: ${c.peer_dep_changes.join(", ")}` : ""}.
              </Callout>
            )}
            {!sum.major && c && (c.level === "high" || c.engines_ok === false || c.peer_dep_changes.length > 0) && (
              <Callout tone="gate" title="Check compatibility">
                {c.engines_ok === false ? "The target version does not support your Node version. " : ""}
                {c.peer_dep_changes.length ? `Peer dependency changes: ${c.peer_dep_changes.join(", ")}.` : ""}
              </Callout>
            )}
          </section>

          {/* ---- the change */}
          <Section
            title="The change"
            lead={diff ? `Edits ${((diff.facts as { files?: string[] }).files ?? [plan.ops[0]?.file_path]).filter(Boolean).join(", ")} in the sandbox copy only.` : undefined}
          >
            {diff?.excerpt ? (
              <DiffView text={diff.excerpt} />
            ) : ev.loaded ? (
              <p className="muted">Guardian has not attached a preview of the change to this plan.</p>
            ) : (
              <Skeleton h={120} />
            )}
            <details className="more">
              <summary>Technical steps ({plan.ops.length})</summary>
              <table className="optable">
                <thead>
                  <tr><th>Operation</th><th>File</th><th>Arguments</th></tr>
                </thead>
                <tbody>
                  {plan.ops.map((o, i) => (
                    <tr key={`${o.op}-${i}`}>
                      <td className="mono">{o.op}</td>
                      <td className="mono">{o.file_path}</td>
                      <td><Json value={o.args} collapsedLines={4} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </details>
          </Section>

          {/* ---- why */}
          <Section title="Why Guardian suggests this" lead="Each statement is labelled by how well it is backed up. The numbered sources open the original record.">
            {verified.length > 0 && (
              <div className="claimgroup">
                <h4 className="mini-h">Verified facts <span className="faint">(from scanners and registries)</span></h4>
                <ClaimList claims={verified} onCite={openEvidence} origin="rule" />
              </div>
            )}
            {inferred.length > 0 && (
              <div className="claimgroup">
                <h4 className="mini-h">Not yet proven <span className="faint">(reasoning the sandbox run will check)</span></h4>
                <ClaimList claims={inferred} onCite={openEvidence} origin="rule" />
              </div>
            )}
            {plan.rationale.length === 0 && <p className="muted">No reasoning was recorded for this plan.</p>}
          </Section>

          {/* ---- score */}
          <Section title="Risk before and after">
            {risk ? (
              <ScoreBar
                risk={risk}
                after={sum.expectedAfter}
                extra={
                  <p className="muted score-foot">
                    The "after" figure is a prediction. It becomes real only if the sandbox re-scan comes back clean.{" "}
                    <button type="button" className="linkish inline" onClick={() => finding && openFinding(finding.finding_id)}>See how the score was worked out</button>
                    .
                  </p>
                }
              />
            ) : (
              <p className="muted">This finding has not been scored yet.</p>
            )}
          </Section>

          <Section title="How to undo it">
            <p className="prose">{plan.rollback}</p>
            <p className="faint mono hash">Plan {plan.plan_id} · hash {plan.plan_hash.slice(0, 16)}</p>
          </Section>
        </div>
      </div>

      {/* ---- decision */}
      <footer className="decision">
        <div className="decision-in">
          {sent ? (
            <Progress decision={sent} />
          ) : approval && !isPending ? (
            <>
              <p className="decided">
                <CheckCircle2 size={18} aria-hidden className={approval.decision === "approve" ? "okc" : ""} />
                <span>
                  <b>{DECISION_WORD[approval.decision] ?? approval.decision}</b> by <span className="mono">{approval.decided_by}</span> on {dateTime(approval.ts)}
                  {approval.comment ? <span className="muted"> - {approval.comment}</span> : null}
                </span>
              </p>
              {approval.decision === "approve" && <Progress decision="approve" compact />}
            </>
          ) : !isPending ? (
            <p className="muted">This plan is not the one waiting for a decision.</p>
          ) : pick === "approve" ? (
            <div className="confirm" role="group" aria-label="Confirm approval">
              <p className="confirm-title">Confirm: approve this fix and start validation?</p>
              <dl className="kv">
                <dt>Plan</dt><dd className="mono">{plan.plan_id}</dd>
                <dt>Plan hash</dt><dd className="mono hashfull">{plan.plan_hash}</dd>
                <dt>What runs</dt><dd>Apply the change to a sandbox copy, build, test (no network), re-scan.</dd>
                <dt>Your repository</dt><dd>Not changed.</dd>
              </dl>
              <p className="faint">Your approval is tied to this exact hash. If the plan changed since you opened this page, Guardian will refuse it.</p>
              {err && <p className="err-inline" role="alert">{err}</p>}
              <div className="decision-actions">
                <button type="button" className="btn primary lg" disabled={busy} onClick={() => void submit("approve")} autoFocus>
                  {busy ? <><Loader2 size={16} className="spin" aria-hidden /> Sending</> : "Confirm and start validation"}
                </button>
                <button type="button" className="btn lg" disabled={busy} onClick={() => setPick(null)}>Go back</button>
              </div>
            </div>
          ) : !me.can_decide ? (
            <Callout tone="info" title="Only approvers can decide" icon={<Info size={18} aria-hidden />}>
              You are signed in as {me.name} ({me.role}), so you can read everything here but not approve, reject or accept the risk. Ask an approver to open this page.
            </Callout>
          ) : (
            <>
              <div className="decision-fields">
                {me.mode !== "token" && <label className="field decided-by">
                  <span>Your name</span>
                  <input value={by} onChange={(e) => setBy(e.target.value)} maxLength={60} />
                </label>}
                <label className={`field grow${needComment && !comment.trim() ? " invalid" : ""}`}>
                  <span>
                    Comment <b className="req">(required to reject or accept the risk; optional to approve)</b>
                  </span>
                  <textarea
                    ref={commentRef}
                    rows={2}
                    value={comment}
                    onChange={(e) => {
                      setComment(e.target.value);
                      if (e.target.value.trim()) setNeedComment(false);
                    }}
                    placeholder="Why are you making this decision?"
                    aria-invalid={needComment && !comment.trim()}
                  />
                  {needComment && !comment.trim() && (
                    <span className="field-err" role="alert">
                      Write a short reason first. A {pick === "accept_risk" ? "risk acceptance" : "rejection"} is recorded in the audit trail.
                    </span>
                  )}
                </label>
              </div>
              {err && <p className="err-inline" role="alert">{err}</p>}
              <div className="decide-grid">
                <div className="decide-opt">
                  <button type="button" className="btn primary lg" disabled={!ready || busy} onClick={() => setPick("approve")}>
                    <Check size={16} aria-hidden /> Approve
                  </button>
                  <p>Try the fix in a sandbox first. Your repository stays untouched.</p>
                </div>
                <div className="decide-opt">
                  <button type="button" className="btn danger lg" disabled={!ready || busy} onClick={() => void submit("reject")}>
                    Reject
                  </button>
                  <p>Turn this plan down. Guardian records why and may propose another fix.</p>
                </div>
                <div className="decide-opt">
                  <button type="button" className="btn warn lg" disabled={!ready || busy} onClick={() => void submit("accept_risk")}>
                    Accept risk
                  </button>
                  <p>Leave the vulnerability in place and record that you chose to.</p>
                </div>
              </div>
              {!ready && (
                <p className="waiting">
                  <Info size={14} aria-hidden />{" "}
                  {kind !== "api" ? "Decisions need the live Guardian service. This is a read-only copy of a scan." : `Waiting for ${missing.join(" and ")} before you can decide.`}
                </p>
              )}
            </>
          )}
        </div>
      </footer>
    </div>
  );
}

/** What happens after the decision: follows the run as it resumes. */
function Progress({ decision, compact }: { decision: Decision; compact?: boolean }) {
  const { pipeline, status } = useStore();
  const node = (id: string) => pipeline.nodes.find((n) => n.id === id)?.state ?? "idle";
  const val = node("validator");
  const rep = node("reporter");
  const finished = status === "done" || status === "failed";
  const icon = (s: string) =>
    s === "done" ? <Check size={16} aria-hidden className="okc" /> : s === "active" ? <Loader2 size={16} aria-hidden className="spin" /> : s === "error" ? <AlertTriangle size={16} aria-hidden /> : <Circle size={16} aria-hidden className="faint" />;
  const { setView } = useStore();
  const resuming = !finished && val === "idle" && rep === "idle";
  const steps: [string, string][] =
    decision === "approve"
      ? [
          ["done", "Decision recorded"],
          [val === "idle" && finished ? "done" : resuming ? "active" : val, "Validation: apply, build, test and re-scan in the sandbox"],
          [rep, "Report"],
        ]
      : [
          ["done", "Decision recorded"],
          [finished ? "done" : "active", finished ? "Scan finished" : "Guardian is continuing with the rest of the scan"],
        ];
  return (
    <div className="progress" role="status" aria-live="polite">
      {!compact && (
        <p className="progress-title">
          {decision === "approve" ? "Approved. Guardian is validating the fix." : decision === "reject" ? "Rejected. Your reason is recorded." : "Risk accepted. Your reason is recorded."}
        </p>
      )}
      <ol className="progress-steps">
        {steps.map(([s, label]) => (
          <li key={label} className={`st-${s}`}>
            {icon(s)}
            <span>{label}</span>
          </li>
        ))}
      </ol>
      {!finished && <p className="faint">{STEP_DOING[pipeline.nodes.find((n) => n.state === "active")?.id ?? "validator"]}...</p>}
      {decision === "approve" && (val !== "idle" || finished) && (
        <button type="button" className="btn sm" onClick={() => setView("validation")}>Open validation</button>
      )}
    </div>
  );
}
