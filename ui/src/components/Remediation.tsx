/**
 * Remediation page: the human approval step. Each suggested fix is a row the reviewer approves, rejects (with a
 * reason that steers the next suggestion) or accepts as a risk. Two ways to work: decide everything and submit
 * once ('all'), or send one decision at a time ('one') to follow what Guardian does after each step. Decisions
 * are drafts in the browser until submitted; nothing is sent to the repository.
 */
import { Check, CheckCircle2, ChevronDown, ChevronRight, Info, Loader2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { submitBatchDecisions, validateHeldFixes, type RejectReason } from "../api/client";
import type { Finding, RecDecision, RecOutcome, Recommendation, RecommendationsFile, RemediationPlan } from "../api/types";
import { bandOf, clock, plural } from "../lib/format";
import { plainTitle } from "../lib/labels";
import { heldApproved, planSummary } from "../lib/plan";
import { AGENT_LABEL, type AgentId } from "../lib/pipeline";
import { useStore } from "../store";
import ApprovalGate from "./ApprovalGate";
import { useEvidenceMany, useStoredState } from "./hooks";
import { Callout, ClaimList, DiffView, EmptyState, SevPill, Skeleton } from "./ui";

/**
 * The Remediation page. Runs that recommend a fix for every finding (batch mode) get the list below.
 * Older runs, which propose one fix at a time, keep the original approval page.
 */
export default function Remediation() {
  const { data } = useStore();
  const recs = data.recommendations;
  const [mode, setMode] = useStoredState<Mode>("guardian.rem.mode", "all");
  if (!recs) return <ApprovalGate />;
  // together: a new key per batch, so drafts never leak from one round into the next.
  // one at a time: the batch id changes after every step, so the page (and its drafts) stay put.
  return <BatchPage key={mode === "one" ? "one" : (recs.batch_id ?? `round-${recs.round}-${recs.status}`)} recs={recs} mode={mode === "one" ? "one" : "all"} setMode={setMode} />;
}

// 'all': decide every row, then one submit starts validation. 'one': each row is submitted on its own (partial
// submit), mainly for stepping through the flow.
type Mode = "all" | "one";

// A decision the reviewer has picked but not yet sent. reasonType is only used for 'reject'.
// planId binds the draft to the plan the reviewer was looking at: a new alternative on the same row starts empty.
type Draft = { decision: RecDecision; comment: string; reasonType?: RejectReason | null; planId?: string | null };
// Drafts keyed by rec_id. Kept in sessionStorage so a reload does not lose unsent choices.
type Drafts = Record<string, Draft>;

// Row outcome (from the backend) to the pill text and CSS tone shown on the row once it is no longer editable.
const STATUS: Record<RecOutcome, { label: string; cls: string }> = {
  awaiting_decision: { label: "Waiting for a decision", cls: "gate" },
  approved: { label: "Approved, waiting for the rest", cls: "ok" },
  validating: { label: "Being tested", cls: "gate" },
  verified: { label: "Verified", cls: "ok" },
  failed: { label: "Failed validation", cls: "bad" },
  rejected: { label: "Rejected", cls: "bad" },
  accepted: { label: "Risk accepted", cls: "info" },
  no_alternative: { label: "No alternatives", cls: "dashed" },
  needs_person: { label: "Needs a person", cls: "bad" },
};

// The three choices on an editable row. 'help' is the tooltip.
const OPTIONS: { id: RecDecision; label: string; help: string }[] = [
  { id: "approve", label: "Approve", help: "Test this fix in the sandbox with the other approved fixes." },
  { id: "reject", label: "Reject", help: "Turn this fix down. Guardian proposes the next alternative, if there is one." },
  { id: "accept_risk", label: "Accept risk", help: "Leave the vulnerability in place and record that you chose to." },
];

/** Why a fix was turned down: the next suggestion follows it. */
export const REJECT_REASONS: { id: RejectReason; label: string; effect: string }[] = [
  { id: "too_big", label: "Too big a change", effect: "Next: only a smaller version or a less invasive fix, smallest first." },
  { id: "too_new", label: "Too new a version", effect: "Next: a slightly older version that is still safe, closest first." },
  { id: "breaks_app", label: "It would break the app", effect: "Next: skips this version line and this kind of change." },
  { id: "different_approach", label: "Use a different kind of fix", effect: "Next: a different kind of change, e.g. remove instead of replace." },
  { id: "other", label: "Other", effect: "Next: the following option in Guardian's usual order." },
];
export const REJECT_LABEL: Record<string, string> = Object.fromEntries(REJECT_REASONS.map((r) => [r.id, r.label]));

// Reject and accept-risk need a written reason (it goes in the audit trail); approve does not.
const needsReason = (d: Draft | undefined) => !!d && d.decision !== "approve";
// A draft is ready to send: approve, or a non-empty comment (and a reject reason for reject).
const isComplete = (d: Draft | undefined) =>
  !!d && (d.decision === "approve" || (d.comment.trim().length > 0 && (d.decision !== "reject" || !!d.reasonType)));

/** What a draft still lacks before it can be sent, in words ("Choose a decision first." when there is no draft). */
export function draftProblem(d: Draft | undefined): string | null {
  if (!d) return "Choose a decision first.";
  if (d.decision === "approve") return null;
  const noReason = d.decision === "reject" && !d.reasonType;
  const noComment = d.comment.trim().length === 0;
  if (noReason && noComment) return "Add a reason: pick why and write a short note.";
  if (noReason) return "Add a reason: pick why you are rejecting it.";
  if (noComment) return "Add a reason: write a short note.";
  return null;
}

/** "36 files: a, b, c and 33 more" */
function fileSummary(files: string[]): string {
  const n = files.length;
  if (n <= 3) return n === 1 ? files[0] : `${n} files: ${files.join(", ")}`;
  return `${n} files: ${files.slice(0, 3).join(", ")} and ${n - 3} more`;
}

/** Read saved drafts for this run/batch; an unreadable or missing store means no drafts. */
function loadDrafts(key: string): Drafts {
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as Drafts) : {};
  } catch {
    return {};
  }
}

/**
 * The batch view: header counts, filter, list of rows and the submit footer. State is mostly local drafts; the
 * server data (recs, plans) comes from the store.
 */
function BatchPage({ recs, mode, setMode }: { recs: RecommendationsFile; mode: Mode; setMode: (m: Mode) => void }) {
  const { data, riskById, findingsById, me, kind, src, refresh, status, setView } = useStore();
  const batchId = recs.batch_id;
  // one-at-a-time mode
  const one = mode === "one";
  // Where drafts are saved. Together mode: one key per batch, so a new batch starts empty. One-at-a-time: one
  // key per run, because the batch id changes after every step and the drafts must survive that.
  const storeKey = one ? `guardian.rem.${src.runId}.steps` : `guardian.rem.${src.runId}.${batchId ?? "none"}`;

  // Rows sorted riskiest first. Uses Guardian's score; falls back to CVSS x 10 when a finding was not scored.
  const items = useMemo(() => {
    const score = (r: Recommendation) => riskById.get(r.primary_finding_id)?.score ?? (findingsById.get(r.primary_finding_id)?.cvss ?? 0) * 10;
    return [...recs.items].sort((a, b) => score(b) - score(a));
  }, [recs.items, riskById, findingsById]);
  // The backend is paused waiting for this batch to be decided.
  const waiting = recs.status === "awaiting_decisions" && !!batchId;
  // Rows that still need a decision. In 'one' mode this also applies between batches, because the batch id
  // changes after every step.
  const pending = useMemo(
    () => (waiting || one ? items.filter((i) => i.kind === "fix" && i.outcome === "awaiting_decision") : []),
    [items, waiting, one],
  );
  // the backend is working: row submits wait, so two steps never overlap
  const backendBusy = recs.status === "validating" || status === "running";

  // ---- draft decisions (local until submitted)
  const [drafts, setDraftsState] = useState<Drafts>(() => (batchId || one ? loadDrafts(storeKey) : {}));
  // Update the drafts and mirror them to sessionStorage (skipped when there is no batch to key them to).
  // Always a functional update: an async submit finishing later must not overwrite drafts picked meanwhile.
  const setDrafts = (change: (prev: Drafts) => Drafts) => {
    setDraftsState((prev) => {
      const next = change(prev);
      if (batchId || one) {
        try {
          sessionStorage.setItem(storeKey, JSON.stringify(next));
        } catch {
          /* storage unavailable: the draft lives for this page load */
        }
      }
      return next;
    });
  };
  const setDraft = (rec: Recommendation, d: Draft) => {
    setDrafts((prev) => ({ ...prev, [rec.rec_id]: { ...d, planId: rec.plan_id } }));
    setRowErr((e) => (e?.id === rec.rec_id ? null : e));
  };
  // The unsent draft of a row; one made for an earlier plan of the same row no longer counts.
  const draftOf = (r: Recommendation): Draft | undefined => {
    const d = drafts[r.rec_id];
    return d && (!d.planId || d.planId === r.plan_id) ? d : undefined;
  };

  // Which rows to list: only those needing a decision, or all. Starts on 'needs' when anything is pending.
  const [filter, setFilter] = useState<"needs" | "all">(pending.length ? "needs" : "all");
  // rec_ids whose 'Show the change and why' panel is expanded.
  const [open, setOpen] = useState<Set<string>>(new Set());
  const toggle = (id: string) =>
    setOpen((p) => {
      const n = new Set(p);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  // Two-step confirmation for the bulk 'Approve all remaining' button.
  const [confirmAll, setConfirmAll] = useState(false);
  // Turned on after a submit attempt, so missing reasons are marked invalid only then.
  const [showErrors, setShowErrors] = useState(false);
  const [by, setBy] = useStoredState<string>("guardian.decider", "reviewer");
  // busy/err: the together-submit request in flight and its error. sent: the batch was accepted, so the page
  // now follows the run.
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  // Row to scroll to and highlight (for 12 s) after a reject in 'one' mode, where the next suggestion replaces
  // it.
  const [flashId, setFlashId] = useState<string | null>(null);
  useEffect(() => {
    if (!flashId) return;
    const t = window.setTimeout(() => setFlashId(null), 12000);
    return () => window.clearTimeout(t);
  }, [flashId]);
  // 'one' mode: rec_id being sent right now, and the error for one row.
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [rowErr, setRowErr] = useState<{ id: string; msg: string } | null>(null);
  // "Validate now": request in flight, the error, and the batch it was started from (until the run is back at a gate).
  const [nowBusy, setNowBusy] = useState(false);
  const [nowErr, setNowErr] = useState<string | null>(null);
  const [nowStart, setNowStart] = useState<{ batch: string; n: number } | null>(null);

  // Can this person change decisions now? Needs the approver role, the live API (not a static copy), nothing
  // sent yet, and something to decide.
  const editable = me.can_decide && kind === "api" && !sent && (one ? pending.length > 0 : waiting);
  // complete: ready to send. undecided: no draft yet. noReason: reject or accept chosen but the reason is
  // missing.
  const complete = pending.filter((p) => isComplete(draftOf(p)));
  const undecided = pending.filter((p) => !draftOf(p));
  const noReason = pending.filter((p) => needsReason(draftOf(p)) && !isComplete(draftOf(p)));
  // Together mode needs every pending row complete, so validation tests one agreed set of fixes.
  const canSubmit = editable && pending.length > 0 && complete.length === pending.length && !busy;

  // after submitting, follow the run quickly until it has moved on
  useEffect(() => {
    if (!sent || status === "done" || status === "failed") return;
    const t = window.setInterval(() => void refresh(), 1500);
    return () => window.clearInterval(t);
  }, [sent, status, refresh]);

  /**
   * Together mode: send one decision per pending row in a single call, which starts validation. The plan hash
   * is sent back so the server can refuse a plan that changed after review.
   */
  const submit = async () => {
    if (!batchId || !canSubmit) {
      setShowErrors(true);
      return;
    }
    setBusy(true);
    setErr(null);
    const decisions = pending.map((p) => {
      const d = draftOf(p)!;
      const plan = p.plan_id ? data.plans.find((x) => x.plan_id === p.plan_id) : undefined;
      return {
        plan_id: p.plan_id ?? "",
        plan_hash: p.plan_hash ?? plan?.plan_hash ?? "",
        decision: d.decision,
        comment: d.comment.trim() || null,
        reason_type: d.decision === "reject" ? (d.reasonType ?? null) : null,
      };
    });
    const r = await submitBatchDecisions(src, data.runId, batchId, decisions, me.mode === "token" ? me.name : by.trim() || "reviewer");
    setBusy(false);
    if (r.ok) {
      setSent(true);
      try {
        sessionStorage.removeItem(storeKey);
      } catch {
        /* nothing to clean */
      }
      void refresh();
    } else setErr(r.message);
  };

  /**
   * One-at-a-time mode: send just this row as a partial submit, then drop its draft. After a reject the row is
   * flashed, because a new suggestion takes its place. Blocked while the backend is busy so two steps never
   * overlap.
   */
  const submitOne = async (p: Recommendation) => {
    const d = draftOf(p);
    if (!batchId || !d || !isComplete(d) || backendBusy || rowBusy || nowBusy) return;
    setRowBusy(p.rec_id);
    setRowErr(null);
    const plan = p.plan_id ? data.plans.find((x) => x.plan_id === p.plan_id) : undefined;
    const r = await submitBatchDecisions(
      src,
      data.runId,
      batchId,
      [{
        plan_id: p.plan_id ?? "",
        plan_hash: p.plan_hash ?? plan?.plan_hash ?? "",
        decision: d.decision,
        comment: d.comment.trim() || null,
        reason_type: d.decision === "reject" ? (d.reasonType ?? null) : null,
      }],
      me.mode === "token" ? me.name : by.trim() || "reviewer",
      true,
    );
    setRowBusy(null);
    if (r.ok) {
      setDrafts((prev) => {
        const next = { ...prev };
        delete next[p.rec_id];
        return next;
      });
      if (d.decision === "reject") setFlashId(p.rec_id);
      void refresh();
    } else setRowErr({ id: p.rec_id, msg: r.message });
  };

  // "Validate now": approved fixes held while others wait can be tested right away (one-at-a-time mode only).
  const held = heldApproved(items);
  const canValidateNow = me.can_decide && kind === "api" && one && waiting && held.length > 0 && !rowBusy;
  const validateNow = async (rows: Recommendation[]) => {
    if (!batchId || nowBusy || rowBusy || backendBusy) return;
    setNowBusy(true);
    setNowErr(null);
    const r = await validateHeldFixes(src, data.runId, batchId, rows.map((x) => x.plan_id ?? ""));
    setNowBusy(false);
    if (r.ok) {
      setNowStart({ batch: batchId, n: rows.length });
      void refresh();
    } else setNowErr(r.message);
  };
  // the page follows the run until the validation is over and the refreshed batch (a new id) is back
  useEffect(() => {
    if (!nowStart) return;
    if (batchId !== nowStart.batch && recs.status !== "validating") {
      setNowStart(null);
      return;
    }
    const t = window.setInterval(() => void refresh(), 1500);
    return () => window.clearInterval(t);
  }, [nowStart, batchId, recs.status, refresh]);

  // ---- header counts
  // count: rows with a given backend outcome. draftCount: pending rows whose unsent draft picked this decision.
  // The header chips add both, so the numbers move as the reviewer clicks.
  const count = (o: RecOutcome) => items.filter((i) => i.outcome === o).length;
  const draftCount = (d: RecDecision) => pending.filter((p) => draftOf(p)?.decision === d).length;
  const counts: [string, number][] = [
    ["to decide", undecided.length],
    ["approved", draftCount("approve") + count("approved") + count("validating")],
    ["rejected", draftCount("reject") + count("rejected")],
    ["accepted", draftCount("accept_risk") + count("accepted")],
    ["no alternatives", count("no_alternative")],
    ["verified", count("verified")],
    ["failed validation", count("failed")],
    ["need a person", count("needs_person")],
  ];

  // Rows to list; the 'needs' filter falls back to all rows when nothing is pending.
  const shown = filter === "needs" && pending.length ? pending : items;
  // The sandbox is (or is about to be) testing. `sent` covers the short gap before the backend status catches
  // up.
  const validating = recs.status === "validating" || sent || !!nowStart;
  // How many approved fixes are in that sandbox run, for the progress message.
  const testing = count("validating") || (sent ? draftCount("approve") : 0) || (nowStart?.n ?? 0);

  if (!items.length)
    return (
      <EmptyState title="Nothing to fix yet" center>
        Guardian suggests a fix for every finding. They appear here after the risk scoring step.
      </EmptyState>
    );

  return (
    <div className="gate-view">
      <div className="gate-main">
        <div className="gate-scroll">
          <div className="gate-in rem-in">
            <header className="page-head">
              <h1>Remediation <span className="faint rem-round">Round {recs.round}{recs.step != null ? ` · Step ${recs.step}` : ""}</span></h1>
              <p className="muted">
                Approve or reject each suggested fix. Validation starts once every fix has a decision; approved fixes are tested together in one sandbox copy.
                Nothing changes in your repository.
              </p>
              <div className="rem-mode" role="group" aria-label="How to decide">
                <div className="seg-tabs">
                  <button type="button" className={!one ? "on" : ""} aria-pressed={!one} onClick={() => setMode("all")}>Decide all together</button>
                  <button type="button" className={one ? "on" : ""} aria-pressed={one} onClick={() => setMode("one")}>One at a time</button>
                </div>
                {one && <span className="faint">Each decision is sent from its own row, so you can follow what Guardian does after every step.</span>}
              </div>
              <ul className="rem-counts" aria-label="Where the fixes stand">
                {counts
                  .filter(([, n], i) => n > 0 || (i === 0 && waiting))
                  .map(([label, n]) => (
                    <li key={label}>
                      <span className="num">{n}</span> {label}
                    </li>
                  ))}
              </ul>
            </header>

            {!me.can_decide && waiting && (
              <Callout tone="info" title="Only approvers can decide" icon={<Info size={18} aria-hidden />}>
                You are signed in as {me.name} ({me.role}), so you can read everything here but not approve, reject or accept the risk. Ask an approver to open this page.
              </Callout>
            )}
            {me.can_decide && waiting && kind !== "api" && (
              <Callout tone="info" title="This is a read-only copy of a scan" icon={<Info size={18} aria-hidden />}>
                Decisions need the live Guardian service.
              </Callout>
            )}

            <div className="rem-tools">
              {pending.length > 0 && (
                <div className="seg-tabs" role="group" aria-label="Show">
                  <button type="button" className={filter === "needs" ? "on" : ""} aria-pressed={filter === "needs"} onClick={() => setFilter("needs")}>
                    Needs decision ({pending.length})
                  </button>
                  <button type="button" className={filter === "all" ? "on" : ""} aria-pressed={filter === "all"} onClick={() => setFilter("all")}>
                    All ({items.length})
                  </button>
                </div>
              )}
              <span className="faint rem-coverage">
                {items.length} rows cover all {new Set(items.flatMap((r) => r.finding_ids)).size} findings: advisories on one package, and
                fixes that edit the same dependency, share a row.
              </span>
              {editable && !one && undecided.length > 0 &&
                (confirmAll ? (
                  <span className="rem-confirm" role="group" aria-label="Confirm approving all remaining fixes">
                    <span>Approve {plural(undecided.length, "remaining fix", "remaining fixes")}?</span>
                    <button
                      type="button"
                      className="btn sm primary"
                      autoFocus
                      onClick={() => {
                        setDrafts((prev) => {
                          const next = { ...prev };
                          for (const p of undecided) next[p.rec_id] = { decision: "approve", comment: "", planId: p.plan_id };
                          return next;
                        });
                        setConfirmAll(false);
                      }}
                    >
                      Yes, approve {undecided.length}
                    </button>
                    <button type="button" className="btn sm" onClick={() => setConfirmAll(false)}>Cancel</button>
                  </span>
                ) : (
                  <button type="button" className="btn sm" onClick={() => setConfirmAll(true)}>
                    Approve all remaining ({undecided.length})
                  </button>
                ))}
            </div>

            <ul className="rem-list" aria-label="Suggested fixes, riskiest first">
              {shown.map((rec) => (
                <Row
                  key={rec.rec_id}
                  rec={rec}
                  draft={draftOf(rec)}
                  editable={editable && pending.includes(rec)}
                  one={one}
                  flash={flashId === rec.rec_id}
                  busyNote={backendBusy ? "Guardian is working on the last step. You can submit the next one when it finishes." : null}
                  submitting={rowBusy === rec.rec_id}
                  anyBusy={!!rowBusy}
                  rowErr={rowErr?.id === rec.rec_id ? rowErr.msg : null}
                  onSubmitOne={() => void submitOne(rec)}
                  showErrors={showErrors}
                  open={open.has(rec.rec_id)}
                  onToggle={() => toggle(rec.rec_id)}
                  onDraft={(d) => setDraft(rec, d)}
                  canValidate={canValidateNow && rec.outcome === "approved" && !!rec.plan_id}
                  validateBusy={nowBusy || validating}
                  onValidate={() => void validateNow([rec])}
                />
              ))}
            </ul>
          </div>
        </div>

        <footer className="decision">
          <div className="decision-in rem-foot">
            {validating ? (
              <div className="progress" role="status" aria-live="polite">
                <p className="progress-title">
                  <Loader2 size={16} className="spin" aria-hidden />{" "}
                  {testing > 0 ? `Validating ${plural(testing, "approved fix", "approved fixes")}${testing > 1 ? " together" : ""} in the sandbox…` : "Validating the approved fixes together in the sandbox…"}
                </p>
                <p className="faint">Guardian applies them to one copy of your project, builds, runs the tests and re-scans it. This can take a few minutes.</p>
                <button type="button" className="btn sm" onClick={() => setView("validation")}>Open validation</button>
              </div>
            ) : recs.status === "done" || status === "done" ? (
              <p className="decided">
                <CheckCircle2 size={18} aria-hidden className="okc" />
                <span>
                  All rounds are finished.{" "}
                  <button type="button" className="linkish inline" onClick={() => setView("report")}>Open the report</button>
                </span>
              </p>
            ) : one && pending.length > 0 ? (
              <>
              <p className="rem-progress" aria-live="polite">
                One at a time: submit each decision from its row. <b className="num">{pending.length}</b> still waiting.
                {held.length > 0 && (
                  <> <b className="num">{held.length}</b> approved {held.length === 1 ? "fix waits" : "fixes wait"} and will be tested together after the last decision, or use <b>Validate now</b> to test {held.length === 1 ? "it" : "them"} straight away while the others keep waiting.</>
                )}
              </p>
              {held.length > 0 && canValidateNow && (
                <div className="rem-foot-row">
                  <button type="button" className="btn primary" disabled={nowBusy || backendBusy} onClick={() => void validateNow(held)}>
                    {nowBusy ? <><Loader2 size={16} className="spin" aria-hidden /> Starting</> : `Validate ${held.length} approved ${held.length === 1 ? "fix" : "fixes"} now`}
                  </button>
                  {nowErr && <p className="err-inline" role="alert">{nowErr}</p>}
                </div>
              )}
              </>
            ) : waiting && pending.length > 0 ? (
              <>
                {editable && me.mode !== "token" && (
                  <label className="field decided-by rem-by">
                    <span>Your name</span>
                    <input value={by} onChange={(e) => setBy(e.target.value)} maxLength={60} />
                  </label>
                )}
                <div className="rem-foot-row">
                  <p className="rem-progress" aria-live="polite">
                    <b className="num">{complete.length}</b> of <b className="num">{pending.length}</b> fixes decided
                    {noReason.length > 0 && <span className="faint"> · {plural(noReason.length, "still needs a reason", "still need a reason")}</span>}
                  </p>
                  <button type="button" className="btn primary lg" disabled={!canSubmit} onClick={() => void submit()}>
                    {busy ? <><Loader2 size={16} className="spin" aria-hidden /> Sending</> : "Submit decisions and start validation"}
                  </button>
                </div>
                {err && <p className="err-inline" role="alert">{err}</p>}
              </>
            ) : (
              <p className="muted">Nothing is waiting for a decision right now.</p>
            )}
          </div>
        </footer>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- one recommendation

/**
 * One recommendation: finding, suggested change, history of earlier attempts, decision controls and expandable
 * detail/log. Which controls show depends on `editable` and `one`.
 */
function Row({
  rec, draft, editable, showErrors, open, onToggle, onDraft, one, busyNote, submitting, anyBusy, rowErr, onSubmitOne, flash,
  canValidate, validateBusy, onValidate,
}: {
  // 'Validate now' for an approved row that is held (one-at-a-time mode), disabled while a validation runs
  canValidate: boolean;
  validateBusy: boolean;
  onValidate: () => void;
  // scroll into view and highlight (after a reject)
  flash: boolean;
  one: boolean;
  // why submitting is disabled right now (the backend is working), or null
  busyNote: string | null;
  submitting: boolean;
  // some row is sending, so every Submit button waits
  anyBusy: boolean;
  rowErr: string | null;
  onSubmitOne: () => void;
  rec: Recommendation;
  draft: Draft | undefined;
  editable: boolean;
  showErrors: boolean;
  open: boolean;
  onToggle: () => void;
  onDraft: (d: Draft) => void;
}) {
  const { findingsById, riskById, plansById, openFinding } = useStore();
  const f = findingsById.get(rec.primary_finding_id);
  const band = f ? bandOf(f, riskById) : null;
  const score = riskById.get(rec.primary_finding_id)?.score ?? null;
  const plan = rec.plan_id ? plansById.get(rec.plan_id) : undefined;
  const sum = plan ? planSummary(plan, f, band) : null;
  const more = rec.finding_ids.length - 1;
  const st = STATUS[rec.outcome];
  const detailId = `rem-d-${rec.rec_id}`;
  const prevPlan = rec.previous ? plansById.get(rec.previous.plan_id) : undefined;
  // Attempt number of the earlier suggestion this one replaces: from its plan, else derived from this plan's
  // attempt.
  const prevN = prevPlan?.attempt ?? (plan && plan.attempt > 1 ? plan.attempt - 1 : null);
  const commentRef = useRef<HTMLTextAreaElement>(null);
  const rowRef = useRef<HTMLLIElement>(null);
  // after a reject in one-at-a-time mode: bring the row (and its new suggestion) into view
  useEffect(() => {
    if (!flash) return;
    let calm = false;
    try {
      calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    } catch {
      /* default motion */
    }
    rowRef.current?.scrollIntoView({ behavior: calm ? "auto" : "smooth", block: "center" });
  }, [flash, rec.plan_id]);
  // Reject and accept-risk need a written reason before they can be sent.
  const missingReason = needsReason(draft) && !draft!.comment.trim();

  return (
    <li ref={rowRef} className={`rem-row${flash ? " flash" : ""}`}>
      <div className="rem-head">
        <span className="rem-risk">
          <SevPill risk={band} />
          {score != null && <span className="num rem-score" title="Guardian risk score, out of 100">{Math.round(score)}</span>}
        </span>
        <div className="rem-title">
          <button type="button" className="linkish" onClick={() => openFinding(rec.primary_finding_id)} title="Open the finding and its evidence">
            {f ? plainTitle(f, band) : rec.primary_finding_id}
          </button>
          {more > 0 && <span className="faint"> +{more} more {more === 1 ? "advisory" : "advisories"} on this package</span>}
        </div>
        {!editable && <span className={`pill ${st.cls}`}>{st.label}</span>}
        {canValidate && (
          <button type="button" className="btn sm primary rem-validate" disabled={validateBusy} onClick={onValidate} title="Test this approved fix in the sandbox now. The other fixes keep waiting for decisions.">
            {validateBusy ? <><Loader2 size={14} className="spin" aria-hidden /> Validating</> : "Validate now"}
          </button>
        )}
      </div>

      {rec.kind === "fix" ? (
        <p className="rem-change">
          <span className="faint">Suggested change</span>{" "}
          <b>{sum ? sum.change : "loading the suggested change…"}</b>
          {sum?.major && <span className="pill gate rem-major">Major version jump</span>}
        </p>
      ) : (
        <p className="rem-change">
          <b>No alternatives</b>
          {rec.reason && <span className="muted"> {rec.reason.replace(/^No alternatives:\s*/i, "— ")}</span>}
        </p>
      )}

      {rec.previous && (
        <p className="rem-prev">
          {prevN ? `Attempt ${prevN} ` : "An earlier attempt "}
          {rec.previous.outcome === "failed"
            ? "failed validation"
            : `was rejected${rec.previous.reason_type && REJECT_LABEL[rec.previous.reason_type] ? ` (${REJECT_LABEL[rec.previous.reason_type].toLowerCase()})` : ""}`}
          {rec.previous.detail ? `: ${rec.previous.detail}` : ""}.
          {rec.kind === "fix" ? " This is the next alternative." : ""}
        </p>
      )}
      {rec.previous?.outcome === "rejected" && rec.steer_note && (
        <p className="rem-steer">
          <span className="faint">How Guardian read your reason:</span> {rec.steer_note}{" "}
          {rec.steer_source === "llm" ? <span className="claim-tag i">AI interpretation</span> : rec.steer_source === "rules" ? <span className="pill">Rule</span> : null}
        </p>
      )}
      {rec.kind === "fix" && rec.reason && !rec.previous && <p className="muted rem-note">{rec.reason}</p>}

      {rec.alternatives.length > 0 && (
        <p className="rem-alts muted">
          <span className="faint">{plural(rec.alternatives.length, "other option", "other options")} if this one does not work:</span>{" "}
          {rec.alternatives.slice(0, 3).map((a) => a.summary).join("; ")}
          {rec.alternatives.length > 3 ? ` and ${rec.alternatives.length - 3} more` : ""}
        </p>
      )}

      {editable && (
        <div className="rem-decide">
          <div className="rem-opts" role="group" aria-label={`Your decision on: ${f ? plainTitle(f, band) : rec.primary_finding_id}`}>
            {OPTIONS.map((o) => {
              const on = draft?.decision === o.id;
              return (
                <button
                  key={o.id}
                  type="button"
                  className={`btn sm rem-opt ${o.id}${on ? " on" : ""}`}
                  aria-pressed={on}
                  title={o.help}
                  onClick={() => {
                    onDraft({ decision: o.id, comment: draft?.comment ?? "", reasonType: o.id === "reject" ? (draft?.reasonType ?? null) : null });
                    if (o.id !== "approve") window.setTimeout(() => commentRef.current?.focus(), 0);
                  }}
                >
                  {on && <Check size={14} aria-hidden />}
                  {o.label}
                </button>
              );
            })}
          </div>
          {draft?.decision === "reject" && (
            <fieldset className={`rem-why${!draft.reasonType && showErrors ? " invalid" : ""}`}>
              <legend>
                Why reject it? <b className="req">(required; it decides what Guardian suggests next)</b>
              </legend>
              <div className="rem-why-opts">
                {REJECT_REASONS.map((r) => (
                  <label key={r.id} className={`rem-why-opt${draft.reasonType === r.id ? " on" : ""}`}>
                    <input
                      type="radio"
                      name={`why-${rec.rec_id}`}
                      checked={draft.reasonType === r.id}
                      onChange={() => onDraft({ ...draft, reasonType: r.id })}
                    />
                    <span>
                      <b>{r.label}</b>
                      <span className="muted">{r.effect}</span>
                    </span>
                  </label>
                ))}
              </div>
              {!draft.reasonType && showErrors && <span className="field-err" role="alert">Pick why you are rejecting it.</span>}
            </fieldset>
          )}
          {needsReason(draft) && (
            <label className={`field rem-comment${missingReason && showErrors ? " invalid" : ""}`}>
              <span>
                Reason <b className="req">(required to {draft!.decision === "reject" ? "reject" : "accept the risk"}; recorded in the audit trail)</b>
              </span>
              <textarea
                ref={commentRef}
                rows={2}
                value={draft!.comment}
                onChange={(e) => onDraft({ ...draft!, comment: e.target.value })}
                placeholder="Why are you making this decision?"
                aria-invalid={missingReason && showErrors}
              />
              {missingReason && showErrors && <span className="field-err" role="alert">Write a short reason first.</span>}
            </label>
          )}
          {one && (
            <div className="rem-one">
              <button type="button" className="btn primary sm" disabled={!isComplete(draft) || !!busyNote || anyBusy} onClick={onSubmitOne}>
                {submitting ? <><Loader2 size={14} className="spin" aria-hidden /> Sending</> : "Submit this decision"}
              </button>
              {busyNote ? <span className="faint">{busyNote}</span> : draftProblem(draft) && <span className="faint" role="status">{draftProblem(draft)}</span>}
            </div>
          )}
          {rowErr && <p className="err-inline" role="alert">{rowErr}</p>}
        </div>
      )}

      <Trace rec={rec} />

      {rec.kind === "fix" && plan && (
        <>
          <button type="button" className="btn ghost sm rem-more" aria-expanded={open} aria-controls={detailId} onClick={onToggle}>
            {open ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
            {open ? "Hide details" : "Show the change and why"}
          </button>
          {open && <Detail id={detailId} rec={rec} plan={plan} finding={f} />}
        </>
      )}
    </li>
  );
}

// ---------------------------------------------------------------- expanded plan detail

// Cap on diff lines rendered inline, so a huge patch (e.g. a lockfile) cannot freeze the page.
const MAX_DIFF_LINES = 400;

/**
 * Expanded part of a row: the diff, the reasoning split into verified and unproven claims, compatibility risk
 * and how to undo it.
 */
function Detail({ id, rec, plan, finding }: { id: string; rec: Recommendation; plan: RemediationPlan; finding: Finding | undefined }) {
  const { openEvidence } = useStore();
  const ev = useEvidenceMany(plan.evidence_ids);
  const diff = ev.items.find((e) => e.kind === "patch_diff" && e.excerpt);
  // Files the plan edits: from the patch evidence if present, else from the plan's operations.
  const files = useMemo(() => {
    const f = (diff?.facts as { files?: string[] } | undefined)?.files;
    return f && f.length ? f : [...new Set(plan.ops.map((o) => o.file_path))];
  }, [diff, plan.ops]);
  const lines = diff?.excerpt ? diff.excerpt.split("\n") : [];
  const cut = lines.length > MAX_DIFF_LINES;
  const c = plan.compatibility_impact;
  // Rationale claims the evidence proves vs. ones only inferred; the sandbox run checks the latter.
  const verified = plan.rationale.filter((r) => r.label === "verified");
  const inferred = plan.rationale.filter((r) => r.label !== "verified");

  return (
    <div className="rem-detail" id={id}>
      <section>
        <h4 className="mini-h">The change</h4>
        {files.length > 0 && <p className="muted">Edits {fileSummary(files)} in the sandbox copy only.</p>}
        {diff?.excerpt ? (
          <>
            <DiffView text={cut ? lines.slice(0, MAX_DIFF_LINES).join("\n") : diff.excerpt} />
            {cut && <p className="faint">Showing the first {MAX_DIFF_LINES} of {lines.length.toLocaleString()} lines.</p>}
          </>
        ) : ev.loaded ? (
          <p className="muted">Guardian has not attached a preview of the change to this plan.</p>
        ) : (
          <Skeleton h={90} />
        )}
      </section>

      <section>
        <h4 className="mini-h">Why Guardian suggests this</h4>
        {verified.length > 0 && (
          <div className="claimgroup">
            <h5 className="mini-h">Verified facts <span className="faint">(from scanners and registries)</span></h5>
            <ClaimList claims={verified} onCite={openEvidence} origin="rule" />
          </div>
        )}
        {inferred.length > 0 && (
          <div className="claimgroup">
            <h5 className="mini-h">Not yet proven <span className="faint">(the sandbox run will check)</span></h5>
            <ClaimList claims={inferred} onCite={openEvidence} origin="rule" />
          </div>
        )}
        {plan.rationale.length === 0 && <p className="muted">No reasoning was recorded for this plan.</p>}
      </section>

      <section>
        <h4 className="mini-h">Compatibility risk</h4>
        {c ? (
          <p>
            Rated <b>{c.level}</b>
            {c.from_version && c.to_version ? `: ${c.from_version} to ${c.to_version}, a ${c.semver_delta} change` : ""}.
            {c.engines_ok === false ? " The target does not support your Node version." : ""}
            {c.peer_dep_changes.length ? ` Peer dependency changes: ${c.peer_dep_changes.join(", ")}.` : ""}
            {c.deprecated_target ? " The target version is deprecated." : ""}
          </p>
        ) : (
          <p className="muted">No compatibility check was recorded for this change.</p>
        )}
      </section>

      <section>
        <h4 className="mini-h">How to undo it</h4>
        <p className="prose">{plan.rollback}</p>
      </section>

      <details className="more">
        <summary>Technical details</summary>
        <dl className="kv">
          <dt>Recommendation</dt><dd className="mono">{rec.rec_id}</dd>
          <dt>Plan</dt><dd className="mono">{plan.plan_id}</dd>
          <dt>Plan hash</dt><dd className="mono hashfull">{plan.plan_hash}</dd>
          <dt>Steps</dt><dd>{plural(plan.ops.length, "operation")}</dd>
          {finding && <><dt>Finding</dt><dd className="mono">{finding.finding_id}</dd></>}
        </dl>
      </details>
    </div>
  );
}

// ---------------------------------------------------------------- what happened (debugging trail)

// Event type to the short word shown in the log.
const TYPE_LABEL: Record<string, string> = {
  agent_start: "started",
  agent_end: "finished",
  decision: "decision",
  guardrail: "refused",
  gate_wait: "waiting",
  gate_resume: "resumed",
  validate_now: "validate now",
  error: "error",
};

/** Collapsible 'What happened' log for one recommendation (debugging trail). */
function Trace({ rec }: { rec: Recommendation }) {
  const { events } = useStore();
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" className="btn ghost sm rem-more" aria-expanded={open} aria-controls={`rem-t-${rec.rec_id}`} onClick={() => setOpen(!open)}>
        {open ? <ChevronDown size={14} aria-hidden /> : <ChevronRight size={14} aria-hidden />}
        {open ? "Hide what happened" : "What happened"}
      </button>
      {open && <TraceList id={`rem-t-${rec.rec_id}`} rec={rec} events={events} />}
    </>
  );
}

/** Events that belong to this row, newest 50 by default. `events` is the run's full event log. */
function TraceList({ id, rec, events }: { id: string; rec: Recommendation; events: ReturnType<typeof useStore>["events"] }) {
  const [all, setAll] = useState(false);
  // An event belongs to this row if it names one of its findings or its current or previous plan. Events carry
  // those ids in several places (finding_id, data.plan_id, plan_ids, also, finding_ids).
  const rows = useMemo(() => {
    const fids = new Set(rec.finding_ids);
    const pids = new Set([rec.plan_id, rec.previous?.plan_id].filter((x): x is string => !!x));
    const listHas = (v: unknown, set: Set<string>) => Array.isArray(v) && v.some((x) => typeof x === "string" && set.has(x));
    return events.filter((e) => {
      const d = (e.data ?? {}) as Record<string, unknown>;
      if (e.finding_id && fids.has(e.finding_id)) return true;
      if (typeof d.plan_id === "string" && pids.has(d.plan_id)) return true;
      if (typeof d.finding_id === "string" && fids.has(d.finding_id)) return true;
      return listHas(d.plan_ids, pids) || listHas(d.also, pids) || listHas(d.finding_ids, fids);
    });
  }, [events, rec.finding_ids, rec.plan_id, rec.previous?.plan_id]);
  // Latest 50 steps unless expanded.
  const shown = all ? rows : rows.slice(-50);
  return (
    <div className="rem-trace" id={id}>
      {rows.length === 0 ? (
        <p className="muted">No steps are recorded for this fix yet.</p>
      ) : (
        <>
          {rows.length > shown.length && (
            <button type="button" className="btn ghost sm" onClick={() => setAll(true)}>Show all {rows.length} steps ({rows.length - shown.length} earlier)</button>
          )}
          <ol className="rem-ev-list">
            {shown.map((e, i) => {
              const rule = e.type === "guardrail" ? String((e.data as { rule?: unknown })?.rule ?? "") : "";
              return (
                <li key={`${e.ts}-${i}`} className={`rem-ev${e.type === "guardrail" ? " refused" : ""}`}>
                  <span className="mono faint rem-ev-t">{clock(e.ts)}</span>
                  <span className="rem-ev-a">{AGENT_LABEL[e.agent as AgentId] ?? e.agent}</span>
                  <span className={`pill${e.type === "guardrail" ? " gate" : ""}`}>{TYPE_LABEL[e.type] ?? e.type.replace(/_/g, " ")}</span>
                  <span className="rem-ev-s">
                    {rule && <span className="pill gate mono">{rule}</span>} {e.summary}
                  </span>
                </li>
              );
            })}
          </ol>
        </>
      )}
    </div>
  );
}
