import { Check, CheckCircle2, ChevronDown, ChevronRight, Info, Loader2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { submitBatchDecisions, type RejectReason } from "../api/client";
import type { Finding, RecDecision, RecOutcome, Recommendation, RecommendationsFile, RemediationPlan } from "../api/types";
import { bandOf, clock, plural } from "../lib/format";
import { plainTitle } from "../lib/labels";
import { planSummary } from "../lib/plan";
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

type Mode = "all" | "one";

type Draft = { decision: RecDecision; comment: string; reasonType?: RejectReason | null };
type Drafts = Record<string, Draft>;

const STATUS: Record<RecOutcome, { label: string; cls: string }> = {
  awaiting_decision: { label: "Waiting for a decision", cls: "gate" },
  validating: { label: "Being tested", cls: "gate" },
  verified: { label: "Verified", cls: "ok" },
  failed: { label: "Failed validation", cls: "bad" },
  rejected: { label: "Rejected", cls: "bad" },
  accepted: { label: "Risk accepted", cls: "info" },
  no_alternative: { label: "No alternatives", cls: "dashed" },
  needs_person: { label: "Needs a person", cls: "bad" },
};

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

const needsReason = (d: Draft | undefined) => !!d && d.decision !== "approve";
const isComplete = (d: Draft | undefined) =>
  !!d && (d.decision === "approve" || (d.comment.trim().length > 0 && (d.decision !== "reject" || !!d.reasonType)));

/** "36 files: a, b, c and 33 more" */
function fileSummary(files: string[]): string {
  const n = files.length;
  if (n <= 3) return n === 1 ? files[0] : `${n} files: ${files.join(", ")}`;
  return `${n} files: ${files.slice(0, 3).join(", ")} and ${n - 3} more`;
}

function loadDrafts(key: string): Drafts {
  try {
    const raw = sessionStorage.getItem(key);
    return raw ? (JSON.parse(raw) as Drafts) : {};
  } catch {
    return {};
  }
}

function BatchPage({ recs, mode, setMode }: { recs: RecommendationsFile; mode: Mode; setMode: (m: Mode) => void }) {
  const { data, riskById, findingsById, me, kind, src, refresh, status, setView } = useStore();
  const batchId = recs.batch_id;
  const one = mode === "one";
  const storeKey = one ? `guardian.rem.${src.runId}.steps` : `guardian.rem.${src.runId}.${batchId ?? "none"}`;

  const items = useMemo(() => {
    const score = (r: Recommendation) => riskById.get(r.primary_finding_id)?.score ?? (findingsById.get(r.primary_finding_id)?.cvss ?? 0) * 10;
    return [...recs.items].sort((a, b) => score(b) - score(a));
  }, [recs.items, riskById, findingsById]);
  const waiting = recs.status === "awaiting_decisions" && !!batchId;
  const pending = useMemo(
    () => (waiting || one ? items.filter((i) => i.kind === "fix" && i.outcome === "awaiting_decision") : []),
    [items, waiting, one],
  );
  // the backend is working: row submits wait, so two steps never overlap
  const backendBusy = recs.status === "validating" || status === "running";

  // ---- draft decisions (local until submitted)
  const [drafts, setDraftsState] = useState<Drafts>(() => (batchId || one ? loadDrafts(storeKey) : {}));
  const setDrafts = (next: Drafts) => {
    setDraftsState(next);
    if (!batchId && !one) return;
    try {
      sessionStorage.setItem(storeKey, JSON.stringify(next));
    } catch {
      /* storage unavailable: the draft lives for this page load */
    }
  };
  const setDraft = (id: string, d: Draft) => setDrafts({ ...drafts, [id]: d });

  const [filter, setFilter] = useState<"needs" | "all">(pending.length ? "needs" : "all");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const toggle = (id: string) =>
    setOpen((p) => {
      const n = new Set(p);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const [confirmAll, setConfirmAll] = useState(false);
  const [showErrors, setShowErrors] = useState(false);
  const [by, setBy] = useStoredState<string>("guardian.decider", "reviewer");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [flashId, setFlashId] = useState<string | null>(null);
  useEffect(() => {
    if (!flashId) return;
    const t = window.setTimeout(() => setFlashId(null), 12000);
    return () => window.clearTimeout(t);
  }, [flashId]);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [rowErr, setRowErr] = useState<{ id: string; msg: string } | null>(null);

  const editable = me.can_decide && kind === "api" && !sent && (one ? pending.length > 0 : waiting);
  const complete = pending.filter((p) => isComplete(drafts[p.rec_id]));
  const undecided = pending.filter((p) => !drafts[p.rec_id]);
  const noReason = pending.filter((p) => needsReason(drafts[p.rec_id]) && !isComplete(drafts[p.rec_id]));
  const canSubmit = editable && pending.length > 0 && complete.length === pending.length && !busy;

  // after submitting, follow the run quickly until it has moved on
  useEffect(() => {
    if (!sent || status === "done" || status === "failed") return;
    const t = window.setInterval(() => void refresh(), 1500);
    return () => window.clearInterval(t);
  }, [sent, status, refresh]);

  const submit = async () => {
    if (!batchId || !canSubmit) {
      setShowErrors(true);
      return;
    }
    setBusy(true);
    setErr(null);
    const decisions = pending.map((p) => {
      const d = drafts[p.rec_id];
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

  // one decision on its own, for stepping through the flow
  const submitOne = async (p: Recommendation) => {
    const d = drafts[p.rec_id];
    if (!batchId || !isComplete(d) || backendBusy || rowBusy) return;
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
      const next = { ...drafts };
      delete next[p.rec_id];
      setDrafts(next);
      if (d.decision === "reject") setFlashId(p.rec_id);
      void refresh();
    } else setRowErr({ id: p.rec_id, msg: r.message });
  };

  // ---- header counts
  const count = (o: RecOutcome) => items.filter((i) => i.outcome === o).length;
  const draftCount = (d: RecDecision) => pending.filter((p) => drafts[p.rec_id]?.decision === d).length;
  const counts: [string, number][] = [
    ["to decide", undecided.length],
    ["approved", draftCount("approve") + count("validating")],
    ["rejected", draftCount("reject") + count("rejected")],
    ["accepted", draftCount("accept_risk") + count("accepted")],
    ["no alternatives", count("no_alternative")],
    ["verified", count("verified")],
    ["failed validation", count("failed")],
    ["need a person", count("needs_person")],
  ];

  const shown = filter === "needs" && pending.length ? pending : items;
  const validating = recs.status === "validating" || sent;
  const testing = count("validating") || (sent ? draftCount("approve") : 0);

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
              {editable && !one && undecided.length > 0 &&
                (confirmAll ? (
                  <span className="rem-confirm" role="group" aria-label="Confirm approving all remaining fixes">
                    <span>Approve {plural(undecided.length, "remaining fix", "remaining fixes")}?</span>
                    <button
                      type="button"
                      className="btn sm primary"
                      autoFocus
                      onClick={() => {
                        const next = { ...drafts };
                        for (const p of undecided) next[p.rec_id] = { decision: "approve", comment: "" };
                        setDrafts(next);
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
                  draft={drafts[rec.rec_id]}
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
                  onDraft={(d) => setDraft(rec.rec_id, d)}
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
                  {testing > 0 ? `Validating ${plural(testing, "approved fix", "approved fixes")} together in the sandbox…` : "Validating the approved fixes together in the sandbox…"}
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
              <p className="rem-progress" aria-live="polite">
                One at a time: submit each decision from its row. <b className="num">{pending.length}</b> still waiting.
              </p>
            ) : waiting ? (
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

function Row({
  rec, draft, editable, showErrors, open, onToggle, onDraft, one, busyNote, submitting, anyBusy, rowErr, onSubmitOne, flash,
}: {
  flash: boolean;
  one: boolean;
  busyNote: string | null;
  submitting: boolean;
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
              {busyNote ? <span className="faint">{busyNote}</span> : !isComplete(draft) && <span className="faint">Choose a decision{draft && draft.decision !== "approve" ? " and fill in the reasons" : ""} first.</span>}
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

const MAX_DIFF_LINES = 400;

function Detail({ id, rec, plan, finding }: { id: string; rec: Recommendation; plan: RemediationPlan; finding: Finding | undefined }) {
  const { openEvidence } = useStore();
  const ev = useEvidenceMany(plan.evidence_ids);
  const diff = ev.items.find((e) => e.kind === "patch_diff" && e.excerpt);
  const files = useMemo(() => {
    const f = (diff?.facts as { files?: string[] } | undefined)?.files;
    return f && f.length ? f : [...new Set(plan.ops.map((o) => o.file_path))];
  }, [diff, plan.ops]);
  const lines = diff?.excerpt ? diff.excerpt.split("\n") : [];
  const cut = lines.length > MAX_DIFF_LINES;
  const c = plan.compatibility_impact;
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

const TYPE_LABEL: Record<string, string> = {
  agent_start: "started",
  agent_end: "finished",
  decision: "decision",
  guardrail: "refused",
  gate_wait: "waiting",
  gate_resume: "resumed",
  error: "error",
};

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

function TraceList({ id, rec, events }: { id: string; rec: Recommendation; events: ReturnType<typeof useStore>["events"] }) {
  const [all, setAll] = useState(false);
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
