import { useEffect, useMemo, useState } from "react";
import { postDecision } from "../api/client";
import type { Approval, Finding, RemediationPlan } from "../api/types";
import { bandOf, findingHeadline } from "../lib/format";
import { useStore } from "../store";
import { useEvidenceMany, useStoredState } from "./hooks";
import RiskTable, { ScoreBar } from "./RiskTable";
import { ClaimList, DiffView, EvChip, Json, Section, SevPill } from "./ui";

function planState(p: RemediationPlan, pendingId: string | undefined, approvals: Approval[]) {
  if (p.plan_id === pendingId) return { key: "pending", label: "Awaiting decision", cls: "gate" };
  const a = [...approvals].reverse().find((x) => x.plan_id === p.plan_id);
  if (a) {
    if (a.decision === "approve") return { key: "approved", label: "Approved", cls: "ok" };
    if (a.decision === "reject") return { key: "rejected", label: "Rejected", cls: "bad" };
    return { key: "accepted", label: "Risk accepted", cls: "sev-medium" };
  }
  return { key: "proposed", label: "Proposed", cls: "" };
}

export default function ApprovalGate() {
  const { data, findingsById } = useStore();
  const pending = data.summary.pending_plan ?? undefined;
  const [sel, setSel] = useState<string | null>(null);
  const plans = data.plans;
  const current = plans.find((p) => p.plan_id === (sel ?? pending?.plan_id)) ?? plans[plans.length - 1];

  if (!plans.length)
    return (
      <div className="empty">
        <strong>No remediation plans yet</strong>
        <span>
          {data.summary.status === "done"
            ? "This run finished without proposing any plan."
            : "Plans appear here as soon as the remediation agent proposes a fix for a finding."}
        </span>
      </div>
    );

  return (
    <div className="gate-view">
      <aside className="gate-list" aria-label="Plans">
        <h2>Plans</h2>
        <ul>
          {plans.map((p) => {
            const f = findingsById.get(p.finding_id);
            const st = planState(p, pending?.plan_id, data.approvals);
            return (
              <li key={p.plan_id}>
                <button
                  type="button"
                  className={`plan-item${current?.plan_id === p.plan_id ? " on" : ""}`}
                  onClick={() => setSel(p.plan_id)}
                >
                  <span className="plan-item-top">
                    <span className="mono">attempt {p.attempt}</span>
                    <span className={`pill ${st.cls}`}>{st.label}</span>
                  </span>
                  <span className="plan-item-title">{f ? findingHeadline(f) : p.finding_id}</span>
                  <span className="muted">
                    {p.action}
                    {p.target_version ? ` to ${p.target_version}` : ""}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </aside>
      {current && <PlanDetail key={current.plan_id} plan={current} finding={findingsById.get(current.finding_id)} />}
    </div>
  );
}

function PlanDetail({ plan, finding }: { plan: RemediationPlan; finding: Finding | undefined }) {
  const { data, riskById, src, kind, refresh } = useStore();
  const pending = data.summary.pending_plan ?? undefined;
  const isPending = plan.plan_id === pending?.plan_id;
  const st = planState(plan, pending?.plan_id, data.approvals);
  const ev = useEvidenceMany(plan.evidence_ids);
  const diff = ev.items.find((e) => e.kind === "patch_diff" && e.excerpt);
  const risk = riskById.get(plan.finding_id);
  const approval = [...data.approvals].reverse().find((a) => a.plan_id === plan.plan_id);
  const missing = [
    !diff && (ev.loaded ? "patch diff evidence" : "diff (loading)"),
    !risk && "risk assessment",
    kind !== "api" && "live API connection",
  ].filter(Boolean) as string[];
  const ready = isPending && missing.length === 0;

  const [by, setBy] = useStoredState<string>("guardian.decider", "reviewer");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [res, setRes] = useState<{ ok: boolean; message: string } | null>(null);
  useEffect(() => setRes(null), [plan.plan_id]);

  const decide = async (decision: "approve" | "reject" | "accept_risk") => {
    if (decision !== "approve" && !comment.trim()) {
      setRes({ ok: false, message: "A comment is required to reject a plan or accept the risk." });
      return;
    }
    setBusy(decision);
    const r = await postDecision(src, plan.plan_id, {
      plan_hash: plan.plan_hash,
      decision,
      comment: comment.trim() || null,
      decided_by: by.trim() || "reviewer",
    });
    setBusy(null);
    setRes(r);
    if (r.ok) {
      setComment("");
      void refresh();
    }
  };

  const ops = useMemo(() => plan.ops, [plan.ops]);

  return (
    <div className="gate-main">
      <div className="gate-scroll">
        <header className="gate-head">
          <div className="insp-pills">
            {finding && <SevPill risk={bandOf(finding, riskById)} />}
            <span className={`pill ${st.cls}`}>{st.label}</span>
            <span className="pill mono">attempt {plan.attempt}</span>
          </div>
          <h2>{finding?.title ?? plan.finding_id}</h2>
          <p className="mono muted">
            {plan.plan_id} · hash {plan.plan_hash.slice(0, 12)}
          </p>
        </header>

        <Section title="Proposed fix">
          <p className="fixline">
            <b>{plan.action}</b>
            {plan.target_version && (
              <>
                {" "}
                to <span className="mono target">{plan.target_version}</span>
              </>
            )}
          </p>
          <table className="optable">
            <thead>
              <tr>
                <th>Operation</th>
                <th>File</th>
                <th>Arguments</th>
              </tr>
            </thead>
            <tbody>
              {ops.map((o, i) => (
                <tr key={`${o.op}-${i}`}>
                  <td className="mono">{o.op}</td>
                  <td className="mono">{o.file_path}</td>
                  <td>
                    <Json value={o.args} collapsedLines={4} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {plan.compatibility_impact && (
            <p className="muted compat">
              Compatibility {plan.compatibility_impact.level}: {plan.compatibility_impact.semver_delta} change{" "}
              <span className="mono">
                {plan.compatibility_impact.from_version} to {plan.compatibility_impact.to_version}
              </span>
              {plan.compatibility_impact.engines_ok === false ? ", engines mismatch" : ""}
              {plan.compatibility_impact.peer_dep_changes.length ? `, peer changes: ${plan.compatibility_impact.peer_dep_changes.join(", ")}` : ""}
            </p>
          )}
        </Section>

        <Section title="Patch diff" aside={diff ? <EvChip id={diff.evidence_id} /> : undefined}>
          {diff?.excerpt ? (
            <DiffView text={diff.excerpt} />
          ) : (
            <p className="muted">{ev.loaded ? "No patch_diff evidence is attached to this plan." : "Loading diff"}</p>
          )}
        </Section>

        <Section title="Target version and cited evidence">
          <ClaimList claims={plan.rationale} />
          <p className="muted expected">{plan.expected_risk_reduction}</p>
        </Section>

        <Section title="Risk score">
          {risk ? (
            <>
              <ScoreBar risk={risk} />
              <details className="more">
                <summary>Factor table</summary>
                <RiskTable risk={risk} />
              </details>
            </>
          ) : (
            <p className="muted">No risk assessment for this finding yet.</p>
          )}
        </Section>

        <Section title="Rollback">
          <p className="prose">{plan.rollback}</p>
        </Section>
      </div>

      <footer className="decision">
        {approval && !isPending ? (
          <p>
            <b>{approval.decision.replace("_", " ")}</b> by <span className="mono">{approval.decided_by}</span> at{" "}
            <span className="mono">{approval.ts.replace("T", " ").replace(/\.\d+/, "")}</span>
            {approval.comment ? <span className="muted"> - {approval.comment}</span> : null}
          </p>
        ) : !isPending ? (
          <p className="muted">This plan is not the one waiting at the gate.</p>
        ) : (
          <>
            <div className="decision-fields">
              <label>
                <span>Decided by</span>
                <input value={by} onChange={(e) => setBy(e.target.value)} maxLength={60} />
              </label>
              <label className="grow">
                <span>Comment (required to reject or accept risk)</span>
                <textarea rows={2} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Reason for the decision" />
              </label>
            </div>
            <div className="decision-actions">
              <button type="button" className="btn primary" disabled={!ready || !!busy} onClick={() => decide("approve")}>
                {busy === "approve" ? "Sending" : "Approve"}
              </button>
              <button type="button" className="btn danger" disabled={!ready || !!busy} onClick={() => decide("reject")}>
                {busy === "reject" ? "Sending" : "Reject"}
              </button>
              <button type="button" className="btn warn" disabled={!ready || !!busy} onClick={() => decide("accept_risk")}>
                {busy === "accept_risk" ? "Sending" : "Accept Risk"}
              </button>
              {!ready && <span className="muted">Waiting for: {missing.join(", ")}</span>}
            </div>
          </>
        )}
        {res && (
          <p className={res.ok ? "ok-inline" : "err-inline"} role={res.ok ? "status" : "alert"}>
            {res.message}
          </p>
        )}
      </footer>
    </div>
  );
}
