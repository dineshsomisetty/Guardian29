import { Download, FileText } from "lucide-react";
import { useEffect, useState } from "react";
import { loadReport } from "../api/client";
import type { ReportJson } from "../api/types";
import { bandOf, fmtDate, purlLabel } from "../lib/format";
import { plainTitle, verdictFail } from "../lib/labels";
import { planSummary } from "../lib/plan";
import { useStore } from "../store";
import { useReportLinks } from "./hooks";
import { EmptyState, Section, SevPill, Skeleton } from "./ui";

const STATUS_WORD: Record<string, string> = {
  verified: "Fixed and verified",
  escalated: "Needs a person",
  accepted: "Risk accepted",
  assessed: "Assessed, no fix yet",
  awaiting_human: "Waiting for approval",
  planned: "Fix planned",
  open: "Open",
};
const DEC_WORD: Record<string, string> = { approve: "Approved", reject: "Rejected", accept_risk: "Risk accepted" };

export default function ReportView() {
  const { src, status, findingsById, openFinding, riskById, data, setView } = useStore();
  const links = useReportLinks(src, status);
  const [rep, setRep] = useState<ReportJson | null | "loading">("loading");
  useEffect(() => {
    let dead = false;
    if (links === "pending") return;
    if (typeof links !== "object" || !links.json) {
      setRep(null);
      return;
    }
    setRep("loading");
    loadReport(src).then((r) => !dead && setRep(r));
    return () => {
      dead = true;
    };
  }, [links, src]);

  const url = (k: "json" | "html") => (typeof links === "object" ? links[k] : null);

  return (
    <div className="page">
      <div className="page-in">
        <header className="page-head row-between">
          <div>
            <h1>Report</h1>
            <p className="muted">The final write-up of this scan: what was found, what was done about it, and what is left.</p>
          </div>
          <div className="row">
            {(["html", "json"] as const).map((k) => {
              const u = url(k);
              const label = k === "html" ? "Download HTML" : "Download JSON";
              return u ? (
                <a key={k} className="btn" href={u} target="_blank" rel="noreferrer" download={`report.${k}`}>
                  <Download size={16} aria-hidden /> {label}
                </a>
              ) : (
                <button key={k} type="button" className="btn" disabled>
                  <Download size={16} aria-hidden /> {label}
                </button>
              );
            })}
          </div>
        </header>

        {(rep === "loading" || links === "pending") && (
          <div className="skel-rows" role="status" aria-label="Loading the report">
            <Skeleton h={120} />
            <Skeleton h={200} />
          </div>
        )}
        {rep === null && links !== "pending" && (
          <EmptyState icon={<FileText size={32} aria-hidden />} title="The report is not ready yet" center>
            Guardian writes the report when the scan is complete.{" "}
            {data.summary.pending_plan || status === "awaiting_human"
              ? "This scan is paused until you decide on the proposed fix. Approve, reject or accept the risk on the Approval page, and the report follows."
              : status === "failed"
                ? "This scan stopped with an error, so no report was written. The activity log shows where it stopped."
                : "This scan is still running. The report appears here when it finishes."}
          </EmptyState>
        )}
        {rep && rep !== "loading" && (
          <>
            <Section title="Outcome">
              <dl className="facts wide">
                <div><dt>Scanned</dt><dd>{rep.target}</dd></div>
                <div><dt>Written</dt><dd>{fmtDate(rep.generated_at)}</dd></div>
                <div><dt>Packages</dt><dd>{rep.inventory.components.toLocaleString()} ({rep.inventory.direct.toLocaleString()} direct, {rep.inventory.transitive.toLocaleString()} indirect)</dd></div>
                <div><dt>Confidence in the result</dt><dd>{rep.final_confidence}</dd></div>
                <div><dt>Work done</dt><dd>{rep.audit.events.toLocaleString()} steps recorded, {rep.audit.llm_calls} AI calls, {rep.audit.tool_calls} tool runs</dd></div>
                <div><dt>Safety rules triggered</dt><dd>{rep.guardrail_events.length}</dd></div>
              </dl>
            </Section>
            <Section title={`What was done about it (${rep.actions.length})`}>
              {rep.actions.length === 0 && <p className="muted">No fixes were proposed.</p>}
              <ul className="plain">
                {rep.actions.map((a) => (
                  <li key={a.plan.plan_id} className="action-row">
                    <button type="button" className="linkish inline" title="Open the finding this fixes, with its risk assessment" onClick={() => openFinding(a.plan.finding_id)}>
                      {planSummary(a.plan, undefined, null).change}
                    </button>
                    <button type="button" className={`pill pill-btn ${a.approval?.decision === "approve" ? "ok" : ""}`} title="Open on the Approval page" onClick={() => setView("gate")}>
                      {a.approval ? DEC_WORD[a.approval.decision] ?? a.approval.decision : "No decision"}
                    </button>
                    {a.validations.map((v) => (
                      <button key={v.attempt_id} type="button" className={`pill pill-btn ${v.verdict === "verified" ? "ok" : "bad"}`} title="Open on the Validation page" onClick={() => setView("validation")}>
                        {v.verdict === "verified" ? "Validated" : `Failed: ${verdictFail(v.verdict)}`}
                      </button>
                    ))}
                  </li>
                ))}
              </ul>
            </Section>
            <Section title={`What is left (${rep.remaining_risk.length})`}>
              <table className="optable">
                <thead>
                  <tr><th>Finding</th><th>State</th><th className="r">Score</th></tr>
                </thead>
                <tbody>
                  {rep.remaining_risk.slice(0, 40).map((r) => {
                    const f = findingsById.get(r.finding_id);
                    return (
                      <tr key={r.finding_id}>
                        <td>
                          <button type="button" className="linkish" onClick={() => openFinding(r.finding_id)}>
                            {f ? (<><SevPill risk={bandOf(f, riskById)} /> {plainTitle(f, bandOf(f, riskById))}</>) : r.finding_id}
                          </button>
                          {f?.component_purl && <span className="faint mono"> {purlLabel(f.component_purl)}</span>}
                        </td>
                        <td><span className={`pill ${r.status === "verified" ? "ok" : r.status === "escalated" ? "bad" : ""}`}>{STATUS_WORD[r.status] ?? r.status}</span></td>
                        <td className="r num">{r.score.toFixed(1)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {rep.remaining_risk.length > 40 && <p className="faint">Showing the first 40. The JSON report has them all.</p>}
            </Section>
          </>
        )}
      </div>
    </div>
  );
}
