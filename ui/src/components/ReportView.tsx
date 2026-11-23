import { Download } from "lucide-react";
import { useEffect, useState } from "react";
import { firstAvailable, loadReport, reportCandidates } from "../api/client";
import type { ReportJson } from "../api/types";
import { findingHeadline, purlLabel } from "../lib/format";
import { useStore } from "../store";
import { Section, SevPill } from "./ui";

export default function ReportView() {
  const { src, status, findingsById, openFinding, data } = useStore();
  const [rep, setRep] = useState<ReportJson | null | "loading">("loading");
  const [urls, setUrls] = useState<{ json: string | null; html: string | null } | null>(null);
  useEffect(() => {
    let dead = false;
    setRep("loading");
    (async () => {
      const [json, html] = await Promise.all([
        firstAvailable(reportCandidates(src, "json")),
        firstAvailable(reportCandidates(src, "html")),
      ]);
      if (dead) return;
      setUrls({ json, html });
      setRep(json ? await loadReport(src) : null);
    })();
    return () => {
      dead = true;
    };
  }, [src, status]);

  return (
    <div className="report">
      <header className="report-head">
        <h2>Report</h2>
        <span className="tm-spacer" />
        {(["json", "html"] as const).map((k) => {
          const u = urls?.[k];
          return u ? (
            <a key={k} className="btn" href={u} target="_blank" rel="noreferrer" download={`report.${k}`}>
              <Download size={14} aria-hidden /> report.{k}
            </a>
          ) : (
            <button key={k} type="button" className="btn" disabled>
              <Download size={14} aria-hidden /> report.{k}
            </button>
          );
        })}
      </header>
      {rep === "loading" && <p className="muted pad">Looking for the report</p>}
      {rep === null && (
        <div className="empty">
          <strong>No report yet</strong>
          <span>
            The reporter writes report.json and report.html when the run is done. This run is {status.replace("_", " ")}
            {data.summary.pending_plan ? " and waiting at the approval gate" : ""}.
          </span>
        </div>
      )}
      {rep && rep !== "loading" && (
        <div className="report-body">
          <Section title="Outcome">
            <dl className="facts">
              <div><dt>Target</dt><dd>{rep.target}</dd></div>
              <div><dt>Generated</dt><dd className="mono">{rep.generated_at}</dd></div>
              <div><dt>Final confidence</dt><dd>{rep.final_confidence}</dd></div>
              <div><dt>Components</dt><dd className="mono">{rep.inventory.components} ({rep.inventory.direct} direct, {rep.inventory.transitive} transitive)</dd></div>
              <div><dt>Audit</dt><dd className="mono">{rep.audit.events} events, {rep.audit.llm_calls} LLM calls, {rep.audit.tool_calls} tool calls</dd></div>
              <div><dt>Guardrail events</dt><dd className="mono">{rep.guardrail_events.length}</dd></div>
            </dl>
          </Section>
          <Section title={`Remaining risk (${rep.remaining_risk.length})`}>
            <table className="optable">
              <thead>
                <tr><th>Finding</th><th>Status</th><th className="r">Score</th></tr>
              </thead>
              <tbody>
                {rep.remaining_risk.map((r) => {
                  const f = findingsById.get(r.finding_id);
                  return (
                    <tr key={r.finding_id}>
                      <td>
                        <button type="button" className="linkish" onClick={() => openFinding(r.finding_id)}>
                          {f ? <><span className="mono">{findingHeadline(f)}</span> <span className="muted">{f.component_purl ? purlLabel(f.component_purl) : ""}</span></> : r.finding_id}
                        </button>
                      </td>
                      <td><span className={`pill ${r.status === "verified" ? "ok" : r.status === "escalated" ? "bad" : ""}`}>{r.status}</span></td>
                      <td className="r num">{r.score.toFixed(1)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </Section>
          <Section title={`Actions (${rep.actions.length})`}>
            <ul className="plain">
              {rep.actions.map((a) => (
                <li key={a.plan.plan_id}>
                  <span className="mono">{a.plan.action}</span>
                  {a.plan.target_version ? <span className="mono"> {a.plan.target_version}</span> : null}{" "}
                  <span className={`pill ${a.approval?.decision === "approve" ? "ok" : ""}`}>{a.approval?.decision ?? "no decision"}</span>{" "}
                  {a.validations.map((v) => (
                    <span key={v.attempt_id} className={`pill ${v.verdict === "verified" ? "ok" : "bad"}`}>
                      {v.verdict.replace(/_/g, " ")}
                    </span>
                  ))}
                </li>
              ))}
            </ul>
          </Section>
          <Section title="Ranking">
            <ol className="rank">
              {rep.ranking.slice(0, 15).map((id) => {
                const f = findingsById.get(id);
                return (
                  <li key={id}>
                    <button type="button" className="linkish" onClick={() => openFinding(id)}>
                      {f && <SevPill risk={f.initial_risk} />} <span className="mono">{f ? findingHeadline(f) : id}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </Section>
        </div>
      )}
    </div>
  );
}
