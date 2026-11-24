import { Download, FileText } from "lucide-react";
import { useEffect, useState } from "react";
import { downloadReport, loadReport } from "../api/client";
import type { ReportJson } from "../api/types";
import { bandOf, fmtDate, purlLabel } from "../lib/format";
import { failLine, plainTitle } from "../lib/labels";
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
const STATE_PILL: Record<string, string> = { fixed: "ok", accepted: "info", needs_person: "bad", open: "gate" };

/** The readable sections report.json gained later (all optional: reports written before that lack them). */
interface V2 {
  overview?: {
    target: string | null; commit: string | null; scanned_at: string | null; generated_at: string | null;
    packages: Record<string, number>; verdict: string; confidence: string; confidence_limits: string[];
    counts: { total: number; by_level: Record<string, number>; fixed: number; accepted: number; open: number; needs_person: number; awaiting_decision?: number };
    key_points?: string[];
  } | null;
  fixes?: {
    title: string; plan_id: string; finding_ids: string[]; finding_count: number; top_titles: string[]; level: string;
    primary_finding_id: string | null; checks: string[]; score_before: number | null; score_after: number | null;
    location: string; approved_by: string | null;
  }[];
  decisions?: {
    plan_id: string; finding_id: string | null; what: string; finding_count: number; decision: string; reason_text: string | null;
    comment: string | null; decided_by: string; decided_at: string; result: string; plan_hash?: string | null; plan_hash_ok?: boolean | null;
  }[];
  open_groups?: { package: string; level: string; score: number; count: number; next_step: string; finding_ids: string[] }[];
  attention?: {
    kind: "accepted" | "needs_person"; title: string; level: string; score: number; finding_ids: string[]; finding_count: number;
    top_titles: string[]; reason: string; decided_by: string | null; decided_at: string | null;
  }[];
  score_guide?: { weights: Record<string, number>; factor_names: Record<string, string>; factor_help: Record<string, string>; bands: Record<string, string>; notes: string[] } | null;
  method?: { ran: string[]; ai: string[]; not_checked: string[]; guardrails: string[] } | null;
  ranked?: {
    rank: number; finding_id: string; title: string; package: string; version: string | null; kind: string; level: string; score: number;
    confidence: string; state: string; status: string; summary: string; provenance_points: number; override: string | null;
    recomputed_score: number | null; score_matches: boolean | null; action: string; decision: string; paths: string[][]; path_count: number;
    factors: { key: string; name: string; value: number; tier: string; assumed: boolean; label: string; weight: number; points: number }[];
    claims: { text: string; label: string }[];
  }[];
  validations?: {
    attempt_id: string; plan_id: string; title: string; verdict_text: string; passed: boolean; group_failure?: boolean; build: string; unit_tests: string;
    integration_tests: string; baseline_note: string; resolved: boolean; new_findings: string[]; risk_before: number; risk_after: number;
    confidence: string; combined: boolean;
  }[];
  before_after?: {
    levels_before: Record<string, number>; levels_after: Record<string, number>; top_before: number; top_after: number;
    sbom_components: number[]; sbom_added: number; sbom_removed: number; sbom_changed: number; new_findings: string[]; note: string;
  } | null;
  guardrails_triggered?: { rule: string; agent: string; text: string }[];
  audit_trail?: { ts: string; agent: string; kind: string; text: string }[];
  appendix?: { finding_id: string; level: string; score: number; title: string; package: string; state: string; status: string; advisory_severity: string | null }[];
}

const LEVELS = ["critical", "high", "medium", "low"] as const;
const SECTIONS: [string, string][] = [
  ["summary", "Summary"], ["inventory", "Inventory"], ["scores", "Risk ranking"], ["findings", "Findings and evidence"],
  ["fixes", "Fixes verified"], ["decisions", "Decisions"], ["validation", "Build, tests, before/after"], ["open", "Still open"],
  ["attention", "Accepted risk, needs a person"], ["method", "Method, guardrails, audit"], ["appendix", "Appendix"],
];
const RANK_SHOWN = 30;
const CARDS_SHOWN = 10;
const APPENDIX_SHOWN = 40;

const Lvl = ({ level }: { level: string }) => (
  <span className={`pill ${(LEVELS as readonly string[]).includes(level) ? `sev-${level}` : ""}`}>{level.charAt(0).toUpperCase() + level.slice(1)}</span>
);
const when = (ts: string | null | undefined) => (ts ? fmtDate(ts) : "-");
const jump = (id: string) => document.getElementById(`rep-${id}`)?.scrollIntoView({ behavior: "smooth", block: "start" });

export default function ReportView() {
  const { src, status, openFinding, data, setView } = useStore();
  const links = useReportLinks(src, status);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [rep, setRep] = useState<ReportJson | null | "loading">("loading");
  const [allRows, setAllRows] = useState(false);
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
  const v2 = (rep && rep !== "loading" ? (rep as unknown as V2) : {}) as V2;
  const ov = v2.overview ?? null;

  return (
    <div className="page">
      <div className="page-in">
        <header className="page-head row-between">
          <div>
            <h1>Report</h1>
            <p className="muted">{status === "done" ? "The final write-up" : "The available progress report"} of this scan: what was found, what was done about it, and what is left.</p>
          </div>
          <div className="row">
            {(["html", "json"] as const).map((k) => {
              const u = url(k);
              const label = k === "html" ? "Download HTML" : "Download JSON";
              return u ? (
                <a key={k} className="btn" href={u} download={`report.${k}`} onClick={(event) => {
                  event.preventDefault();
                  setDownloadError(null);
                  void downloadReport(u, `report.${k}`).catch((error: Error) => setDownloadError(error.message));
                }}>
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
        {downloadError && <p role="alert">{downloadError}</p>}

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
              ? "This scan is paused until you decide on the suggested fixes. Approve, reject or accept the risk on the Remediation page, and the report follows."
              : status === "failed"
                ? "This scan stopped with an error, so no report was written. The activity log shows where it stopped."
                : "This scan is still running. The report appears here when it finishes."}
          </EmptyState>
        )}

        {rep && rep !== "loading" && ov && (
          <>
            {status !== "done" && (
              <div className="callout gate" role="note"><div>
                <strong>Interim report.</strong>{" "}
                {status === "running"
                  ? "Guardian is still working (for example validating a fix), so this shows the state before that step. It is rewritten when the step finishes."
                  : "Some suggested fixes still wait for a decision. This report covers every fix validated so far and is rewritten after each validation and at the end."}
                {ov.scanned_at && <span className="faint"> Written {when(ov.scanned_at)}.</span>}
              </div></div>
            )}
            <nav className="rep-toc" aria-label="Report sections">
              {SECTIONS.map(([id, label], i) => (
                <button key={id} type="button" className="linkish" onClick={() => jump(id)}>{i + 1} {label}</button>
              ))}
            </nav>

            <Section id="rep-summary" title="1  Summary">
              <dl className="facts wide">
                <div><dt>Scanned</dt><dd>{ov.target ?? rep.target}{(ov.commit ?? rep.commit) && <span className="faint mono"> commit {(ov.commit ?? rep.commit ?? "").slice(0, 12)}</span>}</dd></div>
                <div><dt>Scan finished</dt><dd>{when(ov.scanned_at)}</dd></div>
                <div><dt>Packages</dt><dd>{(ov.packages.components ?? 0).toLocaleString()} ({(ov.packages.direct ?? 0).toLocaleString()} direct, {(ov.packages.transitive ?? 0).toLocaleString()} indirect)</dd></div>
              </dl>
              <p className="rep-verdict">{ov.verdict}</p>
              {(ov.key_points ?? []).length > 0 && <ul className="rep-list">{ov.key_points!.map((k, i) => <li key={i}>{k}</li>)}</ul>}
              <div className="rep-stats" role="list" aria-label="Findings by risk level">
                {LEVELS.map((lv) => (
                  <div key={lv} className={`rep-stat sev-${lv}`} role="listitem"><b>{ov.counts.by_level[lv] ?? 0}</b><span>{lv.charAt(0).toUpperCase() + lv.slice(1)} risk</span></div>
                ))}
              </div>
              <div className="rep-stats" role="list" aria-label="What became of the findings">
                <div className="rep-stat ok" role="listitem"><b>{ov.counts.fixed}</b><span>fix verified</span></div>
                <div className="rep-stat info" role="listitem"><b>{ov.counts.accepted}</b><span>risk accepted</span></div>
                <div className="rep-stat gate" role="listitem"><b>{ov.counts.open}</b><span>still open{ov.counts.awaiting_decision ? ` (${ov.counts.awaiting_decision} fixes await a decision)` : ""}</span></div>
                <div className="rep-stat bad" role="listitem"><b>{ov.counts.needs_person}</b><span>need a person</span></div>
              </div>
              <p><strong>Overall confidence: {ov.confidence}.</strong> <span className="muted">What limits it:</span></p>
              <ul className="rep-list">{ov.confidence_limits.map((l, i) => <li key={i}>{l}</li>)}</ul>
            </Section>

            <Section id="rep-inventory" title="2  Inventory and dependency paths">
              <p>
                Guardian listed every package the project uses: <strong>{(ov.packages.components ?? 0).toLocaleString()}</strong> in total,{" "}
                <strong>{(ov.packages.direct ?? 0).toLocaleString()}</strong> chosen directly and <strong>{(ov.packages.transitive ?? 0).toLocaleString()}</strong> pulled in
                indirectly. An indirect package can only be fixed by changing the package that brings it in, so each finding shows its chain.
              </p>
              {(() => {
                const seen = new Set<string>();
                const rows = (v2.ranked ?? []).filter((x) => x.paths.length > 0).filter((x) => {
                  const k = `${x.package}@${x.version}>${x.paths[0].join(">")}`;
                  return seen.has(k) ? false : (seen.add(k), true);
                });
                return rows.length === 0 ? <p className="muted">No finding has a dependency chain.</p> : (
                  <table className="optable">
                    <thead><tr><th>Package</th><th>How it is pulled in (first chain)</th><th className="r">Chains</th></tr></thead>
                    <tbody>
                      {rows.slice(0, 12).map((x) => (
                        <tr key={x.finding_id}><td>{x.package}{x.version ? `@${x.version}` : ""}</td><td>{x.paths[0].join(" > ")}</td><td className="r num">{x.path_count}</td></tr>
                      ))}
                    </tbody>
                  </table>
                );
              })()}
            </Section>

            <Section id="rep-scores" title="3  Risk ranking and how scores work">
              {v2.score_guide && (
                <>
                  {v2.score_guide.notes.map((n, i) => <p key={i} className="muted">{n}</p>)}
                  <p>
                    <strong>Formula:</strong> score = 100 x ({Object.entries(v2.score_guide.weights).map(([k, w]) => `${w} x ${v2.score_guide!.factor_names[k] ?? k}`).join(" + ")}) + provenance points.
                    These weights are Guardian&apos;s own choice, not an industry standard.
                  </p>
                  <table className="optable">
                    <thead><tr><th>Factor</th><th className="r">Weight</th><th>What it measures</th></tr></thead>
                    <tbody>
                      {Object.entries(v2.score_guide.weights).map(([k, w]) => (
                        <tr key={k}><td>{v2.score_guide!.factor_names[k] ?? k} ({k})</td><td className="r num">{Math.round(w * 100)}%</td><td>{v2.score_guide!.factor_help[k] ?? ""}</td></tr>
                      ))}
                    </tbody>
                  </table>
                  <table className="optable">
                    <thead><tr><th>Level</th><th>Score range</th></tr></thead>
                    <tbody>{LEVELS.map((lv) => <tr key={lv}><td><Lvl level={lv} /></td><td>{v2.score_guide!.bands[lv]}</td></tr>)}</tbody>
                  </table>
                </>
              )}
              {(v2.ranked ?? []).length > 0 && (
                <>
                  <h4>Ranking, highest risk first ({Math.min(v2.ranked!.length, RANK_SHOWN)} of {v2.ranked!.length})</h4>
                  <table className="optable">
                    <thead><tr><th className="r">#</th><th>Level</th><th className="r">Score</th><th>Finding</th>
                      {["S", "E", "R", "P", "X"].map((k) => <th key={k} className="r" title={v2.score_guide?.factor_names[k]}>{k}</th>)}
                      <th className="r" title="Provenance modifier, points">Prov.</th><th>Confidence</th><th>Status</th></tr></thead>
                    <tbody>
                      {v2.ranked!.slice(0, RANK_SHOWN).map((x) => (
                        <tr key={x.finding_id}>
                          <td className="r num">{x.rank}</td><td><Lvl level={x.level} /></td><td className="r num">{x.score.toFixed(1)}</td>
                          <td><button type="button" className="linkish" onClick={() => openFinding(x.finding_id)}>{x.title}</button></td>
                          {x.factors.map((f) => <td key={f.key} className="r num" title={`${f.tier}${f.assumed ? " (assumed)" : ""}`}>{f.value}{f.assumed ? "*" : ""}</td>)}
                          {x.factors.length === 0 && <td colSpan={5} className="faint">not scored</td>}
                          <td className="r num">{x.provenance_points || "-"}</td><td>{x.confidence}</td><td>{x.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <p className="faint">Each value is between 0 and 1; a star marks a value assumed because no evidence was available. Points = 100 x weight x value. Every finding&apos;s full factor table is in section 4 and the downloaded reports.</p>
                </>
              )}
            </Section>

            <Section id="rep-findings" title="4  Findings, evidence and recommended action"
              lead={`The ${Math.min((v2.ranked ?? []).length, CARDS_SHOWN)} highest-risk findings. VERIFIED means a statement matches a fact in the cited evidence; INFERRED is the AI reading it. Unsupported statements were removed.`}>
              {(v2.ranked ?? []).slice(0, CARDS_SHOWN).map((x) => (
                <article key={x.finding_id} className="rep-fix">
                  <h4><button type="button" className="linkish" onClick={() => openFinding(x.finding_id)}>{x.rank}. {x.title}</button> <Lvl level={x.level} /></h4>
                  <p className="faint">{x.kind} &middot; {x.package}{x.version ? `@${x.version}` : ""} &middot; score {x.score.toFixed(1)} &middot; confidence {x.confidence} &middot; {x.status}</p>
                  {x.summary && <p>{x.summary}</p>}
                  <dl className="facts wide">
                    <div><dt>Recommended action</dt><dd>{x.action}</dd></div>
                    <div><dt>Decision</dt><dd>{x.decision}</dd></div>
                    {x.paths.length > 0 && <div><dt>Pulled in by</dt><dd>{x.paths.map((p, i) => <div key={i}>{p.join(" > ")}</div>)}</dd></div>}
                  </dl>
                  {x.claims.length > 0 && (
                    <ul className="rep-list">
                      {x.claims.map((c, i) => <li key={i}><span className={`pill ${c.label === "verified" ? "ok" : "gate"}`}>{c.label}</span> {c.text}</li>)}
                    </ul>
                  )}
                  {x.factors.length > 0 && (
                    <details>
                      <summary>Score table (recompute it yourself)</summary>
                      <table className="optable">
                        <thead><tr><th>Factor</th><th className="r">Value</th><th>Basis</th><th>Label</th><th className="r">Weight</th><th className="r">Points</th></tr></thead>
                        <tbody>
                          {x.factors.map((f) => (
                            <tr key={f.key}><td>{f.name} ({f.key})</td><td className="r num">{f.value}</td><td>{f.tier.replace(/_/g, " ")}{f.assumed ? " (assumed)" : ""}</td><td>{f.label}</td><td className="r num">{Math.round(f.weight * 100)}%</td><td className="r num">{f.points}</td></tr>
                          ))}
                          <tr><td colSpan={5}>Provenance modifier</td><td className="r num">{x.provenance_points}</td></tr>
                          <tr><td colSpan={5}><strong>Score{x.override ? ` (level raised by rule: ${x.override.replace(/_/g, " ")})` : ""}</strong></td><td className="r num"><strong>{x.recomputed_score}</strong></td></tr>
                        </tbody>
                      </table>
                    </details>
                  )}
                </article>
              ))}
            </Section>

            <Section id="rep-fixes" title={`5  Fixes applied and verified (${v2.fixes?.length ?? 0})`}
              lead="A fix counts as verified only after it was applied to a copy, built, tested and re-scanned. Nothing was pushed.">
              {(v2.fixes ?? []).length === 0 && <p className="muted">No fix was verified in this run.</p>}
              {(v2.fixes ?? []).map((x) => (
                <article key={x.plan_id} className="rep-fix">
                  <h4>
                    {x.primary_finding_id ? (
                      <button type="button" className="linkish" title="Open the main finding this fixes" onClick={() => openFinding(x.primary_finding_id!)}>{x.title}</button>
                    ) : x.title}{" "}
                    <Lvl level={x.level} />
                  </h4>
                  <p>Resolves <strong>{x.finding_count} {x.finding_count === 1 ? "finding" : "findings"}</strong>{x.top_titles.length > 0 && ", for example:"}</p>
                  <ul className="rep-list">
                    {x.top_titles.map((t, i) => <li key={i}>{t}</li>)}
                    {x.finding_count > x.top_titles.length && <li className="faint">and {x.finding_count - x.top_titles.length} more</li>}
                  </ul>
                  <p className="faint">How it was checked</p>
                  <ul className="rep-list">{x.checks.map((c, i) => <li key={i}>{c}</li>)}</ul>
                  {x.score_before !== null && <p className="rep-score">Risk score of the worst finding it covers: <span className="num">{x.score_before} &rarr; {x.score_after}</span></p>}
                  <p className="faint">Where: {x.location}</p>
                  <button type="button" className="pill pill-btn ok" title="Open on the Validation page" onClick={() => setView("validation")}>See the validation</button>
                </article>
              ))}
            </Section>

            <Section id="rep-decisions" title={`6  Decisions made by people (${v2.decisions?.length ?? 0})`}>
              {(v2.decisions ?? []).length === 0 ? <p className="muted">No person has decided on a fix yet.</p> : (
                <table className="optable">
                  <thead><tr><th>When</th><th>Who</th><th>Decision</th><th>About</th><th className="r">Findings</th><th>Reason or comment</th><th>What followed</th><th>Plan hash</th></tr></thead>
                  <tbody>
                    {(v2.decisions ?? []).map((d, i) => (
                      <tr key={`${d.plan_id}-${i}`}>
                        <td>{when(d.decided_at)}</td>
                        <td>{d.decided_by}</td>
                        <td><button type="button" className={`pill pill-btn ${d.decision === "approve" ? "ok" : d.decision === "reject" ? "bad" : "info"}`} title="Open on the Remediation page" onClick={() => setView("gate")}>{DEC_WORD[d.decision] ?? d.decision}</button></td>
                        <td>{d.finding_id ? <button type="button" className="linkish" onClick={() => openFinding(d.finding_id!)}>{d.what}</button> : d.what}</td>
                        <td className="r num">{d.finding_count}</td>
                        <td>{d.reason_text && <em>{d.reason_text}{d.comment ? ": " : ""}</em>}{d.comment ?? (d.reason_text ? "" : <span className="faint">none given</span>)}</td>
                        <td>{d.result}</td>
                        <td><code>{(d.plan_hash ?? "-").slice(0, 12)}</code>{d.plan_hash_ok === true && <div className="faint">matches the plan</div>}{d.plan_hash_ok === false && <div className="faint">plan changed since</div>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Section>

            <Section id="rep-validation" title="7  Build and test results, before and after">
              {(v2.validations ?? []).length === 0 ? <p className="muted">No fix was built or tested in this run.</p> : (
                <table className="optable">
                  <thead><tr><th>Fix</th><th>Result</th><th>Build</th><th>Unit tests</th><th>Integration tests</th><th>Problem gone?</th><th>New findings</th><th className="r">Risk before &rarr; after</th></tr></thead>
                  <tbody>
                    {(v2.validations ?? []).map((v, i) => (
                      <tr key={`${v.attempt_id}-${v.plan_id}-${i}`}>
                        <td>{v.title}{v.combined && <div className="faint">tested together with other fixes</div>}</td>
                        <td><span className={`pill ${v.passed ? "ok" : v.group_failure ? "" : "bad"}`}>{v.verdict_text}</span></td>
                        <td>{v.build}</td><td>{v.unit_tests}</td><td>{v.integration_tests}</td><td>{v.resolved ? "yes" : "no"}</td>
                        <td>{v.new_findings.length ? v.new_findings.slice(0, 3).join("; ") : "none"}</td>
                        <td className="r num">{v.risk_before} &rarr; {v.risk_after}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {v2.before_after && (
                <>
                  <h4>Risk before and after</h4>
                  <table className="optable">
                    <thead><tr><th></th>{LEVELS.map((lv) => <th key={lv} className="r">{lv.charAt(0).toUpperCase() + lv.slice(1)}</th>)}<th className="r">Highest score</th></tr></thead>
                    <tbody>
                      <tr><td>Before any fix</td>{LEVELS.map((lv) => <td key={lv} className="r num">{v2.before_after!.levels_before[lv] ?? 0}</td>)}<td className="r num">{v2.before_after.top_before}</td></tr>
                      <tr><td>After verified fixes</td>{LEVELS.map((lv) => <td key={lv} className="r num">{v2.before_after!.levels_after[lv] ?? 0}</td>)}<td className="r num">{v2.before_after.top_after}</td></tr>
                    </tbody>
                  </table>
                  <p className="faint">{v2.before_after.note}</p>
                  <h4>Inventory (SBOM) before and after</h4>
                  <p>{v2.before_after.sbom_components.length === 2
                    ? `${v2.before_after.sbom_components[0].toLocaleString()} packages before, ${v2.before_after.sbom_components[1].toLocaleString()} after the verified fixes: ${v2.before_after.sbom_added} added, ${v2.before_after.sbom_removed} removed, ${v2.before_after.sbom_changed} changed version.`
                    : "No before/after package comparison was produced, because no fix was verified."}</p>
                  <h4>New findings introduced by fixes</h4>
                  {v2.before_after.new_findings.length === 0
                    ? <p>None: the re-scans of the patched copies showed no problem that was not already there.</p>
                    : <ul className="rep-list">{v2.before_after.new_findings.map((t, i) => <li key={i}>{t}</li>)}</ul>}
                </>
              )}
            </Section>

            <Section id="rep-open" title={`8  What is still open (${ov.counts.open} findings in ${v2.open_groups?.length ?? 0} packages)`}
              lead="Grouped by package, worst score first. The full list is in the appendix.">
              {(v2.open_groups ?? []).length === 0 ? <p className="muted">Nothing is open: every finding was fixed, accepted or handed to a person.</p> : (
                <table className="optable">
                  <thead><tr><th>Worst level</th><th className="r">Score</th><th>Package</th><th className="r">Findings</th><th>Suggested next step</th></tr></thead>
                  <tbody>
                    {(v2.open_groups ?? []).map((g) => (
                      <tr key={g.package}>
                        <td><Lvl level={g.level} /></td>
                        <td className="r num">{g.score.toFixed(1)}</td>
                        <td><button type="button" className="linkish" title="Open the worst finding of this package" onClick={() => openFinding(g.finding_ids[0])}>{g.package}</button></td>
                        <td className="r num">{g.count}</td>
                        <td>{g.next_step}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Section>

            <Section id="rep-attention" title="9  Remaining risk: accepted by a person, or needs a person">
              {(["accepted", "needs_person"] as const).map((kind) => {
                const items = (v2.attention ?? []).filter((a) => a.kind === kind);
                return (
                  <div key={kind} className="rep-block">
                    <h4>{kind === "accepted" ? `Risks accepted by a person (${items.length})` : `Items that need a person (${items.length})`}</h4>
                    {items.length === 0 ? <p className="muted">{kind === "accepted" ? "No risk was accepted." : "Nothing needs a person right now."}</p> : (
                      <table className="optable">
                        <thead>
                          <tr><th>Level</th><th className="r">Score</th><th>{kind === "accepted" ? "Fix that was not applied" : "Item"}</th><th className="r">Findings</th><th>{kind === "accepted" ? "Reason given" : "Why Guardian cannot settle it"}</th>{kind === "accepted" && <th>Accepted by</th>}</tr>
                        </thead>
                        <tbody>
                          {items.map((a, i) => (
                            <tr key={`${a.title}-${i}`}>
                              <td><Lvl level={a.level} /></td>
                              <td className="r num">{a.score.toFixed(1)}</td>
                              <td><button type="button" className="linkish" onClick={() => openFinding(a.finding_ids[0])}>{a.title}</button></td>
                              <td className="r num">{a.finding_count}</td>
                              <td>{a.reason}</td>
                              {kind === "accepted" && <td>{a.decided_by ?? "-"}<br /><span className="faint">{when(a.decided_at)}</span></td>}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                );
              })}
            </Section>

            <Section id="rep-method" title="10  Method, limits, guardrails and audit trail">
              {v2.method && (
                <div className="rep-method">
                  {([["What ran", v2.method.ran], ["How AI was used", v2.method.ai], ["What was not checked", v2.method.not_checked], ["Guardrails that applied", v2.method.guardrails]] as [string, string[]][]).map(([t, xs]) => (
                    <details key={t} open={t === "What was not checked"}>
                      <summary>{t} ({xs.length})</summary>
                      <ul className="rep-list">{xs.map((x, i) => <li key={i}>{x}</li>)}</ul>
                    </details>
                  ))}
                </div>
              )}
              <h4>Guardrail events in this run ({(v2.guardrails_triggered ?? []).length})</h4>
              {(v2.guardrails_triggered ?? []).length === 0 ? <p>No guardrail had to block or remove anything.</p> : (
                <ul className="rep-list">{v2.guardrails_triggered!.slice(0, 40).map((g, i) => <li key={i}><strong>{g.rule}</strong> {g.text}</li>)}</ul>
              )}
              {(v2.audit_trail ?? []).length > 0 && (
                <details>
                  <summary>Audit trail: where a person, a safety rule or the validator was involved ({v2.audit_trail!.length})</summary>
                  <table className="optable">
                    <thead><tr><th>Time (UTC)</th><th>Who</th><th>Kind</th><th>What</th></tr></thead>
                    <tbody>{v2.audit_trail!.map((a, i) => <tr key={i}><td>{a.ts.replace("T", " ")}</td><td>{a.agent.replace(/_/g, " ")}</td><td>{a.kind}</td><td>{a.text}</td></tr>)}</tbody>
                  </table>
                </details>
              )}
              <p className="faint">Work recorded: {rep.audit.events.toLocaleString()} steps, {rep.audit.llm_calls} AI calls, {rep.audit.tool_calls} tool runs, {rep.guardrail_events.length} safety rules triggered.</p>
            </Section>

            <Section id="rep-appendix" title={`11  Appendix: all findings (${v2.appendix?.length ?? 0})`}>
              <table className="optable">
                <thead><tr><th>Level</th><th className="r">Score</th><th>Finding</th><th>Package</th><th>Status</th><th>Advisory says</th></tr></thead>
                <tbody>
                  {(v2.appendix ?? []).slice(0, allRows ? undefined : APPENDIX_SHOWN).map((a) => (
                    <tr key={a.finding_id}>
                      <td><Lvl level={a.level} /></td>
                      <td className="r num">{a.score.toFixed(1)}</td>
                      <td><button type="button" className="linkish" onClick={() => openFinding(a.finding_id)}>{a.title}</button></td>
                      <td>{a.package}</td>
                      <td><span className={`pill ${STATE_PILL[a.state] ?? ""}`}>{a.status}</span></td>
                      <td>{a.advisory_severity ?? "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {(v2.appendix ?? []).length > APPENDIX_SHOWN && (
                <button type="button" className="btn sm" onClick={() => setAllRows(!allRows)}>{allRows ? "Show fewer" : `Show all ${v2.appendix!.length}`}</button>
              )}
              <p className="faint">Internal ids and the full evidence of every finding are in the downloaded HTML and JSON reports.</p>
            </Section>
          </>
        )}

        {rep && rep !== "loading" && !ov && <LegacyBody rep={rep} />}
      </div>
    </div>
  );
}

/** Reports written before the readable sections existed: the three original blocks. */
function LegacyBody({ rep }: { rep: ReportJson }) {
  const { findingsById, openFinding, riskById, setView } = useStore();
  return (
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
              <button type="button" className={`pill pill-btn ${a.approval?.decision === "approve" ? "ok" : ""}`} title="Open on the Remediation page" onClick={() => setView("gate")}>
                {a.approval ? DEC_WORD[a.approval.decision] ?? a.approval.decision : "No decision"}
              </button>
              {a.validations.map((v) => (
                <button key={v.attempt_id} type="button" className={`pill pill-btn ${v.verdict === "verified" ? "ok" : v.group_failure ? "" : "bad"}`} title="Open on the Validation page" onClick={() => setView("validation")}>
                  {v.verdict === "verified" ? "Validated" : failLine(v)}
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
            {[...rep.remaining_risk].sort((a, b) => b.score - a.score).slice(0, 40).map((r) => {
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
  );
}
