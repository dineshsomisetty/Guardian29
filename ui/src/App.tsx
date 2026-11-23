import { lazy, Suspense, useEffect, useState } from "react";
import {
  fetchEvidence,
  fetchLatestRun,
  fetchRunFindings,
  fetchRunHistory,
  fetchRun,
  getEventsUrl,
  reportUrl,
  startRun,
  submitDecision,
  type RunData,
} from "./api/client";
import type { AgentEvent, Evidence, Finding, GraphNode, RunSummary } from "./api/types";
import {
  changesMock,
  evidenceMock,
  findingsMock,
  graphMock,
  plansMock,
  summaryMock,
  traceMock,
  validationMock,
} from "./mocks/guardianMocks";

const GraphView = lazy(() => import("./components/GraphView"));
const demoData: RunData = {
  summary: summaryMock,
  graph: graphMock,
  findings: findingsMock,
  changes: changesMock,
  plans: plansMock,
  validation: validationMock,
  report: { json_available: false, html_available: false },
};

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function findingIdentity(finding: Finding): string {
  return [
    finding.category,
    finding.component_purl ?? finding.file_path ?? finding.title,
    finding.vuln_id ?? "",
  ].join("|");
}

export default function App() {
  const [data, setData] = useState<RunData>(demoData);
  const [events, setEvents] = useState<AgentEvent[]>(traceMock);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
  const [activeTab, setActiveTab] = useState<"graph" | "findings" | "trace" | "approval" | "validation" | "monitoring">("graph");
  const [source, setSource] = useState<"demo" | "live">("demo");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [repo, setRepo] = useState("targets/juice-shop");
  const [decisionComment, setDecisionComment] = useState("");
  const [decisionMessage, setDecisionMessage] = useState("");
  const [runHistory, setRunHistory] = useState<RunSummary[]>([]);
  const [newFindings, setNewFindings] = useState<Finding[]>([]);
  const [previousRunId, setPreviousRunId] = useState("");
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");

  function showRun(run: RunData) {
    setData(run);
    setEvents([]);
    setSelected(null);
    setSelectedEvidence(null);
    setDecisionComment("");
    setDecisionMessage("");
    setSource("live");
    setError("");
  }

  async function loadLatest() {
    setLoading(true);
    setError("");
    try {
      await showRun(await fetchLatestRun());
    } catch (loadError) {
      setError(`Live run was not loaded. ${describeError(loadError)} Demo data remains visible.`);
    } finally {
      setLoading(false);
    }
  }

  async function createRun() {
    setLoading(true);
    setError("");
    try {
      const { run_id: createdRunId } = await startRun(repo);
      await showRun(await fetchRun(createdRunId));
    } catch (startError) {
      setError(`Run could not be started or loaded. ${describeError(startError)} Demo data remains visible.`);
    } finally {
      setLoading(false);
    }
  }

  async function openEvidence(evidenceId: string) {
    setError("");
    setSelectedEvidence(null);
    try {
      const evidence = source === "live"
        ? await fetchEvidence(data.summary.run_id, evidenceId)
        : evidenceMock[evidenceId];
      if (!evidence) {
        throw new Error(`Evidence ${evidenceId} is not present in the demo fixtures.`);
      }
      setSelectedEvidence(evidence);
    } catch (evidenceError) {
      setError(`Evidence could not be loaded. ${describeError(evidenceError)}`);
    }
  }

  async function makeDecision(
    plan: RunData["plans"][number],
    decision: "approve" | "reject" | "accept_risk",
  ) {
    setError("");
    setDecisionMessage("");
    if (source !== "live") {
      setDecisionMessage("Demo mode: no decision was sent or recorded.");
      return;
    }
    if (decision !== "approve" && !decisionComment.trim()) {
      setError("A comment is required to reject a plan or accept its risk.");
      return;
    }

    setLoading(true);
    try {
      const result = await submitDecision(data.summary.run_id, plan, decision, decisionComment.trim());
      setDecisionMessage(result.detail ?? (result.gate_resumed
        ? "Decision recorded and the human gate resumed."
        : "Decision recorded, but the human gate has not resumed."));
    } catch (decisionError) {
      setError(`Decision was not accepted. ${describeError(decisionError)}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (source !== "live" || activeTab !== "trace") {
      return;
    }

    const stream = new EventSource(getEventsUrl(data.summary.run_id));
    stream.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as AgentEvent;
        setEvents((current) => [...current, event].slice(-500));
      } catch (parseError) {
        setError(`Received an invalid agent event: ${describeError(parseError)}`);
        stream.close();
      }
    };
    stream.onerror = () => {
      stream.close();
      if (data.summary.status !== "done" && data.summary.status !== "failed") {
        setError("The live agent trace disconnected before the run finished.");
      }
    };
    return () => stream.close();
  }, [activeTab, data.summary.run_id, data.summary.status, source]);

  useEffect(() => {
    if (activeTab !== "monitoring") {
      return;
    }
    if (source !== "live") {
      setRunHistory([]);
      setNewFindings([]);
      setPreviousRunId("");
      setHistoryError("Load a live run to compare saved runs and repositories.");
      return;
    }

    let cancelled = false;
    async function loadHistory() {
      setHistoryLoading(true);
      setHistoryError("");
      try {
        const history = await fetchRunHistory();
        const currentIndex = history.findIndex((run) => run.run_id === data.summary.run_id);
        const priorRuns = currentIndex >= 0
          ? history.slice(currentIndex + 1)
          : history.filter((run) => run.run_id !== data.summary.run_id);
        const previous = priorRuns.find((run) => run.target === data.summary.target);
        let added: Finding[] = [];
        if (previous) {
          const previousFindings = await fetchRunFindings(previous.run_id);
          const priorIds = new Set(previousFindings.map(findingIdentity));
          added = data.findings.filter((finding) => !priorIds.has(findingIdentity(finding)));
        }
        if (!cancelled) {
          setRunHistory(history);
          setNewFindings(added);
          setPreviousRunId(previous?.run_id ?? "");
        }
      } catch (historyLoadError) {
        if (!cancelled) {
          setHistoryError(`Saved-run comparison failed. ${describeError(historyLoadError)}`);
        }
      } finally {
        if (!cancelled) {
          setHistoryLoading(false);
        }
      }
    }
    void loadHistory();
    return () => {
      cancelled = true;
    };
  }, [activeTab, data.findings, data.summary.run_id, data.summary.target, source]);

  const repositorySummaries = new Map<string, RunSummary>();
  for (const run of runHistory) {
    if (!repositorySummaries.has(run.target)) {
      repositorySummaries.set(run.target, run);
    }
  }

  return (
    <main className="dashboard">
      <header>
        <div>
          <p className="eyebrow">GUARDIAN / SUPPLY CHAIN</p>
          <h1>Inventory &amp; risk overview</h1>
        </div>
        <div className="run-status">
          <span className={data.summary.status === "failed" ? "failed" : ""} />
          {data.summary.status.replaceAll("_", " ")}
          <b>{data.summary.run_id}</b>
          <span className={`source-badge ${source}`}>{source === "demo" ? "Demo data" : "Live run"}</span>
        </div>
      </header>

      <section className="run-toolbar" aria-label="Run controls">
        <label>
          Target path
          <input value={repo} onChange={(event) => setRepo(event.target.value)} />
        </label>
        <button disabled={loading} onClick={createRun}>{loading ? "Working..." : "Start run"}</button>
        <button className="secondary-button" disabled={loading} onClick={loadLatest}>Load latest run</button>
        <button className="secondary-button" onClick={() => {
          setData(demoData);
          setEvents(traceMock);
          setSelected(null);
          setSelectedEvidence(null);
          setDecisionComment("");
          setDecisionMessage("");
          setSource("demo");
          setError("");
        }}>Use demo data</button>
        {source === "live" && data.report.json_available && (
          <a className="report-link" href={reportUrl(data.summary.run_id)} target="_blank" rel="noreferrer">
            JSON report
          </a>
        )}
      </section>
      {error && <div className="error-banner" role="alert">{error}</div>}

      <section className="header-strip">
        <div><span>Components</span><strong>{data.summary.sbom.components.toLocaleString()}</strong></div>
        <div><span>Direct</span><strong>{data.summary.sbom.direct}</strong></div>
        <div><span>Transitive</span><strong>{data.summary.sbom.transitive.toLocaleString()}</strong></div>
        <div><span>Findings</span><strong>{data.summary.findings.total}</strong></div>
        <div><span>Critical</span><strong className="critical">{data.summary.findings.by_risk.critical}</strong></div>
      </section>

      <nav className="tabs">
        <button className={activeTab === "graph" ? "active" : ""} onClick={() => setActiveTab("graph")}>Dependency graph</button>
        <button className={activeTab === "findings" ? "active" : ""} onClick={() => setActiveTab("findings")}>Findings</button>
        <button className={activeTab === "trace" ? "active" : ""} onClick={() => setActiveTab("trace")}>Agent trace</button>
        <button className={activeTab === "approval" ? "active" : ""} onClick={() => setActiveTab("approval")}>Approval</button>
        <button className={activeTab === "validation" ? "active" : ""} onClick={() => setActiveTab("validation")}>Validation</button>
        <button className={activeTab === "monitoring" ? "active" : ""} onClick={() => setActiveTab("monitoring")}>Monitoring</button>
      </nav>

      {activeTab === "graph" && (
        <section className="workspace">
          <div className="graph-panel">
            <Suspense fallback={<div className="muted" style={{ padding: 24 }}>Loading dependency graph...</div>}>
              <GraphView graph={data.graph} selectedNodeId={selected?.id ?? null} onSelect={setSelected} />
            </Suspense>
          </div>
          <aside className="side-panel">
            {selected ? (
              <>
                <p className="eyebrow">{selected.kind}</p>
                <h2>{selected.label}</h2>
                {selected.version && <p>Version <b>{selected.version}</b></p>}
                <p>Scope <b>{selected.scope ?? "unknown"}</b></p>
                <p>Project <b>{selected.project ?? "n/a"}</b></p>
                <p>Origin <code>{selected.origin ?? "unknown"}</code></p>
                <p>Integrity <code>{selected.integrity ?? "unknown"}</code></p>
                <p>Findings <b>{selected.finding_ids.join(", ") || "none"}</b></p>
              </>
            ) : <p className="muted">Select a node to inspect provenance and dependency paths.</p>}
          </aside>
        </section>
      )}

      {activeTab === "findings" && (
        <section className="panel-list">
          {data.findings.map((finding) => (
            <article className="finding" key={finding.finding_id}>
              <div>
                {finding.initial_risk && <span className={`badge ${finding.initial_risk}`}>{finding.initial_risk} initial risk</span>}
                <span className="badge status">{finding.status}</span>
                {finding.provenance && (
                  <>
                    <span className={`badge ${finding.provenance.signature_verified === true ? "verified" : "status"}`}>
                      Signature {finding.provenance.signature_verified === true ? "verified" : finding.provenance.signature_verified === false ? "not verified" : "unknown"}
                    </span>
                    <span className={`badge ${finding.provenance.attestation_present === true ? "verified" : "status"}`}>
                      Attestation {finding.provenance.attestation_present === true ? "present" : finding.provenance.attestation_present === false ? "absent" : "unknown"}
                    </span>
                  </>
                )}
              </div>
              <h2>{finding.title}</h2>
              <p>{finding.component_purl ?? finding.file_path ?? finding.category}</p>
              {finding.dependency_paths.map((path, index) => <code key={index}>{path.join(" → ")}</code>)}
              <div className="evidence-links">
                <small>Evidence</small>
                {finding.evidence_ids.map((evidenceId) => (
                  <button key={evidenceId} onClick={() => openEvidence(evidenceId)}>{evidenceId}</button>
                ))}
              </div>
            </article>
          ))}
          <article className="finding">
            <h2>What changed</h2>
            <p><b>Base:</b> {data.changes.base} <b>Head:</b> {data.changes.head}</p>
            <p>Added: {data.changes.added.join(", ") || "none"}</p>
            <p>Removed: {data.changes.removed.join(", ") || "none"}</p>
            {data.changes.changed.map((change) => (
              <p key={change.name}>{change.name}: {change.from} → {change.to}</p>
            ))}
            {data.changes.integrity_changed.map((change) => (
              <p key={change.purl}>Integrity changed: {change.purl}</p>
            ))}
          </article>
        </section>
      )}

      {activeTab === "trace" && (
        <section className="trace">
          {events.length === 0 && <p className="muted">Waiting for agent events...</p>}
          {events.map((event, index) => (
            <article key={`${event.agent}-${event.ts}-${index}`}>
              <div className={`agent-dot ${event.agent}`} />
              <div>
                <span>{event.agent}</span><b>{event.type}</b>
                <p>{event.summary}</p>
                {event.evidence_ids.map((id) => (
                  <button className="trace-evidence" key={id} onClick={() => openEvidence(id)}>{id}</button>
                ))}
              </div>
            </article>
          ))}
        </section>
      )}

      {activeTab === "approval" && (
        <section className="panel-list">
          {data.plans.length === 0 && <p className="empty-state">No remediation plans are available for this run.</p>}
          {data.plans.map((plan) => (
            <article className="finding approval-card" key={plan.plan_id}>
              <p className="eyebrow">Plan attempt {plan.attempt} · {plan.plan_id}</p>
              <h2>{plan.action}{plan.target_version ? ` → ${plan.target_version}` : ""}</h2>
              <p>Finding <b>{plan.finding_id}</b></p>
              <p>Expected risk reduction: {plan.expected_risk_reduction}</p>
              <p>Rollback: {plan.rollback}</p>
              {plan.compatibility_impact && (
                <p>
                  Compatibility: {plan.compatibility_impact.from_version} → {plan.compatibility_impact.to_version}
                  {" · "}{plan.compatibility_impact.semver_delta} change
                  {" · "}{plan.compatibility_impact.level} impact
                </p>
              )}
              <h3>Rationale claims</h3>
              {plan.rationale.map((claim, index) => (
                <p key={`${plan.plan_id}-${index}`}>
                  <span className={`badge ${claim.label}`}>{claim.label}</span>
                  {claim.text}
                  {claim.evidence_ids.map((id) => (
                    <button className="trace-evidence" key={id} onClick={() => openEvidence(id)}>{id}</button>
                  ))}
                </p>
              ))}
              <div className="evidence-links">
                <b>Plan evidence</b>
                {plan.evidence_ids.map((id) => (
                  <button key={id} onClick={() => openEvidence(id)}>{id}</button>
                ))}
              </div>
              <label className="comment-field">
                Decision comment
                <textarea value={decisionComment} onChange={(event) => setDecisionComment(event.target.value)} />
              </label>
              <div className="decision-actions">
                <button disabled={loading} onClick={() => makeDecision(plan, "approve")}>Approve</button>
                <button disabled={loading || !decisionComment.trim()} onClick={() => makeDecision(plan, "reject")}>Reject</button>
                <button disabled={loading || !decisionComment.trim()} onClick={() => makeDecision(plan, "accept_risk")}>Accept risk</button>
              </div>
            </article>
          ))}
          {decisionMessage && <p className="decision-message" role="status">{decisionMessage}</p>}
        </section>
      )}

      {activeTab === "validation" && (
        <section className="validation-list">
          {data.validation.length === 0 && <p className="empty-state">No validation attempts are available for this run.</p>}
          {data.validation.map((attempt) => (
            <article className="validation-card" key={attempt.attempt_id}>
              <div className="validation-heading">
                <div><p className="eyebrow">Attempt {attempt.attempt_id}</p><h2>{attempt.verdict.replaceAll("_", " ")}</h2></div>
                <span className={`badge ${attempt.verdict === "verified" ? "verified" : "high"}`}>{attempt.final_confidence} confidence</span>
              </div>
              <div className="validation-metrics">
                <p>Build <b>{attempt.build_ok ? "passed" : "failed"}</b></p>
                <p>Unit tests <b>{attempt.unit_tests.passed ?? 0} passed / {attempt.unit_tests.failed ?? 0} failed</b></p>
                <p>Integration tests <b>{attempt.integration_tests.passed ?? 0} passed / {attempt.integration_tests.failed ?? 0} failed</b></p>
                <p>Risk <b>{attempt.risk_before} → {attempt.risk_after}</b></p>
                <p>Finding resolved <b>{attempt.target_finding_resolved ? "yes" : "no"}</b></p>
                {attempt.artifact_rescanned && <p>Rescanned artifact <b>{attempt.artifact_rescanned}</b></p>}
              </div>
              {attempt.new_findings.length > 0 && <p>New findings: {attempt.new_findings.join(", ")}</p>}
              <div className="evidence-links">
                {attempt.log_evidence_ids.map((id) => (
                  <button key={id} onClick={() => openEvidence(id)}>Log {id}</button>
                ))}
                {attempt.detector_evidence_ids.map((id) => (
                  <button key={id} onClick={() => openEvidence(id)}>Detector {id}</button>
                ))}
              </div>
            </article>
          ))}
        </section>
      )}

      {activeTab === "monitoring" && (
        <section className="monitoring-layout">
          <article className="finding">
            <p className="eyebrow">Saved-run comparison</p>
            <h2>New findings since previous run</h2>
            {historyLoading && <p className="muted">Loading saved runs...</p>}
            {historyError && <p className="muted">{historyError}</p>}
            {!historyLoading && !historyError && (
              <>
                <p>{previousRunId ? `Compared with ${previousRunId}` : "No earlier run for this target is available."}</p>
                {newFindings.length === 0
                  ? <p>No new findings in the saved-run comparison.</p>
                  : newFindings.map((finding) => (
                    <p className="new-finding" key={finding.finding_id}>
                      <span className={`badge ${finding.initial_risk ?? "status"}`}>{finding.initial_risk ?? "unrated"}</span>
                      {finding.title}
                    </p>
                  ))}
              </>
            )}
            <small>This compares stored results; it does not trigger a fresh intelligence scan.</small>
          </article>
          <article className="finding">
            <p className="eyebrow">Repository overview</p>
            <h2>Latest saved run per target</h2>
            {repositorySummaries.size === 0 && !historyLoading && <p className="muted">No saved runs are available.</p>}
            {Array.from(repositorySummaries.values()).map((run) => (
              <div className="repository-row" key={run.target}>
                <b>{run.target}</b>
                <span>{run.findings.total} findings</span>
                <span>{run.findings.by_risk.critical} critical · {run.findings.by_risk.high} high</span>
                <code>{run.run_id}</code>
              </div>
            ))}
          </article>
        </section>
      )}

      {selectedEvidence && (
        <aside className="evidence-drawer" aria-label="Evidence details">
          <button className="close-button" onClick={() => setSelectedEvidence(null)} aria-label="Close evidence">×</button>
          <p className="eyebrow">{selectedEvidence.kind}</p>
          <h2>{selectedEvidence.evidence_id}</h2>
          <p>Source <b>{selectedEvidence.source_tool}</b></p>
          {selectedEvidence.file_path && <p>File <code>{selectedEvidence.file_path}{selectedEvidence.line ? `:${selectedEvidence.line}` : ""}</code></p>}
          {selectedEvidence.excerpt && <blockquote>{selectedEvidence.excerpt}</blockquote>}
          <h3>Verified facts</h3>
          <pre>{JSON.stringify(selectedEvidence.facts, null, 2)}</pre>
        </aside>
      )}
    </main>
  );
}
