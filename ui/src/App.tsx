import { lazy, Suspense, useEffect, useState } from "react";
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  Layers,
  Radio,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  fetchEvidence,
  fetchLatestRun,
  fetchRunFindings,
  fetchRunHistory,
  fetchRun,
  getEventsUrl,
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

import Header from "./components/Header";
import MetricCards from "./components/MetricCards";
import NodeDetailPanel from "./components/NodeDetailPanel";
import FindingsView from "./components/FindingsView";
import TraceView from "./components/TraceView";
import ApprovalView from "./components/ApprovalView";
import ValidationView from "./components/ValidationView";
import MonitoringView from "./components/MonitoringView";
import EvidenceDrawer from "./components/EvidenceDrawer";

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

type TabType = "graph" | "findings" | "trace" | "approval" | "validation" | "monitoring";

export default function App() {
  const [data, setData] = useState<RunData>(demoData);
  const [events, setEvents] = useState<AgentEvent[]>(traceMock);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>("graph");
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
      const evidence =
        source === "live"
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
      setDecisionMessage("Demo mode: no decision was sent or recorded to backend API.");
      return;
    }
    if (decision !== "approve" && !decisionComment.trim()) {
      setError("A comment is required to reject a plan or accept its risk.");
      return;
    }

    setLoading(true);
    try {
      const result = await submitDecision(
        data.summary.run_id,
        plan,
        decision,
        decisionComment.trim(),
      );
      setDecisionMessage(
        result.detail ??
          (result.gate_resumed
            ? "Decision recorded and the human gate resumed."
            : "Decision recorded, but the human gate has not resumed."),
      );
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
      setHistoryError("Load a live run to compare saved runs and target repositories.");
      return;
    }

    let cancelled = false;
    async function loadHistory() {
      setHistoryLoading(true);
      setHistoryError("");
      try {
        const history = await fetchRunHistory();
        const currentIndex = history.findIndex((run) => run.run_id === data.summary.run_id);
        const priorRuns =
          currentIndex >= 0
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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      <Header
        summary={data.summary}
        source={source}
        loading={loading}
        repo={repo}
        onRepoChange={setRepo}
        onCreateRun={createRun}
        onLoadLatest={loadLatest}
        onUseDemo={() => {
          setData(demoData);
          setEvents(traceMock);
          setSelected(null);
          setSelectedEvidence(null);
          setDecisionComment("");
          setDecisionMessage("");
          setSource("demo");
          setError("");
        }}
        reportJsonAvailable={data.report.json_available}
      />

      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 py-5 flex flex-col gap-4">
        {error && (
          <div
            role="alert"
            className="flex items-center gap-3 p-3.5 rounded-xl bg-red-950/80 border border-red-800 text-red-200 text-xs shadow-lg"
          >
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span className="flex-1">{error}</span>
            <button
              onClick={() => setError("")}
              className="text-red-400 hover:text-red-200 font-bold px-1.5"
            >
              ×
            </button>
          </div>
        )}

        <MetricCards summary={data.summary} />

        <nav className="flex items-center gap-1.5 p-1 bg-slate-900/90 rounded-xl border border-slate-800 overflow-x-auto">
          <button
            onClick={() => setActiveTab("graph")}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
              activeTab === "graph"
                ? "bg-cyan-600 text-white shadow-md shadow-cyan-600/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Dependency Graph</span>
          </button>

          <button
            onClick={() => setActiveTab("findings")}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
              activeTab === "findings"
                ? "bg-cyan-600 text-white shadow-md shadow-cyan-600/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Findings &amp; Changes</span>
            <span
              className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                activeTab === "findings" ? "bg-cyan-900 text-white" : "bg-slate-800 text-slate-300"
              }`}
            >
              {data.findings.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab("trace")}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
              activeTab === "trace"
                ? "bg-cyan-600 text-white shadow-md shadow-cyan-600/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Agent Trace</span>
            <span
              className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold ${
                activeTab === "trace" ? "bg-cyan-900 text-white" : "bg-slate-800 text-slate-300"
              }`}
            >
              {events.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab("approval")}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
              activeTab === "approval"
                ? "bg-cyan-600 text-white shadow-md shadow-cyan-600/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Approval Gate</span>
            {data.plans.length > 0 && (
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-amber-500 text-slate-950">
                {data.plans.length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab("validation")}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
              activeTab === "validation"
                ? "bg-cyan-600 text-white shadow-md shadow-cyan-600/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>Validation &amp; Re-Scan</span>
          </button>

          <button
            onClick={() => setActiveTab("monitoring")}
            className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
              activeTab === "monitoring"
                ? "bg-cyan-600 text-white shadow-md shadow-cyan-600/30"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Continuous Monitoring</span>
          </button>
        </nav>

        <div className="flex-1 min-h-[580px]">
          {activeTab === "graph" && (
            <div className="h-[650px] rounded-xl overflow-hidden border border-slate-800 bg-slate-950 flex relative shadow-xl">
              <div className="flex-1 h-full">
                <Suspense
                  fallback={
                    <div className="flex items-center justify-center h-full text-slate-500 text-xs">
                      Loading interactive graph engine...
                    </div>
                  }
                >
                  <GraphView
                    graph={data.graph}
                    selectedNodeId={selected?.id ?? null}
                    onSelect={setSelected}
                  />
                </Suspense>
              </div>

              {selected && (
                <NodeDetailPanel
                  node={selected}
                  graph={data.graph}
                  onSelectNode={setSelected}
                  onOpenFinding={(fid) => {
                    const found = data.findings.find((f) => f.finding_id === fid);
                    if (found && found.evidence_ids.length > 0) {
                      openEvidence(found.evidence_ids[0]);
                    }
                  }}
                />
              )}
            </div>
          )}

          {activeTab === "findings" && (
            <FindingsView
              findings={data.findings}
              changes={data.changes}
              onOpenEvidence={openEvidence}
            />
          )}

          {activeTab === "trace" && (
            <TraceView
              events={events}
              source={source}
              onOpenEvidence={openEvidence}
            />
          )}

          {activeTab === "approval" && (
            <ApprovalView
              plans={data.plans}
              loading={loading}
              decisionComment={decisionComment}
              onCommentChange={setDecisionComment}
              onMakeDecision={makeDecision}
              decisionMessage={decisionMessage}
              onOpenEvidence={openEvidence}
            />
          )}

          {activeTab === "validation" && (
            <ValidationView
              validation={data.validation}
              onOpenEvidence={openEvidence}
            />
          )}

          {activeTab === "monitoring" && (
            <MonitoringView
              source={source}
              historyLoading={historyLoading}
              historyError={historyError}
              previousRunId={previousRunId}
              newFindings={newFindings}
              runHistory={runHistory}
              onOpenFinding={(fid) => {
                const found = data.findings.find((f) => f.finding_id === fid);
                if (found && found.evidence_ids.length > 0) {
                  openEvidence(found.evidence_ids[0]);
                }
              }}
            />
          )}
        </div>
      </main>

      {selectedEvidence && (
        <EvidenceDrawer
          evidence={selectedEvidence}
          onClose={() => setSelectedEvidence(null)}
        />
      )}
    </div>
  );
}
