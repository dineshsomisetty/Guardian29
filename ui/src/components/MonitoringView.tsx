import { Activity, Clock, Layers, ShieldAlert } from "lucide-react";
import type { Finding, RunSummary } from "../api/types";

interface MonitoringViewProps {
  source: "demo" | "live";
  historyLoading: boolean;
  historyError: string;
  previousRunId: string;
  newFindings: Finding[];
  runHistory: RunSummary[];
  onOpenFinding?: (findingId: string) => void;
}

export default function MonitoringView({
  source,
  historyLoading,
  historyError,
  previousRunId,
  newFindings,
  runHistory,
  onOpenFinding,
}: MonitoringViewProps) {
  const repositorySummaries = new Map<string, RunSummary>();
  for (const run of runHistory) {
    if (!repositorySummaries.has(run.target)) {
      repositorySummaries.set(run.target, run);
    }
  }

  return (
    <div className="space-y-4">
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            Continuous Supply Chain Monitoring &amp; Fleet Overview
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Compare new vulnerability introductions against previous baseline runs and inspect fleet repository postures.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded-md bg-slate-950 text-slate-300 border border-slate-800 font-mono">
            {runHistory.length} Historical Runs Monitored
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm backdrop-blur-sm space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" /> Delta: New Findings Since Prior Run
            </h3>
            {previousRunId && (
              <span className="text-[11px] font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800/60">
                vs {previousRunId}
              </span>
            )}
          </div>

          {source !== "live" ? (
            <div className="p-6 text-center text-slate-400 text-xs">
              <p className="font-semibold text-slate-300">Demo Mode Active</p>
              <p className="text-slate-500 mt-1">
                Connect to a live FastAPI instance with saved runs to evaluate temporal supply chain deltas.
              </p>
            </div>
          ) : historyLoading ? (
            <div className="p-6 text-center text-slate-400 text-xs">
              <div className="w-5 h-5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
              <span>Analyzing historical run snapshots...</span>
            </div>
          ) : historyError ? (
            <p className="text-xs text-amber-400 p-3 rounded-lg bg-amber-950/40 border border-amber-900">
              {historyError}
            </p>
          ) : newFindings.length === 0 ? (
            <div className="p-6 text-center text-slate-400 text-xs">
              <p className="font-semibold text-emerald-400">Zero New Vulnerabilities Introduced</p>
              <p className="text-slate-500 mt-1">
                No new findings detected relative to baseline run {previousRunId || "snapshot"}.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {newFindings.map((finding) => (
                <div
                  key={finding.finding_id}
                  className="p-3 rounded-lg bg-red-950/30 border border-red-900/50 flex items-center justify-between text-xs"
                >
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-red-950 text-red-300 border border-red-800">
                      NEW
                    </span>
                    <span className="font-bold text-white">{finding.title}</span>
                  </div>
                  {onOpenFinding && (
                    <button
                      onClick={() => onOpenFinding(finding.finding_id)}
                      className="text-cyan-400 hover:text-cyan-300 text-[11px] font-medium"
                    >
                      Inspect
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}

          <p className="text-[10px] text-slate-500 pt-2 border-t border-slate-800">
            * Compares persistent run artifact summaries and SBOM differentials.
          </p>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-sm backdrop-blur-sm space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" /> Fleet Target Postures
            </h3>
            <span className="text-xs text-slate-400">{repositorySummaries.size} Targets Tracked</span>
          </div>

          {repositorySummaries.size === 0 ? (
            <div className="p-6 text-center text-slate-400 text-xs">
              <p className="font-semibold text-slate-300">No Historical Target Repositories</p>
              <p className="text-slate-500 mt-1">
                Trigger runs against different repositories in <code className="text-cyan-400">targets/</code> to track your fleet posture.
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {Array.from(repositorySummaries.values()).map((run) => (
                <div
                  key={run.target}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                >
                  <div>
                    <h4 className="font-bold text-white font-mono">{run.target}</h4>
                    <div className="flex items-center gap-2 text-[11px] text-slate-400 mt-0.5">
                      <Clock className="w-3 h-3 text-slate-500" />
                      <span>{run.started_at}</span>
                      <span>·</span>
                      <code className="text-cyan-400">{run.run_id}</code>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800/60 font-mono">
                      {run.findings.by_risk.critical} Crit
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-orange-950 text-orange-400 border border-orange-800/60 font-mono">
                      {run.findings.by_risk.high} High
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-300 bg-slate-800 border border-slate-700">
                      {run.findings.total} Total
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
