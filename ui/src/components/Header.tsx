import { useState } from "react";
import {
  Activity,
  Bot,
  Copy,
  Download,
  GitBranch,
  Play,
  RotateCcw,
  Shield,
} from "lucide-react";
import type { RunSummary } from "../api/types";
import { reportUrl } from "../api/client";

interface HeaderProps {
  summary: RunSummary;
  source: "demo" | "live";
  loading: boolean;
  repo: string;
  onRepoChange: (value: string) => void;
  onCreateRun: () => void;
  onLoadLatest: () => void;
  onUseDemo: () => void;
  reportJsonAvailable: boolean;
}

export default function Header({
  summary,
  source,
  loading,
  repo,
  onRepoChange,
  onCreateRun,
  onLoadLatest,
  onUseDemo,
  reportJsonAvailable,
}: HeaderProps) {
  const [copied, setCopied] = useState(false);

  const copyRunId = () => {
    navigator.clipboard.writeText(summary.run_id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const statusColor = {
    done: "bg-emerald-500 text-emerald-400 border-emerald-500/30",
    failed: "bg-red-500 text-red-400 border-red-500/30",
    discovering: "bg-cyan-500 text-cyan-400 border-cyan-500/30 animate-pulse",
    detecting: "bg-amber-500 text-amber-400 border-amber-500/30 animate-pulse",
    analysing: "bg-purple-500 text-purple-400 border-purple-500/30 animate-pulse",
    planning_loop: "bg-indigo-500 text-indigo-400 border-indigo-500/30 animate-pulse",
    reporting: "bg-blue-500 text-blue-400 border-blue-500/30",
    created: "bg-slate-500 text-slate-400 border-slate-500/30",
  }[summary.status] ?? "bg-slate-500 text-slate-400 border-slate-500/30";

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-30">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-3.5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center gap-3.5 flex-wrap">
            <div className="flex items-center gap-2.5">
              <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 p-0.5 shadow-lg shadow-cyan-500/20 flex items-center justify-center">
                <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
                  <Shield className="w-5 h-5 text-cyan-400" />
                </div>
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-1.5">
                    GUARDIAN<span className="text-cyan-400">29</span>
                  </h1>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase bg-cyan-950 text-cyan-400 border border-cyan-800/50">
                    DEV-3
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 tracking-wide">
                  Autonomous Software Supply Chain Security Defense
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 pl-3 border-l border-slate-800 text-xs">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-300">
                <span className={`w-2 h-2 rounded-full ${statusColor}`} />
                <span className="capitalize font-medium">{summary.status.replace("_", " ")}</span>
                <span className="text-slate-600">·</span>
                <code className="text-cyan-400 font-mono text-[11px]">{summary.run_id}</code>
                <button
                  onClick={copyRunId}
                  className="p-0.5 text-slate-400 hover:text-slate-200 transition-colors ml-1"
                  title="Copy Run ID"
                >
                  <Copy className="w-3 h-3" />
                </button>
                {copied && <span className="text-[10px] text-emerald-400 font-medium">Copied!</span>}
              </div>

              {summary.commit && (
                <div className="hidden sm:flex items-center gap-1 px-2 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-400 text-xs font-mono">
                  <GitBranch className="w-3 h-3 text-slate-500" />
                  <span>{summary.commit.slice(0, 7)}</span>
                </div>
              )}

              <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-slate-900 border border-slate-800 text-slate-400 text-xs">
                <Bot className="w-3 h-3 text-purple-400" />
                <span className="text-slate-300 font-mono text-[11px]">{summary.llm.model}</span>
              </div>

              <span
                className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide ${
                  source === "demo"
                    ? "bg-purple-950/80 text-purple-300 border border-purple-800/50"
                    : "bg-emerald-950/80 text-emerald-300 border border-emerald-800/50 animate-pulse"
                }`}
              >
                {source === "demo" ? "Demo Fixture" : "Live API"}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap">
            <div className="relative flex-1 sm:w-64">
              <input
                type="text"
                value={repo}
                onChange={(e) => onRepoChange(e.target.value)}
                placeholder="Target repo (e.g. targets/juice-shop)"
                className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
              />
            </div>

            <button
              disabled={loading}
              onClick={onCreateRun}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md shadow-cyan-600/20 disabled:opacity-50 disabled:cursor-wait transition-all"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{loading ? "Running..." : "Start Run"}</span>
            </button>

            <button
              disabled={loading}
              onClick={onLoadLatest}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-medium disabled:opacity-50 transition-colors"
              title="Fetch the newest run from the server"
            >
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Load Latest</span>
            </button>

            <button
              onClick={onUseDemo}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-medium transition-colors"
              title="Reset to pre-loaded demo fixtures"
            >
              <RotateCcw className="w-3.5 h-3.5 text-purple-400" />
              <span>Demo</span>
            </button>

            {source === "live" && reportJsonAvailable && (
              <a
                href={reportUrl(summary.run_id)}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-400 text-xs font-medium transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Report</span>
              </a>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
