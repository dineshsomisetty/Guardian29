import { Box, Layers, ShieldAlert, Sparkles } from "lucide-react";
import type { RunSummary } from "../api/types";

interface MetricCardsProps {
  summary: RunSummary;
}

export default function MetricCards({ summary }: MetricCardsProps) {
  const { sbom, findings } = summary;
  const directPercent = sbom.components > 0
    ? Math.round((sbom.direct / sbom.components) * 100)
    : 0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 mb-5">
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90 shadow-sm backdrop-blur-sm hover:border-slate-700/80 transition-colors">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span className="font-medium flex items-center gap-1.5 text-slate-300">
            <Box className="w-3.5 h-3.5 text-cyan-400" /> Components (SBOM)
          </span>
          <span className="text-[11px] font-mono text-cyan-400">{sbom.file}</span>
        </div>
        <div className="flex items-baseline justify-between mb-2">
          <span className="text-2xl font-bold tracking-tight text-white font-mono">
            {sbom.components.toLocaleString()}
          </span>
          <span className="text-xs text-slate-400">
            <b className="text-slate-200">{sbom.direct}</b> direct ({directPercent}%)
          </span>
        </div>
        <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden flex">
          <div
            className="bg-cyan-500 h-full"
            style={{ width: `${directPercent}%` }}
            title={`Direct: ${sbom.direct}`}
          />
          <div
            className="bg-blue-600/70 h-full"
            style={{ width: `${100 - directPercent}%` }}
            title={`Transitive: ${sbom.transitive}`}
          />
        </div>
        <div className="flex justify-between text-[10px] text-slate-500 mt-1.5">
          <span>{sbom.direct} Direct</span>
          <span>{sbom.transitive.toLocaleString()} Transitive</span>
        </div>
      </div>

      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90 shadow-sm backdrop-blur-sm hover:border-slate-700/80 transition-colors">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span className="font-medium flex items-center gap-1.5 text-slate-300">
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" /> Security Findings
          </span>
          <span className="text-[10px] uppercase font-bold text-red-400 bg-red-950/70 px-1.5 py-0.5 rounded border border-red-800/50">
            {findings.by_risk.critical} Critical
          </span>
        </div>
        <div className="flex items-baseline justify-between mb-2">
          <span className="text-2xl font-bold tracking-tight text-white font-mono">
            {findings.total}
          </span>
          <span className="text-xs text-slate-400">
            {findings.by_risk.critical + findings.by_risk.high} high priority
          </span>
        </div>
        <div className="grid grid-cols-4 gap-1 text-center text-[10px] font-mono">
          <div className="py-0.5 rounded bg-red-950/60 border border-red-800/40 text-red-400">
            <span className="block font-bold">{findings.by_risk.critical}</span>
            <span className="text-[9px] uppercase tracking-wider text-red-500/70">Crit</span>
          </div>
          <div className="py-0.5 rounded bg-orange-950/60 border border-orange-800/40 text-orange-400">
            <span className="block font-bold">{findings.by_risk.high}</span>
            <span className="text-[9px] uppercase tracking-wider text-orange-500/70">High</span>
          </div>
          <div className="py-0.5 rounded bg-amber-950/60 border border-amber-800/40 text-amber-300">
            <span className="block font-bold">{findings.by_risk.medium}</span>
            <span className="text-[9px] uppercase tracking-wider text-amber-500/70">Med</span>
          </div>
          <div className="py-0.5 rounded bg-emerald-950/60 border border-emerald-800/40 text-emerald-400">
            <span className="block font-bold">{findings.by_risk.low}</span>
            <span className="text-[9px] uppercase tracking-wider text-emerald-500/70">Low</span>
          </div>
        </div>
      </div>

      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90 shadow-sm backdrop-blur-sm hover:border-slate-700/80 transition-colors">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span className="font-medium flex items-center gap-1.5 text-slate-300">
            <Layers className="w-3.5 h-3.5 text-purple-400" /> Attack Vectors
          </span>
          <span className="text-[11px] text-slate-500">{Object.keys(findings.by_category).length} types</span>
        </div>
        <div className="flex flex-wrap gap-1.5 mt-2">
          {Object.entries(findings.by_category).map(([cat, count]) => (
            <span
              key={cat}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] bg-slate-800/90 border border-slate-700/70 text-slate-300"
            >
              <span className="capitalize">{cat.replace("_", " ")}:</span>
              <b className="text-cyan-400 font-mono">{count}</b>
            </span>
          ))}
        </div>
      </div>

      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800/90 shadow-sm backdrop-blur-sm hover:border-slate-700/80 transition-colors">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
          <span className="font-medium flex items-center gap-1.5 text-slate-300">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" /> Target &amp; Defense
          </span>
          <span className="text-[10px] uppercase font-bold text-cyan-400 bg-cyan-950/80 px-1.5 py-0.5 rounded border border-cyan-800/50">
            {summary.projects.join(" + ")}
          </span>
        </div>
        <div className="space-y-1.5 text-xs text-slate-300 mt-1">
          <div className="flex justify-between items-center text-[11px]">
            <span className="text-slate-500">Target Workspace:</span>
            <code className="text-slate-200 font-semibold">{summary.target}</code>
          </div>
          <div className="flex justify-between items-center text-[11px]">
            <span className="text-slate-500">Autonomous Gate:</span>
            <span className="text-emerald-400 font-medium">Human-in-the-Loop</span>
          </div>
          <div className="flex justify-between items-center text-[11px]">
            <span className="text-slate-500">Evidence Policy:</span>
            <span className="text-cyan-400 font-medium">Grounded Rationale</span>
          </div>
        </div>
      </div>
    </div>
  );
}
