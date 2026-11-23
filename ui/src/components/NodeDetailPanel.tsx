import { useState } from "react";
import {
  Check,
  ChevronRight,
  Copy,
  ShieldAlert,
} from "lucide-react";
import type { GraphData, GraphNode, Priority } from "../api/types";

interface NodeDetailPanelProps {
  node: GraphNode;
  graph: GraphData;
  onSelectNode: (node: GraphNode | null) => void;
  onOpenFinding?: (findingId: string) => void;
}

const riskBadgeStyle: Record<Priority, string> = {
  critical: "bg-red-950 text-red-300 border-red-700/60",
  high: "bg-orange-950 text-orange-300 border-orange-700/60",
  medium: "bg-amber-950 text-amber-300 border-amber-700/60",
  low: "bg-emerald-950 text-emerald-300 border-emerald-700/60",
};

export default function NodeDetailPanel({
  node,
  graph,
  onSelectNode,
  onOpenFinding,
}: NodeDetailPanelProps) {
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const copyText = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const ancestors: GraphNode[] = [];
  let currentTarget = node.id;
  while (currentTarget) {
    const parentEdge = graph.edges.find((e) => e.target === currentTarget);
    if (!parentEdge) break;
    const parentNode = graph.nodes.find((n) => n.id === parentEdge.source);
    if (parentNode && !ancestors.some((a) => a.id === parentNode.id)) {
      ancestors.unshift(parentNode);
      currentTarget = parentNode.id;
    } else {
      break;
    }
  }

  return (
    <aside className="w-80 border-l border-slate-800 bg-slate-900/95 backdrop-blur-md p-4 overflow-y-auto flex flex-col gap-4 text-xs">
      <div className="pb-3 border-b border-slate-800">
        <div className="flex items-center justify-between gap-2 mb-1.5">
          <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/50">
            {node.kind}
          </span>
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide border ${
              riskBadgeStyle[node.risk]
            }`}
          >
            {node.risk} risk
          </span>
        </div>
        <h2 className="text-base font-bold text-white break-words">{node.label}</h2>
        {node.version && (
          <p className="text-slate-400 font-mono text-[11px] mt-0.5">version {node.version}</p>
        )}
      </div>

      <div className="space-y-2">
        <h3 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Package Details
        </h3>
        <div className="bg-slate-950/60 rounded-lg p-2.5 space-y-2 border border-slate-800/80">
          <div className="flex justify-between items-center">
            <span className="text-slate-500">Scope:</span>
            <span className="font-semibold text-slate-200 capitalize">{node.scope ?? "unknown"}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-500">Project:</span>
            <span className="font-semibold text-slate-200">{node.project ?? "root"}</span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-slate-500">Direct Dependency:</span>
            <span className="font-semibold text-slate-200">{node.direct ? "Yes" : "Transitive"}</span>
          </div>
          {node.deprecated !== undefined && (
            <div className="flex justify-between items-center">
              <span className="text-slate-500">Deprecated:</span>
              <span className={node.deprecated ? "text-amber-400 font-bold" : "text-slate-300"}>
                {node.deprecated ? "Yes" : "No"}
              </span>
            </div>
          )}
        </div>
      </div>

      <div className="space-y-2">
        <h3 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
          Provenance &amp; Integrity
        </h3>
        <div className="bg-slate-950/60 rounded-lg p-2.5 space-y-2 border border-slate-800/80">
          <div>
            <div className="flex items-center justify-between text-slate-500 text-[10px] mb-1">
              <span>Origin URL:</span>
              {node.origin && (
                <button
                  onClick={() => copyText(node.origin!, "origin")}
                  className="hover:text-cyan-400 text-slate-400 flex items-center gap-0.5"
                >
                  {copiedField === "origin" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedField === "origin" ? "Copied" : "Copy"}</span>
                </button>
              )}
            </div>
            <code className="block bg-slate-900 p-1.5 rounded text-[10px] text-cyan-300 font-mono break-all border border-slate-800">
              {node.origin || "Unknown"}
            </code>
          </div>

          <div>
            <div className="flex items-center justify-between text-slate-500 text-[10px] mb-1">
              <span>Integrity Hash:</span>
              {node.integrity && (
                <button
                  onClick={() => copyText(node.integrity!, "integrity")}
                  className="hover:text-cyan-400 text-slate-400 flex items-center gap-0.5"
                >
                  {copiedField === "integrity" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedField === "integrity" ? "Copied" : "Copy"}</span>
                </button>
              )}
            </div>
            <code className="block bg-slate-900 p-1.5 rounded text-[10px] text-slate-300 font-mono break-all border border-slate-800">
              {node.integrity || "Not available"}
            </code>
          </div>
        </div>
      </div>

      {ancestors.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Path to Root
          </h3>
          <div className="bg-slate-950/60 rounded-lg p-2.5 border border-slate-800/80 flex flex-col gap-1.5">
            {ancestors.map((ancestor, idx) => (
              <div key={ancestor.id} className="flex items-center gap-1.5 text-[11px]">
                <span className="text-slate-600 font-mono">{idx + 1}.</span>
                <button
                  onClick={() => onSelectNode(ancestor)}
                  className="text-cyan-400 hover:text-cyan-300 hover:underline truncate max-w-[190px]"
                >
                  {ancestor.label}
                </button>
                <ChevronRight className="w-3 h-3 text-slate-600 shrink-0 ml-auto" />
              </div>
            ))}
            <div className="flex items-center gap-1.5 text-[11px] font-bold text-white pt-1 border-t border-slate-800">
              <span className="text-slate-600 font-mono">{ancestors.length + 1}.</span>
              <span className="truncate">{node.label}</span>
              <span className="text-[9px] px-1 rounded bg-cyan-950 text-cyan-400 ml-auto border border-cyan-800/40">
                Selected
              </span>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h3 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Findings ({node.finding_ids.length})
          </h3>
        </div>
        {node.finding_ids.length === 0 ? (
          <p className="text-slate-500 text-[11px] italic">No active security findings for this component.</p>
        ) : (
          <div className="space-y-1.5">
            {node.finding_ids.map((fid) => (
              <div
                key={fid}
                className="p-2 rounded bg-red-950/40 border border-red-800/50 flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />
                  <span className="font-mono text-red-300 text-[11px]">{fid}</span>
                </div>
                {onOpenFinding && (
                  <button
                    onClick={() => onOpenFinding(fid)}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 font-medium"
                  >
                    View
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}
