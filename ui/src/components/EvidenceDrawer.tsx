import { useState } from "react";
import { Check, Copy, FileCode, X } from "lucide-react";
import type { Evidence } from "../api/types";

interface EvidenceDrawerProps {
  evidence: Evidence;
  onClose: () => void;
}

export default function EvidenceDrawer({ evidence, onClose }: EvidenceDrawerProps) {
  const [copied, setCopied] = useState(false);

  const copyFacts = () => {
    navigator.clipboard.writeText(JSON.stringify(evidence.facts, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="fixed inset-0 bg-slate-950/70 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />

      <aside className="relative w-full max-w-lg bg-slate-900 border-l border-slate-800 shadow-2xl p-6 overflow-y-auto flex flex-col gap-5 z-10">
        <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                {evidence.kind}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-950 border border-slate-800">
                {evidence.source_tool}
              </span>
            </div>
            <h2 className="text-base font-bold text-white font-mono break-all">
              {evidence.evidence_id}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            title="Close drawer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
            <span className="text-[10px] font-semibold text-slate-500 uppercase block mb-0.5">
              Source Tool
            </span>
            <span className="font-mono text-cyan-400 font-semibold">{evidence.source_tool}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80">
            <span className="text-[10px] font-semibold text-slate-500 uppercase block mb-0.5">
              Timestamp
            </span>
            <span className="font-mono text-slate-300 text-[11px] truncate block">
              {evidence.created_at}
            </span>
          </div>
        </div>

        {evidence.file_path && (
          <div className="space-y-1">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              Target File Reference
            </span>
            <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 flex items-center gap-2 break-all">
              <FileCode className="w-4 h-4 text-slate-500 shrink-0" />
              <span>
                {evidence.file_path}
                {evidence.line ? `:${evidence.line}` : ""}
              </span>
            </div>
          </div>
        )}

        {evidence.excerpt && (
          <div className="space-y-1">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
              Tool Excerpt / Finding Proof
            </span>
            <blockquote className="p-3 rounded-lg bg-slate-950 border-l-2 border-cyan-500 text-xs text-slate-300 font-mono italic leading-relaxed">
              {evidence.excerpt}
            </blockquote>
          </div>
        )}

        <div className="space-y-1.5 flex-1 flex flex-col min-h-0">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Verified Grounded Facts
            </span>
            <button
              onClick={copyFacts}
              className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? "Copied" : "Copy JSON"}</span>
            </button>
          </div>
          <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 overflow-auto flex-1 max-h-96">
            {JSON.stringify(evidence.facts, null, 2)}
          </pre>
        </div>
      </aside>
    </div>
  );
}
