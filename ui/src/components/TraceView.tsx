import { useState } from "react";
import {
  Activity,
  Bot,
  CheckCircle2,
  Cpu,
  FileText,
  Filter,
  Flame,
  Radio,
  Sparkles,
  Terminal,
} from "lucide-react";
import type { AgentEvent } from "../api/types";

interface TraceViewProps {
  events: AgentEvent[];
  source: "demo" | "live";
  onOpenEvidence: (evidenceId: string) => void;
}

const agentConfig: Record<string, { badge: string; dot: string; icon: typeof Bot }> = {
  supervisor: {
    badge: "bg-purple-950 text-purple-300 border-purple-800/60",
    dot: "bg-purple-500",
    icon: Sparkles,
  },
  discovery: {
    badge: "bg-blue-950 text-blue-300 border-blue-800/60",
    dot: "bg-blue-500",
    icon: Terminal,
  },
  detection: {
    badge: "bg-amber-950 text-amber-300 border-amber-800/60",
    dot: "bg-amber-500",
    icon: Flame,
  },
  evidence_analyst: {
    badge: "bg-emerald-950 text-emerald-300 border-emerald-800/60",
    dot: "bg-emerald-500",
    icon: Cpu,
  },
  remediation: {
    badge: "bg-indigo-950 text-indigo-300 border-indigo-800/60",
    dot: "bg-indigo-500",
    icon: Activity,
  },
  validator: {
    badge: "bg-cyan-950 text-cyan-300 border-cyan-800/60",
    dot: "bg-cyan-500",
    icon: CheckCircle2,
  },
};

export default function TraceView({
  events,
  source,
  onOpenEvidence,
}: TraceViewProps) {
  const [agentFilter, setAgentFilter] = useState<string>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const availableAgents = Array.from(new Set(events.map((e) => e.agent)));
  const availableTypes = Array.from(new Set(events.map((e) => e.type)));

  const filteredEvents = events.filter((e) => {
    if (agentFilter !== "all" && e.agent !== agentFilter) return false;
    if (typeFilter !== "all" && e.type !== typeFilter) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-slate-900/90 rounded-xl border border-slate-800">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-950 text-xs font-semibold text-slate-300 border border-slate-800">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Agent Execution Log ({events.length} events)</span>
          </div>
          {source === "live" && (
            <span className="flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800/50">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
              Live SSE Stream Active
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-500 flex items-center gap-1 text-[11px]">
            <Filter className="w-3 h-3" /> Agent:
          </span>
          <select
            value={agentFilter}
            onChange={(e) => setAgentFilter(e.target.value)}
            className="px-2 py-1 bg-slate-950 border border-slate-800 rounded-md text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Agents</option>
            {availableAgents.map((agent) => (
              <option key={agent} value={agent}>
                {agent}
              </option>
            ))}
          </select>

          <span className="text-slate-500 flex items-center gap-1 text-[11px] ml-2">
            Type:
          </span>
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="px-2 py-1 bg-slate-950 border border-slate-800 rounded-md text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
          >
            <option value="all">All Event Types</option>
            {availableTypes.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="relative pl-6 sm:pl-8 space-y-4 before:absolute before:left-3 sm:before:left-4 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800 text-slate-400">
            <Bot className="w-8 h-8 text-slate-600 mx-auto mb-2 animate-bounce" />
            <p className="font-semibold text-slate-300">Waiting for agent events...</p>
            <p className="text-xs text-slate-500 mt-1">
              Events will stream live as multi-agent orchestration proceeds.
            </p>
          </div>
        ) : (
          filteredEvents.map((event, index) => {
            const conf = agentConfig[event.agent] ?? {
              badge: "bg-slate-800 text-slate-300 border-slate-700",
              dot: "bg-slate-500",
              icon: Bot,
            };
            const Icon = conf.icon;

            return (
              <div key={`${event.agent}-${event.ts}-${index}`} className="relative group">
                <div
                  className={`absolute -left-[27px] sm:-left-[35px] top-3 w-5 h-5 rounded-full ${conf.dot} flex items-center justify-center text-slate-950 ring-4 ring-slate-950 shadow-md`}
                >
                  <Icon className="w-3 h-3 text-white" />
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800/90 hover:border-slate-700 shadow-sm backdrop-blur-sm transition-all">
                  <div className="flex items-center justify-between gap-2 flex-wrap mb-1.5">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${conf.badge}`}
                      >
                        {event.agent.replace("_", " ")}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-300 uppercase">
                        {event.type}
                      </span>
                      {event.finding_id && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono text-red-400 bg-red-950/60 border border-red-800/40">
                          {event.finding_id}
                        </span>
                      )}
                    </div>
                    <time className="text-[11px] font-mono text-slate-500">{event.ts}</time>
                  </div>

                  <p className="text-xs text-slate-200 font-medium leading-relaxed mb-2">
                    {event.summary}
                  </p>

                  {event.evidence_ids.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap pt-2 border-t border-slate-800/60">
                      <span className="text-[10px] font-semibold text-slate-500 uppercase flex items-center gap-1">
                        <FileText className="w-3 h-3" /> Grounded Evidence:
                      </span>
                      {event.evidence_ids.map((id) => (
                        <button
                          key={id}
                          onClick={() => onOpenEvidence(id)}
                          className="px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-[10px] border border-slate-700/60 transition-colors"
                        >
                          {id}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
