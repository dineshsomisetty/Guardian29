import { useState } from "react";
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  FileDiff,
  FileText,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { Changes, Finding, Priority } from "../api/types";

interface FindingsViewProps {
  findings: Finding[];
  changes: Changes;
  onOpenEvidence: (evidenceId: string) => void;
}

const severityConfig: Record<
  Priority,
  { badge: string; text: string; border: string; bg: string }
> = {
  critical: {
    badge: "bg-red-950 text-red-300 border-red-700/60",
    text: "text-red-400",
    border: "border-red-900/40",
    bg: "bg-red-950/20",
  },
  high: {
    badge: "bg-orange-950 text-orange-300 border-orange-700/60",
    text: "text-orange-400",
    border: "border-orange-900/40",
    bg: "bg-orange-950/20",
  },
  medium: {
    badge: "bg-amber-950 text-amber-300 border-amber-700/60",
    text: "text-amber-400",
    border: "border-amber-900/40",
    bg: "bg-amber-950/20",
  },
  low: {
    badge: "bg-emerald-950 text-emerald-300 border-emerald-700/60",
    text: "text-emerald-400",
    border: "border-emerald-900/40",
    bg: "bg-emerald-950/20",
  },
};

export default function FindingsView({
  findings,
  changes,
  onOpenEvidence,
}: FindingsViewProps) {
  const [activeSubTab, setActiveSubTab] = useState<"findings" | "changes">("findings");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Priority | "all">("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");

  const categories = Array.from(new Set(findings.map((f) => f.category)));

  const filteredFindings = findings.filter((finding) => {
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchTitle = finding.title.toLowerCase().includes(q);
      const matchPurl = (finding.component_purl ?? "").toLowerCase().includes(q);
      const matchVuln = (finding.vuln_id ?? "").toLowerCase().includes(q);
      const matchFile = (finding.file_path ?? "").toLowerCase().includes(q);
      if (!matchTitle && !matchPurl && !matchVuln && !matchFile) return false;
    }
    if (severityFilter !== "all" && finding.initial_risk !== severityFilter) {
      return false;
    }
    if (categoryFilter !== "all" && finding.category !== categoryFilter) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 p-3 bg-slate-900/80 rounded-xl border border-slate-800">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveSubTab("findings")}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeSubTab === "findings"
                ? "bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Security Findings ({findings.length})</span>
          </button>
          <button
            onClick={() => setActiveSubTab("changes")}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeSubTab === "changes"
                ? "bg-purple-950 text-purple-300 border border-purple-800/80 shadow-sm"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileDiff className="w-3.5 h-3.5" />
            <span>What Changed (Delta)</span>
          </button>
        </div>

        {activeSubTab === "findings" && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter vulnerabilities..."
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div className="flex items-center gap-1">
              {(["all", "critical", "high", "medium", "low"] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-1 rounded text-[11px] font-medium capitalize transition-colors ${
                    severityFilter === sev
                      ? "bg-slate-700 text-white font-bold"
                      : "bg-slate-950/60 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {categories.length > 1 && (
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="px-2.5 py-1.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-400"
              >
                <option value="all">All Categories</option>
                {categories.map((c) => (
                  <option key={c} value={c}>
                    {c.replace("_", " ")}
                  </option>
                ))}
              </select>
            )}
          </div>
        )}
      </div>

      {activeSubTab === "findings" ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filteredFindings.length === 0 ? (
            <div className="col-span-full p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800 text-slate-400">
              <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
              <p className="font-semibold text-slate-300">No findings match the current criteria.</p>
              <p className="text-xs text-slate-500 mt-1">Try resetting the filter or search query.</p>
            </div>
          ) : (
            filteredFindings.map((finding) => {
              const risk = finding.initial_risk ?? "low";
              const style = severityConfig[risk] ?? severityConfig.low;

              return (
                <article
                  key={finding.finding_id}
                  className={`p-4 rounded-xl bg-slate-900/90 border ${style.border} shadow-sm backdrop-blur-sm flex flex-col justify-between gap-3 hover:border-slate-600 transition-colors`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2 flex-wrap mb-2">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${style.badge}`}
                        >
                          {finding.initial_risk ? `${finding.initial_risk} risk` : "Unrated"}
                        </span>
                        {finding.cvss !== undefined && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-200 border border-slate-700">
                            CVSS {finding.cvss}
                          </span>
                        )}
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800/80 text-slate-300 uppercase tracking-wide">
                          {finding.category.replace("_", " ")}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/40">
                          {finding.detector}
                        </span>
                      </div>
                      <span className="text-[10px] uppercase font-bold text-slate-400 px-1.5 py-0.5 rounded bg-slate-800">
                        {finding.status}
                      </span>
                    </div>

                    <h3 className="text-sm font-bold text-white mb-1">{finding.title}</h3>

                    <div className="text-xs text-slate-400 mb-2 font-mono break-all">
                      {finding.component_purl ? (
                        <span className="text-cyan-300">{finding.component_purl}</span>
                      ) : (
                        <span>
                          {finding.file_path}
                          {finding.line ? `:${finding.line}` : ""}
                        </span>
                      )}
                    </div>

                    {(finding.affected_range || finding.fixed_versions.length > 0) && (
                      <div className="flex items-center gap-2 text-xs mb-3 p-2 rounded-lg bg-slate-950/80 border border-slate-800">
                        {finding.affected_range && (
                          <div>
                            <span className="text-[10px] text-slate-500 uppercase block">Affected:</span>
                            <span className="font-mono text-red-400 font-semibold text-[11px]">
                              {finding.affected_range}
                            </span>
                          </div>
                        )}
                        {finding.fixed_versions.length > 0 && (
                          <div className="ml-auto flex items-center gap-1.5">
                            <span className="text-[10px] text-slate-500 uppercase">Fixed in:</span>
                            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 font-mono text-[11px] font-bold border border-emerald-800/60">
                              {finding.fixed_versions.join(", ")}
                            </span>
                          </div>
                        )}
                      </div>
                    )}

                    {finding.provenance && (
                      <div className="flex items-center gap-2 mb-3 text-[11px]">
                        <span className="text-slate-500 text-[10px] uppercase">Provenance:</span>
                        <span
                          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            finding.provenance.signature_verified === true
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800/50"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {finding.provenance.signature_verified === true ? (
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <AlertCircle className="w-3 h-3 text-slate-400" />
                          )}
                          Sig {finding.provenance.signature_verified === true ? "Verified" : "Unknown"}
                        </span>
                        <span
                          className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            finding.provenance.attestation_present === true
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800/50"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          Attestation {finding.provenance.attestation_present === true ? "Present" : "Absent"}
                        </span>
                      </div>
                    )}

                    {finding.dependency_paths.length > 0 && (
                      <div className="space-y-1 mb-2">
                        <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider block">
                          Dependency Trace
                        </span>
                        {finding.dependency_paths.map((path, idx) => (
                          <div
                            key={idx}
                            className="flex items-center gap-1.5 flex-wrap p-1.5 rounded bg-slate-950/60 border border-slate-800/70 text-[11px] font-mono text-slate-300"
                          >
                            {path.map((segment, sIdx) => (
                              <span key={sIdx} className="flex items-center gap-1">
                                <span className={sIdx === path.length - 1 ? "text-red-400 font-bold" : ""}>
                                  {segment}
                                </span>
                                {sIdx < path.length - 1 && (
                                  <ChevronRight className="w-3 h-3 text-slate-600 shrink-0" />
                                )}
                              </span>
                            ))}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="pt-2.5 border-t border-slate-800/80 flex items-center justify-between flex-wrap gap-2 text-xs">
                    <span className="text-[11px] text-slate-500 flex items-center gap-1">
                      <FileText className="w-3.5 h-3.5" /> Evidence
                    </span>
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {finding.evidence_ids.map((id) => (
                        <button
                          key={id}
                          onClick={() => onOpenEvidence(id)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 font-mono text-[11px] border border-slate-700/60 transition-colors"
                        >
                          {id}
                        </button>
                      ))}
                    </div>
                  </div>
                </article>
              );
            })
          )}
        </div>
      ) : (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="flex items-center justify-between gap-4 mb-3 pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <FileDiff className="w-4 h-4 text-purple-400" /> Manifest Comparison
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Comparing baseline backup against active target package manifest
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="px-2 py-1 rounded bg-slate-950 text-slate-400 border border-slate-800">
                  Base: {changes.base}
                </span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                <span className="px-2 py-1 rounded bg-purple-950/80 text-purple-300 border border-purple-800/60">
                  Head: {changes.head}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
              <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/40">
                <span className="text-[10px] uppercase font-bold text-emerald-400 block mb-1">
                  Added Packages (+{changes.added.length})
                </span>
                {changes.added.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">None added</p>
                ) : (
                  <div className="space-y-1">
                    {changes.added.map((pkg) => (
                      <code key={pkg} className="block text-xs text-emerald-300 font-mono">
                        + {pkg}
                      </code>
                    ))}
                  </div>
                )}
              </div>

              <div className="p-3 rounded-lg bg-red-950/30 border border-red-900/40">
                <span className="text-[10px] uppercase font-bold text-red-400 block mb-1">
                  Removed Packages (-{changes.removed.length})
                </span>
                {changes.removed.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">None removed</p>
                ) : (
                  <div className="space-y-1">
                    {changes.removed.map((pkg) => (
                      <code key={pkg} className="block text-xs text-red-300 font-mono">
                        - {pkg}
                      </code>
                    ))}
                  </div>
                )}
              </div>

              <div className="p-3 rounded-lg bg-amber-950/30 border border-amber-900/40">
                <span className="text-[10px] uppercase font-bold text-amber-400 block mb-1">
                  Version Changes ({changes.changed.length})
                </span>
                {changes.changed.length === 0 ? (
                  <p className="text-xs text-slate-500 italic">No version deltas</p>
                ) : (
                  <div className="space-y-1.5">
                    {changes.changed.map((c) => (
                      <div key={c.name} className="text-xs font-mono flex items-center justify-between">
                        <span className="text-slate-200">{c.name}:</span>
                        <div className="flex items-center gap-1">
                          <span className="text-slate-400">{c.from}</span>
                          <ArrowRight className="w-2.5 h-2.5 text-slate-500" />
                          <span className="text-amber-300 font-bold">{c.to}</span>
                          {c.major_jump && (
                            <span className="px-1 rounded text-[9px] font-bold bg-red-950 text-red-400 border border-red-800">
                              MAJOR
                            </span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {changes.integrity_changed.length > 0 && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] uppercase font-bold text-amber-400 block mb-2">
                  Integrity Hash Discrepancies ({changes.integrity_changed.length})
                </span>
                <div className="space-y-2">
                  {changes.integrity_changed.map((ic) => (
                    <div key={ic.purl} className="text-xs font-mono space-y-0.5">
                      <div className="text-cyan-300 font-semibold">{ic.purl}</div>
                      <div className="text-slate-500 text-[10px] flex items-center gap-2">
                        <span>From: {ic.from}</span>
                        <ArrowRight className="w-2.5 h-2.5 text-slate-600" />
                        <span className="text-amber-400">To: {ic.to}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {changes.evidence_ids.length > 0 && (
              <div className="flex items-center gap-2 mt-4 pt-3 border-t border-slate-800 text-xs">
                <span className="text-slate-500">Supporting Evidence:</span>
                {changes.evidence_ids.map((id) => (
                  <button
                    key={id}
                    onClick={() => onOpenEvidence(id)}
                    className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-[11px] border border-slate-700"
                  >
                    {id}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
