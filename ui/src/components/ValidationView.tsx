import {
  ArrowRight,
  CheckCircle2,
  FileCheck2,
  FileText,
  XCircle,
} from "lucide-react";
import type { ValidationResult } from "../api/types";

interface ValidationViewProps {
  validation: ValidationResult[];
  onOpenEvidence: (evidenceId: string) => void;
}

export default function ValidationView({
  validation,
  onOpenEvidence,
}: ValidationViewProps) {
  return (
    <div className="space-y-4">
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            Remediation Verification &amp; Re-Scan Results
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Automated sandbox verification, test execution suites, and SBOM diff validation across remediation attempts.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded-md bg-slate-950 text-slate-300 border border-slate-800 font-mono">
            {validation.length} Verification Attempt{validation.length !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      {validation.length === 0 ? (
        <div className="p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800 text-slate-400">
          <FileCheck2 className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="font-semibold text-slate-300">No validation attempts recorded for this run.</p>
          <p className="text-xs text-slate-500 mt-1">
            Verification results appear once a remediation plan is executed in the isolated sandbox.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {validation.map((attempt) => {
            const isVerified = attempt.verdict === "verified";
            const unitTotal = (attempt.unit_tests.passed ?? 0) + (attempt.unit_tests.failed ?? 0);
            const unitPercent = unitTotal > 0 ? Math.round(((attempt.unit_tests.passed ?? 0) / unitTotal) * 100) : 100;

            return (
              <article
                key={attempt.attempt_id}
                className={`p-5 rounded-xl bg-slate-900/90 border ${
                  isVerified ? "border-emerald-800/70" : "border-amber-800/60"
                } shadow-md backdrop-blur-sm space-y-4`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
                  <div className="flex items-center gap-2.5">
                    <div
                      className={`w-7 h-7 rounded-lg flex items-center justify-center ${
                        isVerified ? "bg-emerald-950 text-emerald-400 border border-emerald-800" : "bg-red-950 text-red-400 border border-red-800"
                      }`}
                    >
                      {isVerified ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <h3 className="text-sm font-bold text-white capitalize">
                          {attempt.verdict.replace("_", " ")}
                        </h3>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-950 border border-slate-800">
                          {attempt.attempt_id}
                        </span>
                      </div>
                      <span className="text-[11px] text-slate-400">
                        Target: <b className="text-slate-200 font-mono">{attempt.finding_id}</b>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-950 text-slate-300 border border-slate-800">
                      Confidence: {attempt.final_confidence}
                    </span>
                    {attempt.artifact_rescanned && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                        {attempt.artifact_rescanned}
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">
                      Build Status
                    </span>
                    <div className="flex items-center gap-1.5">
                      {attempt.build_ok ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-400" />
                      )}
                      <span className={`text-xs font-bold ${attempt.build_ok ? "text-emerald-400" : "text-red-400"}`}>
                        {attempt.build_ok ? "Passed Successfully" : "Build Failed"}
                      </span>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">
                      Unit Tests
                    </span>
                    <div className="flex items-baseline justify-between mb-1 text-xs">
                      <span className="font-bold text-white font-mono">
                        {attempt.unit_tests.passed ?? 0} Passed
                      </span>
                      <span className="text-[11px] text-red-400 font-mono">
                        {attempt.unit_tests.failed ?? 0} Failed
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden flex">
                      <div className="bg-emerald-500 h-full" style={{ width: `${unitPercent}%` }} />
                      <div className="bg-red-500 h-full" style={{ width: `${100 - unitPercent}%` }} />
                    </div>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">
                      Integration Tests
                    </span>
                    <div className="text-xs font-mono font-bold text-white">
                      {attempt.integration_tests.passed ?? 0} Passed / {attempt.integration_tests.failed ?? 0} Failed
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {attempt.integration_tests.skipped ?? 0} Skipped
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">
                      Risk Score Delta
                    </span>
                    <div className="flex items-center gap-2 text-xs font-mono font-bold">
                      <span className="text-red-400">{attempt.risk_before}</span>
                      <ArrowRight className="w-3 h-3 text-slate-500" />
                      <span className={attempt.risk_after === 0 ? "text-emerald-400" : "text-amber-400"}>
                        {attempt.risk_after}
                      </span>
                      <span className="text-[10px] px-1 py-0.5 rounded bg-emerald-950 text-emerald-400 ml-auto">
                        -{attempt.risk_before - attempt.risk_after} pts
                      </span>
                    </div>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between flex-wrap gap-2 text-xs">
                  <span className="text-[11px] text-slate-500 flex items-center gap-1">
                    <FileText className="w-3.5 h-3.5" /> Verification Logs &amp; Evidence
                  </span>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {attempt.log_evidence_ids.map((id) => (
                      <button
                        key={id}
                        onClick={() => onOpenEvidence(id)}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-[11px] border border-slate-700"
                      >
                        Log {id}
                      </button>
                    ))}
                    {attempt.detector_evidence_ids.map((id) => (
                      <button
                        key={id}
                        onClick={() => onOpenEvidence(id)}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-purple-400 font-mono text-[11px] border border-slate-700"
                      >
                        Detector {id}
                      </button>
                    ))}
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}
