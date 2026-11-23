import {
  AlertTriangle,
  ArrowRight,
  Info,
  RotateCcw,
  ShieldCheck,
  ThumbsDown,
  ThumbsUp,
} from "lucide-react";
import type { RemediationPlan } from "../api/types";

interface ApprovalViewProps {
  plans: RemediationPlan[];
  loading: boolean;
  decisionComment: string;
  onCommentChange: (val: string) => void;
  onMakeDecision: (
    plan: RemediationPlan,
    decision: "approve" | "reject" | "accept_risk",
  ) => void;
  decisionMessage: string;
  onOpenEvidence: (evidenceId: string) => void;
}

export default function ApprovalView({
  plans,
  loading,
  decisionComment,
  onCommentChange,
  onMakeDecision,
  decisionMessage,
  onOpenEvidence,
}: ApprovalViewProps) {
  return (
    <div className="space-y-4">
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            Human-in-the-Loop Remediation Approval Gate
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Review proposed supply chain mitigations, grounded rationale claims, and compatibility impacts before automated execution.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded-md bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-mono">
            {plans.length} Plan{plans.length !== 1 ? "s" : ""} Pending Review
          </span>
        </div>
      </div>

      {decisionMessage && (
        <div className="p-3.5 rounded-xl bg-blue-950/80 border border-blue-800 text-blue-200 text-xs flex items-center gap-2">
          <Info className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{decisionMessage}</span>
        </div>
      )}

      {plans.length === 0 ? (
        <div className="p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800 text-slate-400">
          <ShieldCheck className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="font-semibold text-slate-300">No remediation plans are pending approval.</p>
          <p className="text-xs text-slate-500 mt-1">
            When vulnerabilities are detected and remediation agents formulate a strategy, they will appear here.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {plans.map((plan) => (
            <article
              key={plan.plan_id}
              className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700/80 shadow-md backdrop-blur-sm space-y-4"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                      Attempt #{plan.attempt}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-950 border border-slate-800">
                      ID: {plan.plan_id}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-500 bg-slate-950 border border-slate-800">
                      Hash: {plan.plan_hash.slice(0, 16)}...
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white capitalize flex items-center gap-2">
                    <span>{plan.action}</span>
                    {plan.target_version && (
                      <span className="text-cyan-400 font-mono">→ v{plan.target_version}</span>
                    )}
                  </h3>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-[11px] text-slate-400">Target Finding:</span>
                  <span className="px-2 py-0.5 rounded bg-red-950/80 text-red-300 font-mono text-xs border border-red-800/60">
                    {plan.finding_id}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
                  <span className="text-[10px] uppercase font-bold text-slate-400 block mb-1">
                    Expected Risk Reduction
                  </span>
                  <p className="text-xs text-emerald-300 font-medium">
                    {plan.expected_risk_reduction}
                  </p>
                </div>

                {plan.compatibility_impact && (
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] uppercase font-bold text-slate-400">
                        Compatibility Impact
                      </span>
                      <span
                        className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                          plan.compatibility_impact.level === "high"
                            ? "bg-red-950 text-red-300 border border-red-800"
                            : "bg-amber-950 text-amber-300 border border-amber-800"
                        }`}
                      >
                        {plan.compatibility_impact.level} impact
                      </span>
                    </div>
                    <div className="text-xs space-y-1">
                      <div className="flex items-center gap-2 font-mono">
                        <span className="text-slate-400">{plan.compatibility_impact.from_version}</span>
                        <ArrowRight className="w-3 h-3 text-slate-600" />
                        <span className="text-cyan-400 font-bold">{plan.compatibility_impact.to_version}</span>
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-slate-800 text-slate-300">
                          {plan.compatibility_impact.semver_delta}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500">
                        Node/Engines:{" "}
                        <b className={plan.compatibility_impact.engines_ok ? "text-emerald-400" : "text-amber-400"}>
                          {plan.compatibility_impact.engines_ok ? "Compatible" : "Check engines"}
                        </b>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 flex items-start gap-2">
                <RotateCcw className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400 block">
                    Rollback Strategy
                  </span>
                  <p className="text-xs text-slate-300 font-mono mt-0.5">{plan.rollback}</p>
                </div>
              </div>

              <div className="space-y-2">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                  Grounded Verification Claims
                </span>
                <div className="space-y-2">
                  {plan.rationale.map((claim, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    >
                      <div className="flex items-start gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase shrink-0 mt-0.5 ${
                            claim.label === "verified"
                              ? "bg-emerald-950 text-emerald-300 border border-emerald-800/60"
                              : "bg-blue-950 text-blue-300 border border-blue-800/60"
                          }`}
                        >
                          {claim.label}
                        </span>
                        <span className="text-slate-200">{claim.text}</span>
                      </div>
                      {claim.evidence_ids.length > 0 && (
                        <div className="flex items-center gap-1 shrink-0">
                          {claim.evidence_ids.map((id) => (
                            <button
                              key={id}
                              onClick={() => onOpenEvidence(id)}
                              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 font-mono text-[10px] border border-slate-700"
                            >
                              {id}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              <div className="pt-3 border-t border-slate-800 space-y-3">
                <div>
                  <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between mb-1.5">
                    <span>Decision Justification Comment (Required for Reject / Accept Risk)</span>
                    <span className="text-slate-500 font-mono text-[10px]">
                      {decisionComment.length}/2000
                    </span>
                  </label>
                  <textarea
                    rows={2}
                    value={decisionComment}
                    onChange={(e) => onCommentChange(e.target.value)}
                    placeholder="Enter architectural rationale or justification for approval, rejection, or risk acceptance..."
                    className="w-full p-2.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
                  />
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    disabled={loading}
                    onClick={() => onMakeDecision(plan, "approve")}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold shadow-md shadow-emerald-600/20 disabled:opacity-50 disabled:cursor-wait transition-all"
                  >
                    <ThumbsUp className="w-3.5 h-3.5" />
                    <span>Approve &amp; Execute</span>
                  </button>

                  <button
                    disabled={loading || !decisionComment.trim()}
                    onClick={() => onMakeDecision(plan, "reject")}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-red-700 hover:bg-red-600 text-white text-xs font-bold shadow-md shadow-red-700/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                    title={!decisionComment.trim() ? "Comment is required to reject a plan" : "Reject plan"}
                  >
                    <ThumbsDown className="w-3.5 h-3.5" />
                    <span>Reject Plan</span>
                  </button>

                  <button
                    disabled={loading || !decisionComment.trim()}
                    onClick={() => onMakeDecision(plan, "accept_risk")}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold shadow-md shadow-amber-600/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
                    title={!decisionComment.trim() ? "Comment is required to accept risk" : "Accept residual risk"}
                  >
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Accept Residual Risk</span>
                  </button>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
