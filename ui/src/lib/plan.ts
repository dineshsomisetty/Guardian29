import type { Approval, Finding, RemediationPlan, Risk, RiskAssessment } from "../api/types";
import { purlName } from "./format";
import { BAND_COPY, plainTitle } from "./labels";

export interface PlanSummary {
  pkg: string;
  from: string | null;
  to: string | null;
  verb: string;
  /** "upgrade X to B" / "replace X with Y": the short action phrase used in lists and timelines */
  change: string;
  major: boolean;
  /** "Guardian proposes to upgrade X from A to B to fix ..." */
  sentence: string;
  reason: string;
  expectedAfter: number | null;
}

const VERB: Record<string, string> = { upgrade: "upgrade", pin: "pin", remove: "remove", replace: "replace", downgrade: "downgrade" };

export function planSummary(plan: RemediationPlan, finding: Finding | undefined, band: Risk | null): PlanSummary {
  const op = plan.ops[0];
  const argName = op && typeof op.args?.name === "string" ? (op.args.name as string) : null;
  const vulnName = finding?.component_purl ? purlName(finding.component_purl) : null;
  const pkg = argName ?? vulnName ?? "the dependency";
  const c = plan.compatibility_impact;
  const from = c?.from_version ?? null;
  const to = plan.target_version ?? c?.to_version ?? null;
  const verb = VERB[plan.action] ?? plan.action;
  let reason = "";
  if (finding?.category === "cve") {
    const adj = band ? BAND_COPY[band].adj : "known";
    reason = `a ${adj} vulnerability in ${vulnName ?? pkg}`;
    if (vulnName && vulnName !== pkg) reason += `, which ${pkg} pulls in`;
  } else if (finding) reason = plainTitle(finding, band).replace(/^./, (x) => x.toLowerCase());
  // a replacement names the new package, so it reads "replace X with Y", never "replace X to Y"
  const prep = plan.action === "replace" ? "with" : "to";
  const move = from && to ? ` from ${from} ${prep} ${to}` : to ? ` ${prep} ${to}` : "";
  const change = `${verb} ${pkg}${to ? ` ${prep} ${to}` : ""}`;
  const sentence = `Guardian proposes to ${verb} ${pkg}${move}${reason ? ` to fix ${reason}` : ""}.`;
  const m = /->\s*([\d.]+)/.exec(plan.expected_risk_reduction ?? "");
  return { pkg, from, to, verb, change, major: c?.semver_delta === "major", sentence, reason, expectedAfter: m ? Number(m[1]) : null };
}

/** The latest recorded decision on a plan, if any. */
export function decisionOf(planId: string, approvals: Approval[]): Approval["decision"] | null {
  for (let i = approvals.length - 1; i >= 0; i--) if (approvals[i].plan_id === planId) return approvals[i].decision;
  return null;
}

export function scoreOf(risk: RiskAssessment | undefined, f: Finding | undefined): number | null {
  if (risk) return risk.score;
  if (f?.cvss != null) return f.cvss * 10;
  return null;
}
