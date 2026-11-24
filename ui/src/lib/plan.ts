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
  const change = specialChange(plan) ?? `${verb} ${pkg}${to ? ` ${prep} ${to}` : ""}`;
  const sentence = `Guardian proposes to ${verb} ${pkg}${move}${reason ? ` to fix ${reason}` : ""}.`;
  const m = /->\s*([\d.]+)/.exec(plan.expected_risk_reduction ?? "");
  return { pkg, from, to, verb, change, major: c?.semver_delta === "major", sentence, reason, expectedAfter: m ? Number(m[1]) : null };
}

const short = (s: string) => (/^(sha256:)?[0-9a-f]{40,}$/.test(s) ? `${s.replace(/^sha256:/, "").slice(0, 12)}…` : s);

/** Plans whose op is not "set package X to version Y" read better named by what they actually change. */
function specialChange(plan: RemediationPlan): string | null {
  const op = plan.ops[0];
  if (plan.action === "mitigate" && !plan.ops.length) return "no code change: accept a documented mitigation";
  if (!op) return null;
  const a = op.args as Record<string, unknown>;
  switch (op.op) {
    case "generate_lockfile": {
      const ps = Array.isArray(a.projects) ? (a.projects as string[]) : [];
      return `turn lockfiles back on and add them${ps.length ? ` (${ps.join(", ")})` : ""}`;
    }
    case "pin_action_sha":
      return `pin ${String(a.action)}@${String(a.ref)} to commit ${short(String(a.sha))}`;
    case "pin_image_digest":
      return `pin image ${String(a.image)}${a.tag ? `:${String(a.tag)}` : ""} to digest ${short(String(a.digest))}`;
    case "update_base_image":
      return `update base image ${String(a.image)} to ${String(a.new_tag ?? a.tag ?? "")}`.trim();
    default:
      return null;
  }
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
