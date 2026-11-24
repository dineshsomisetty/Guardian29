/**
 * Helpers that turn a remediation plan into plain words for the approval and validation pages, and look up
 * decisions on a plan.
 */
import type { Approval, Finding, RemediationPlan, Risk, RiskAssessment } from "../api/types";
import { purlName } from "./format";
import { BAND_COPY, plainTitle } from "./labels";

export interface PlanSummary {
  // package the plan edits: from the first operation, else the vulnerable package
  pkg: string;
  // versions before and after, when known; null for non-version changes
  from: string | null;
  to: string | null;
  // the action word: upgrade, pin, remove, replace, downgrade
  verb: string;
  /** "upgrade X to B" / "replace X with Y": the short action phrase used in lists and timelines */
  change: string;
  // true for a major version jump (can break the app)
  major: boolean;
  /** "Guardian proposes to upgrade X from A to B to fix ..." */
  sentence: string;
  // why, in a phrase ('a high-risk vulnerability in x'); empty when there is no finding
  reason: string;
  // expected risk score after the fix, parsed from expected_risk_reduction ('68 -> 8')
  expectedAfter: number | null;
}

const VERB: Record<string, string> = { upgrade: "upgrade", pin: "pin", remove: "remove", replace: "replace", downgrade: "downgrade" };

/**
 * Short, readable description of what a plan does: the action phrase, a full sentence, whether it is a major
 * jump, and the expected score after.
 */
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

// Shorten a long commit sha or image digest for display.
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

/**
 * The most recent decision recorded for a plan, or null if none (approvals are in the order they were made).
 */
export function decisionOf(planId: string, approvals: Approval[]): Approval["decision"] | null {
  for (let i = approvals.length - 1; i >= 0; i--) if (approvals[i].plan_id === planId) return approvals[i].decision;
  return null;
}

/** Guardian's score for a finding, else its CVSS scaled to 0-100, else null. */
export function scoreOf(risk: RiskAssessment | undefined, f: Finding | undefined): number | null {
  if (risk) return risk.score;
  if (f?.cvss != null) return f.cvss * 10;
  return null;
}

/** Approved fixes that are held (not tested yet) while other fixes still wait for a decision: "Validate now" can test them. */
export function heldApproved<T extends { outcome: string; plan_id?: string | null }>(items: T[]): T[] {
  return items.filter((i) => i.outcome === "approved" && !!i.plan_id);
}
