import type { Finding, Risk, RiskAssessment } from "../api/types";

export const RISKS: Risk[] = ["critical", "high", "medium", "low"];
export const RISK_LABEL: Record<Risk, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export const riskRank = (r: string | null | undefined) => (r ? (RANK[r] ?? 9) : 9);

export function purlLabel(id: string): string {
  if (!id.startsWith("pkg:")) return id;
  const rest = id.slice(4).replace(/^[^/]+\//, "");
  try {
    return decodeURIComponent(rest);
  } catch {
    return rest;
  }
}

export function purlName(id: string): string {
  const l = purlLabel(id);
  const i = l.lastIndexOf("@");
  return i > 0 ? l.slice(0, i) : l;
}

export const shortCommit = (c: string | null | undefined) => (c ? c.slice(0, 7) : "unknown");

export function clock(ts: string): string {
  const m = /T(\d\d:\d\d:\d\d)/.exec(ts);
  return m ? m[1] : ts;
}

export function dateTime(ts: string | undefined): string {
  if (!ts) return "";
  return ts.replace("T", " ").replace(/\.\d+/, "").replace("Z", "Z");
}

export const isCve = (f: Finding) => f.category === "cve";

export function bandOf(f: Finding, risk: Map<string, RiskAssessment>): Risk | null {
  return risk.get(f.finding_id)?.band ?? f.initial_risk;
}

export function categoryLabel(c: string): string {
  return c.replace(/_/g, " ");
}

export function findingHeadline(f: Finding): string {
  if (f.vuln_id) return f.vuln_id;
  return f.title;
}

export function claimCounts(fs: Finding[], risk: RiskAssessment[]) {
  let verified = 0;
  let inferred = 0;
  const add = (label: string) => {
    if (label === "verified") verified++;
    else inferred++;
  };
  for (const f of fs) for (const c of f.claims) add(c.label);
  for (const r of risk) for (const c of r.claims) add(c.label);
  return { verified, inferred };
}

export const fixed1 = (n: number) => (Number.isInteger(n) ? String(n) : n.toFixed(1));

export const FACTORS = [
  { key: "S", name: "Severity", weight: 0.3 },
  { key: "E", name: "Exploitability", weight: 0.25 },
  { key: "R", name: "Reachability", weight: 0.2 },
  { key: "P", name: "Production", weight: 0.15 },
  { key: "X", name: "Exposure", weight: 0.1 },
] as const;
