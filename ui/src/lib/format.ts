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


export function purlVersion(id: string): string {
  const l = purlLabel(id);
  const i = l.lastIndexOf("@");
  return i > 0 ? l.slice(i + 1) : "";
}

/** Findings that describe the same advisory on the same package (different versions) share a key. */
export function groupKey(f: Finding): string {
  if (f.category === "cve" && f.vuln_id && f.component_purl) return `cve|${f.vuln_id}|${purlName(f.component_purl)}`;
  return f.finding_id;
}

export function fmtDate(ts: string | undefined | null): string {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function ago(ts: string | undefined | null): string {
  if (!ts) return "";
  const d = new Date(ts).getTime();
  if (Number.isNaN(d)) return "";
  const s = Math.max(0, (Date.now() - d) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
