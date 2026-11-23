// Plain-language vocabulary: every technical id the data contract uses maps to words a non-specialist can read.
import type { Evidence, Finding, Risk, RiskAssessment } from "../api/types";
import { purlName, purlVersion } from "./format";

export const CATEGORY_LABEL: Record<string, string> = {
  cve: "Known vulnerability (CVE)",
  typosquat: "Typosquat",
  install_script: "Install script",
  unpinned_ci: "Unpinned CI action",
  untrusted_image: "Tag-only image",
  lockfile: "Missing lockfile",
  unexpected_change: "Unexpected change",
  provenance: "Weak provenance",
};

export const CATEGORY_SHORT: Record<string, string> = {
  cve: "Vulnerability",
  typosquat: "Typosquat",
  install_script: "Install script",
  unpinned_ci: "Unpinned CI",
  untrusted_image: "Tag-only image",
  lockfile: "No lockfile",
  unexpected_change: "Unexpected change",
};

export const CATEGORY_WHY: Record<string, string> = {
  cve: "A published security flaw in a package you depend on.",
  typosquat: "A package name that imitates a popular one. Attackers use these to slip in malicious code.",
  install_script: "A dependency that runs code on your machine the moment it is installed.",
  unpinned_ci: "A build step that can change without review because it is not locked to a fixed commit.",
  untrusted_image: "A container base image referenced by a movable tag, so what you build can change silently.",
  lockfile: "Without a lockfile, installs can silently pull different (or tampered) versions.",
  unexpected_change: "A dependency changed in a way that does not match the surrounding history.",
};

const humanize = (s: string) => {
  const t = s.replace(/[_-]+/g, " ").trim();
  return t.charAt(0).toUpperCase() + t.slice(1);
};

export const categoryLabel = (c: string) => CATEGORY_LABEL[c] ?? humanize(c);
export const categoryShort = (c: string) => CATEGORY_SHORT[c] ?? humanize(c);

export const BAND_COPY: Record<Risk, { name: string; line: string; adj: string }> = {
  critical: { name: "Critical", adj: "critical", line: "Fix first. Likely to be exploited and used in production." },
  high: { name: "High", adj: "high-severity", line: "Fix soon. Serious flaws that reach real code paths." },
  medium: { name: "Medium", adj: "medium-severity", line: "Fix in normal maintenance. Real, but harder to exploit." },
  low: { name: "Low", adj: "low-severity", line: "Track it. Little practical impact today." },
};

// ------------------------------------------------------------------ plain titles

const sub = (s: string, re: RegExp) => re.exec(s);

/** One-line, plain-language title for a finding. */
export function plainTitle(f: Finding, band: Risk | null): string {
  const name = f.component_purl ? purlName(f.component_purl) : "";
  const ver = f.component_purl ? purlVersion(f.component_purl) : "";
  switch (f.category) {
    case "cve": {
      const adj = band ? BAND_COPY[band].adj : "known";
      const who = name ? `${name}${ver ? ` ${ver}` : ""}` : "A dependency";
      return `${who} has ${/^[aeiou]/.test(adj) ? "an" : "a"} ${adj} vulnerability${f.vuln_id ? ` (${f.vuln_id})` : ""}`;
    }
    case "typosquat": {
      const m = sub(f.title, /'([^']+)'.*looks like '([^']+)'/);
      return m ? `"${m[1]}" looks like a typosquat of "${m[2]}"` : f.title;
    }
    case "install_script": {
      const m = sub(f.title, /\(([^)]+)\)/);
      const who = name ? `${name}${ver ? ` ${ver}` : ""}` : "A dependency";
      return `${who} runs a script when installed${m ? ` (${m[1]})` : ""}`;
    }
    case "unpinned_ci": {
      const m = sub(f.title, /Action (\S+)/);
      return m ? `${m[1]} is not pinned to a commit` : f.title;
    }
    case "untrusted_image": {
      const m = sub(f.title, /image (\S+)/);
      return m ? `Base image ${m[1]} is referenced by tag only` : f.title;
    }
    case "lockfile":
      return f.file_path ? `No lockfile is kept (${f.file_path} disables it)` : "No lockfile is kept for this project";
    default:
      return f.title;
  }
}

/** The technical id shown as secondary text. */
export function findingRef(f: Finding): string {
  if (f.vuln_id) return [f.vuln_id, ...f.aliases.slice(0, 1)].join(" / ");
  if (f.component_purl && f.category !== "untrusted_image") return `${purlName(f.component_purl)}@${purlVersion(f.component_purl)}`;
  return f.file_path ?? f.finding_id;
}

export function firstSentence(s: string | null | undefined, max = 220): string {
  if (!s) return "";
  const t = s.trim().replace(/\s+/g, " ");
  const m = /^(.+?[.!?])(\s|$)/.exec(t);
  const out = m ? m[1] : t;
  return out.length > max ? `${out.slice(0, max - 1).trimEnd()}…` : out;
}

/** "Why it matters", one sentence. Prefer the scored summary, then the analyst explanation. */
export function whyItMatters(f: Finding, risk: RiskAssessment | undefined): string {
  const fromRisk = risk?.summary ? firstSentence(risk.summary) : "";
  if (fromRisk) return fromRisk.replace(/^Ranks (critical|high|medium|low)( despite[^,]*,)? because /i, (_m, b: string) => `Rated ${b} because `);
  if (f.explanation) return firstSentence(f.explanation);
  return CATEGORY_WHY[f.category] ?? "";
}

// ------------------------------------------------------------------ risk factors

export const FACTOR_INFO = {
  S: { name: "Severity", weight: 0.3, help: "How damaging the flaw is on paper (CVSS score from the advisory)." },
  E: { name: "Exploitability", weight: 0.25, help: "How likely attackers are to use it: exploit probability (EPSS) and the known-exploited list (KEV)." },
  R: { name: "Reachability", weight: 0.2, help: "Whether your own code actually imports and uses the vulnerable package." },
  P: { name: "Used in production", weight: 0.15, help: "Whether the package ships to production or is only a development tool." },
  X: { name: "Exposure", weight: 0.1, help: "Whether the running service can be reached from outside, for example on an open network port." },
} as const;
export type FactorKey = keyof typeof FACTOR_INFO;
export const FACTOR_KEYS = Object.keys(FACTOR_INFO) as FactorKey[];

const TIER: Record<string, string> = {
  cvss: "Taken from the CVSS score",
  epss: "Exploit probability (EPSS)",
  kev: "Listed as actively exploited",
  imported: "Imported by application code",
  not_imported: "Not imported anywhere",
  prod: "Production dependency",
  dev: "Development-only",
  network: "Service is reachable over the network",
  local: "Only reachable locally",
  unknown: "Could not be determined",
  default: "Default assumption",
  heuristic: "Estimated from available signals",
};
export const tierLabel = (t: string) => TIER[t] ?? humanize(t);

// ------------------------------------------------------------------ evidence

const EVIDENCE_TITLE: Record<string, string> = {
  scanner_output: "Scanner match",
  osv: "Advisory record (OSV)",
  kev: "Known-exploited check (CISA KEV)",
  epss: "Exploit likelihood (EPSS)",
  graph: "Dependency graph",
  reachability: "Code usage scan",
  exposure: "Exposure check",
  registry_metadata: "Registry metadata",
  file_excerpt: "File excerpt",
  provenance: "Package provenance",
  detector_result: "Detector result",
  sbom: "Software inventory (SBOM)",
  changes: "Changes since the base version",
  compat_hint: "Compatibility check",
  patch_diff: "Proposed change",
  diff: "Code change",
  build_log: "Build log",
  test_result: "Test results",
  sbom_diff: "Inventory before and after",
};

export function evidenceTitle(ev: Pick<Evidence, "kind" | "source_tool">): string {
  const base = EVIDENCE_TITLE[ev.kind] ?? humanize(ev.kind);
  if (ev.kind === "scanner_output") {
    const t = /^([a-z]+)/i.exec(ev.source_tool)?.[1];
    if (t) return `${base} (${t.charAt(0).toUpperCase()}${t.slice(1)})`;
  }
  return base;
}

export function evidenceKindTitle(kind: string): string {
  return EVIDENCE_TITLE[kind] ?? humanize(kind);
}

const pct = (n: unknown) => (typeof n === "number" ? `${(n * 100).toFixed(1)}%` : "");

/** One plain sentence describing what an evidence record says. */
export function evidenceSummary(ev: Evidence): string {
  const f = ev.facts ?? {};
  const s = (k: string) => (f[k] == null ? "" : String(f[k]));
  switch (ev.kind) {
    case "scanner_output":
    case "osv": {
      const bits = [s("vuln_id"), s("severity"), f.cvss != null ? `CVSS ${s("cvss")}` : "", (f.fixed_versions as string[] | undefined)?.length ? `fixed in ${(f.fixed_versions as string[]).join(", ")}` : ""];
      return bits.filter(Boolean).join(" · ") || (ev.excerpt ?? "");
    }
    case "epss":
      return `${s("cve")}: ${pct(f.epss)} chance of exploitation, higher than ${pct(f.percentile)} of known flaws`;
    case "kev":
      return `${s("cve")}: ${f.listed ? "listed as actively exploited" : "not on the known-exploited list"}`;
    case "reachability": {
      const hits = Array.isArray(f.hits) ? f.hits.length : 0;
      return `${s("package")}: ${hits ? `imported in ${hits} place${hits === 1 ? "" : "s"}` : "no imports found"} (${s("files_scanned")} files scanned)`;
    }
    case "exposure":
      return `${s("package")}: ${f.imported_in_prod ? "used by production code" : "not used by production code"}${Array.isArray(f.expose) && f.expose.length ? `, service listens on ${[...new Set(f.expose as string[])].join(", ")}` : ""}`;
    case "registry_metadata":
      return f.hooks ? `${s("package")} ${s("version")} declares ${(f.hooks as string[]).join(", ")}` : `${s("repository_url") || s("package") || "Registry record"}`;
    case "provenance":
      return `Provenance ${s("status") || "unknown"}${f.maintainer_changed ? ", maintainer changed" : ""}`;
    case "graph":
      return f.components != null
        ? `${s("components")} packages (${s("direct")} direct, ${s("transitive")} transitive)`
        : f.path || f.paths ? "How this package is reached from the project" : "A slice of the dependency graph";
    case "compat_hint":
      return `${s("from_version")} to ${s("to_version")}: ${s("semver_delta")} change, compatibility risk ${s("level")}`;
    case "patch_diff":
      return `Changes ${(f.files as string[] | undefined)?.join(", ") ?? "files"} in an isolated copy`;
    case "sbom":
      return `${s("unique_purls") || s("components")} components catalogued`;
    case "file_excerpt":
      return ev.excerpt ? ev.excerpt.split("\n")[0].slice(0, 140) : "A quoted line from the repository";
    default: {
      const bits = Object.entries(f)
        .filter(([, v]) => typeof v === "string" || typeof v === "number" || typeof v === "boolean")
        .slice(0, 3)
        .map(([k, v]) => `${k.replace(/_/g, " ")}: ${String(v)}`);
      return bits.join(" · ") || ev.excerpt?.split("\n")[0]?.slice(0, 140) || "";
    }
  }
}

// ------------------------------------------------------------------ pipeline

export const STEP_DOING: Record<string, string> = {
  discovery: "Mapping everything the project depends on",
  detection: "Scanning for vulnerabilities and suspicious packages",
  evidence_analyst: "Collecting and checking the evidence",
  investigator: "Investigating the riskiest findings",
  risk_analyst: "Scoring how risky each finding is",
  remediation: "Planning a safe fix",
  human_gate: "Waiting for your approval",
  validator: "Testing the fix in a sandbox",
  reporter: "Writing the report",
};

export const LLM_NAME = (model: string | null | undefined): string => {
  if (!model) return "AI model";
  if (/deepseek/i.test(model)) return "DeepSeek";
  if (/claude/i.test(model)) return "Claude";
  if (/gpt|openai/i.test(model)) return "OpenAI";
  return model;
};

export function llmMode(mode: string | null | undefined): { word: string; help: string } {
  switch (mode) {
    case "replay":
      return { word: "replay", help: "AI answers are replayed from a previous recorded run. No new model calls were made." };
    case "record":
      return { word: "live", help: "The AI model was called live, and its answers are recorded so this run can be replayed later." };
    case "live":
      return { word: "live", help: "The AI model was called live for this run." };
    default:
      return { word: mode ?? "off", help: "No AI model was used." };
  }
}
