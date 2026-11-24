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
  provenance_gap: "Provenance gap",
  policy_violation: "Policy violation",
  maintainer_change: "Maintainer or release change",
  dependency_confusion: "Dependency confusion",
  malicious_indicator: "Malicious indicator",
  integrity_change: "Integrity change",
  major_jump: "Major version jump",
  outdated: "Outdated package",
};

export const CATEGORY_SHORT: Record<string, string> = {
  cve: "Vulnerability",
  typosquat: "Typosquat",
  install_script: "Install script",
  unpinned_ci: "Unpinned CI",
  untrusted_image: "Tag-only image",
  lockfile: "No lockfile",
  unexpected_change: "Unexpected change",
  provenance_gap: "Provenance gap",
  policy_violation: "Policy",
  maintainer_change: "Maintainer change",
  dependency_confusion: "Dep. confusion",
  malicious_indicator: "Malicious",
  integrity_change: "Integrity change",
  major_jump: "Major jump",
  outdated: "Outdated",
};

export const CATEGORY_WHY: Record<string, string> = {
  cve: "A published security flaw in a package you depend on.",
  typosquat: "A package name that imitates a popular one. Attackers use these to slip in malicious code.",
  install_script: "A dependency that runs code on your machine the moment it is installed.",
  unpinned_ci: "A build step that can change without review because it is not locked to a fixed commit.",
  untrusted_image: "A container base image referenced by a movable tag, so what you build can change silently.",
  lockfile: "Without a lockfile, installs can silently pull different (or tampered) versions.",
  unexpected_change: "A dependency changed in a way that does not match the surrounding history.",
  provenance_gap: "We cannot confirm where this package came from or who built it, so a tampered release would look the same.",
  policy_violation: "Breaks one of your own rules in guardian.yaml, such as unpinned actions or a denylisted package.",
  maintainer_change: "Who publishes this package, or how often it is released, changed recently. Account takeovers often look like this.",
  dependency_confusion: "A public package uses the name of one of your internal packages, so installs could fetch the attacker's copy.",
  malicious_indicator: "The package shows signs of deliberately harmful behaviour.",
  integrity_change: "The same version now has a different checksum, which means its contents changed after release.",
  major_jump: "A dependency jumped a major version without an explanation, which can break code or hide a takeover.",
  outdated: "The package is deprecated or far behind its latest release, so fixes no longer reach you.",
};

const humanize = (s: string) => {
  const t = s.replace(/[_-]+/g, " ").trim();
  return t.charAt(0).toUpperCase() + t.slice(1);
};

export const categoryLabel = (c: string) => CATEGORY_LABEL[c] ?? humanize(c);
export const categoryShort = (c: string) => CATEGORY_SHORT[c] ?? humanize(c);

export const BAND_COPY: Record<Risk, { name: string; line: string; adj: string }> = {
  critical: { name: "Critical", adj: "critical", line: "Fix first: severe and exposed in your project." },
  high: { name: "High", adj: "high-risk", line: "Fix soon: serious, but less exposed or less likely to be exploited than Critical." },
  medium: { name: "Medium", adj: "medium-risk", line: "Fix in normal maintenance: real, but harder to exploit here." },
  low: { name: "Low", adj: "low-risk", line: "Track it: little practical impact today." },
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
  S: { name: "Severity", weight: 0.4, help: "How damaging the flaw is on paper (CVSS score from the advisory)." },
  E: { name: "Exploitability", weight: 0.15, help: "How likely attackers are to use it: exploit probability (EPSS) and the known-exploited list (KEV)." },
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
  called: "The vulnerable function is called by application code",
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

/**
 * Score range (inclusive) of each level. Mirrors guardian/core/scoring.py band(); the UI only reads the level
 * the backend already chose, these ranges are for display (scale, 'High is 60 to 79').
 */
export const BAND_RANGE: Record<Risk, [number, number]> = { low: [0, 39], medium: [40, 59], high: [60, 79], critical: [80, 100] };
export const BAND_ORDER: Risk[] = ["low", "medium", "high", "critical"];

/**
 * The factor weights the backend actually used. A finding with no package code to reach (CI action, lockfile,
 * image) has Reachability 'not_applicable', and its weight moves onto Severity so the maximum is still 100
 * points. The table and bar must use these, not FACTOR_INFO's defaults.
 */
export function weightsFor(risk: RiskAssessment): Record<FactorKey, number> {
  const w = Object.fromEntries(FACTOR_KEYS.map((k) => [k, FACTOR_INFO[k].weight])) as Record<FactorKey, number>;
  if (risk.factors.R.tier === "not_applicable") {
    w.S += w.R;
    w.R = 0;
  }
  return w;
}

/** What Guardian found for one factor, in plain words. */
export function factorFinding(key: FactorKey, risk: RiskAssessment, f: Finding | undefined): string {
  const v = risk.factors[key];
  if (v.tier === "not_applicable") return "Does not apply: there is no package code to reach";
  if (v.unknown) return "Could not be checked, so the middle value was used";
  const pct = Math.round(v.value * 100);
  switch (key) {
    case "S":
      if (v.tier === "cvss" && f?.cvss != null) return `CVSS ${f.cvss.toFixed(1)} from the published advisory`;
      // Only CVEs have a CVSS score; other kinds of issue get a fixed severity weight.
      if (f && f.category !== "cve") return `Fixed weight for this kind of issue (${categoryShort(f.category)})`;
      return tierLabel(v.tier);
    case "E":
      if (v.tier === "kev") return "On the list of flaws attackers are actively using (CISA KEV)";
      if (v.tier === "epss") return `More likely to be exploited than ${pct}% of known flaws (EPSS)`;
      return tierLabel(v.tier);
    case "R":
      if (v.tier === "not_imported") return "Your code never imports this package";
      if (v.tier === "imported") return "Your code imports it, but the vulnerable function was not seen being called";
      if (v.tier === "called") return "Your code calls the vulnerable function";
      return tierLabel(v.tier);
    case "P":
      return v.tier === "dev" ? "Only used while developing, not shipped" : v.tier === "prod" ? "Ships to production" : tierLabel(v.tier);
    case "X":
      return v.tier === "network" ? "The running service is reachable over the network" : v.tier === "local" || v.tier === "internal" ? "Only reachable from inside" : tierLabel(v.tier);
  }
}

/**
 * The level the advisory alone would give (standard CVSS cut-offs 9 / 7 / 4, else its severity word), before
 * Guardian considers your project. Null for non-CVE findings, which have no advisory. This is NOT the level
 * shown to the user, which is Guardian's own score.
 */
export function advisoryBand(f: Finding): Risk | null {
  if (f.category !== "cve") return null;
  if (f.cvss != null) return f.cvss >= 9 ? "critical" : f.cvss >= 7 ? "high" : f.cvss >= 4 ? "medium" : "low";
  const s = (f.severity ?? "").toLowerCase();
  return s === "critical" || s === "high" || s === "medium" || s === "low" ? s : s === "moderate" ? "medium" : null;
}

// Join words as 'a, b and c'.
const joinWords = (xs: string[]) => (xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

/**
 * One or two sentences reconciling Guardian's level with the advisory's own rating, built only from the factors
 * (no model text), so the reader sees why a Critical advisory can be a High risk here, or the other way round.
 * The level shown everywhere is Guardian's; the advisory's appears only in this explanation.
 */
export function scoreExplainer(f: Finding, risk: RiskAssessment): string {
  const band = risk.band;
  const name = BAND_COPY[band].name;
  const fx = risk.factors;
  const adv = advisoryBand(f);
  const advText = f.cvss != null ? `${BAND_COPY[adv ?? band].name}, CVSS ${f.cvss.toFixed(1)}` : adv ? BAND_COPY[adv].name : "";
  const unknown = FACTOR_KEYS.filter((k) => fx[k].unknown).map((k) => FACTOR_INFO[k].name.toLowerCase());
  const unknownNote = unknown.length ? ` ${joinWords(unknown).replace(/^./, (c) => c.toUpperCase())} could not be checked, so a middle value was used.` : "";
  const override = risk.override_applied ? " A safety rule also raised it, because the flaw is actively exploited and reachable in production." : "";
  if (!adv) return `${name} because of the kind of issue it is and how it reaches your project. There is no published advisory score for it.${unknownNote}${override}`;
  if (adv === band) return `${name}, the same as the advisory's own rating (${advText}). Your project's context neither raises nor lowers it.${unknownNote}${override}`;
  // lower: Guardian ranks it below the advisory. Then the reasons name what pulled it down (not imported, dev
  // only, unlikely to be exploited, not exposed); otherwise what pushed it up.
  const lower = BAND_ORDER.indexOf(band) < BAND_ORDER.indexOf(adv);
  const reasons: string[] = [];
  if (lower) {
    if (fx.R.tier === "not_imported") reasons.push("your code never imports the package");
    else if (fx.R.tier === "imported") reasons.push("your code imports the package but was not seen calling the vulnerable function");
    if (fx.P.tier === "dev") reasons.push("it is only used while developing");
    if (!fx.E.unknown && fx.E.value < 0.3) reasons.push("attackers are unlikely to exploit it");
    if (fx.X.tier === "local" || fx.X.tier === "internal") reasons.push("the service is not reachable from outside");
  } else {
    if (fx.R.tier === "called") reasons.push("your code calls the vulnerable function");
    if (fx.P.tier === "prod") reasons.push("it ships to production");
    if (fx.X.tier === "network") reasons.push("the service is reachable over the network");
    if (fx.E.tier === "kev") reasons.push("attackers are actively using it");
    else if (!fx.E.unknown && fx.E.value >= 0.8) reasons.push("it is more likely to be exploited than most flaws");
  }
  const why = reasons.length ? joinWords(reasons) : "the other four factors pull the score " + (lower ? "down" : "up");
  return `The advisory rates it ${advText}. Guardian ranks it ${lower ? "lower" : "higher"}, ${name}, because ${why}.${unknownNote}${override}`;
}

/**
 * True for the risk analyst's machine summary ('... Factors: S=0.92 (cvss) ...'), which is for logs, not
 * people, so it is never shown as the explanation.
 */
export const isMachineSummary = (s: string | null | undefined) => !!s && /Factors:\s*S=/.test(s);

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

// ------------------------------------------------------------------ statuses and verdicts in plain words

/** Run and finding statuses as the backend writes them (models.FindingStatus, run_summary.status). */
const STATUS_TEXT: Record<string, string> = {
  open: "Open",
  assessed: "Assessed",
  planned: "Fix planned",
  awaiting_human: "Awaiting your approval",
  validating: "Being validated",
  verified: "Fixed and verified",
  accepted: "Risk accepted",
  escalated: "Escalated for security review",
  below_threshold: "Below the risk threshold",
  running: "Running",
  done: "Finished",
  failed: "Stopped with an error",
};

export const statusText = (s: string | null | undefined) =>
  s ? STATUS_TEXT[s] ?? s.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()) : "Unknown";

/** Validation verdicts (models.ValidationResult.verdict), phrased as what went wrong. */
const VERDICT_FAIL: Record<string, string> = {
  failed_build: "the build failed",
  failed_tests: "tests that passed before the fix now fail",
  regressed: "the fix introduced new vulnerabilities or packages",
  not_resolved: "the vulnerability was still there after the fix",
  timeout: "a sandbox step ran out of time",
  still_imported: "the package is still imported by the source code",
};

export const verdictFail = (v: string) => VERDICT_FAIL[v] ?? v.replace(/_/g, " ");

/** Neutral wording for a result that is only the shared failure of a group run: nobody was blamed for it yet. */
export const GROUP_FAILED = "Tested only as part of a group that failed";

/** One line for a non-verified result: the blame is only placed when this fix was isolated (or failed pre-flight). */
export const failLine = (v: { verdict: string; reason?: string | null; group_failure?: boolean }) =>
  v.group_failure ? GROUP_FAILED : `Failed: ${v.reason || verdictFail(v.verdict)}`;
