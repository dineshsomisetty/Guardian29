import type { Evidence, Finding, GraphNode } from "../../api/types";

const CATEGORY_NAMES: Record<string, string> = {
  cve: "CVE",
  typosquat: "Typosquat",
  lockfile: "Lockfile",
  unpinned_ci: "Unpinned CI",
  untrusted_image: "Untrusted image",
  integrity_change: "Integrity change",
  dependency_confusion: "Dependency confusion",
  malicious_indicator: "Malicious indicator",
  install_script: "Install script",
  deprecated: "Deprecated",
};

export function categoryName(c: string): string {
  return CATEGORY_NAMES[c] ?? c.replace(/_/g, " ").replace(/^\w/, (m) => m.toUpperCase());
}

/** "grype@0.122.1" -> "grype 0.122.1"; "detector:typosquat" stays (rendered in caps by CSS). */
export function toolName(t: string): string {
  return t.replace("@", " ");
}

/** Short label for a graph node id: "express-jwt@0.1.3" for purls, the id itself for projects. */
export function nodeLabel(id: string, nodes: Map<string, GraphNode>): string {
  const n = nodes.get(id);
  if (n?.kind === "package") return n.version ? `${n.label}@${n.version}` : n.label;
  if (n) return n.label;
  const m = /^pkg:[^/]+\/(.+)$/.exec(id);
  return m ? decodeURIComponent(m[1]) : id;
}

export interface Depth {
  kind: "direct" | "transitive" | "none";
  hops: number;
  paths: number;
}

export function pathDepth(f: Finding): Depth {
  const ps = f.dependency_paths.filter((p) => p.length > 1);
  if (!ps.length) return { kind: "none", hops: 0, paths: 0 };
  const hops = Math.min(...ps.map((p) => p.length - 1));
  return { kind: hops <= 1 ? "direct" : "transitive", hops, paths: ps.length };
}

export function labelCounts(f: Finding) {
  let verified = 0, inferred = 0, rejected = 0;
  for (const c of f.claims) {
    if (c.label === "verified") verified++;
    else if (c.label === "inferred") inferred++;
    else rejected++;
  }
  return { verified, inferred, rejected };
}

export function fileLine(f: { file_path: string | null; line: number | null }): string | null {
  if (!f.file_path) return null;
  return f.line != null ? `${f.file_path}:${f.line}` : f.file_path;
}

export function isAnomaly(f: Finding): boolean {
  return f.category !== "cve";
}

export function factText(v: unknown): string {
  if (v == null) return "null";
  if (Array.isArray(v)) return v.length ? v.map((x) => (typeof x === "object" ? JSON.stringify(x) : String(x))).join(", ") : "[]";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

const KIND_VERB: Record<string, string> = {
  scanner_output: "Collected scanner match",
  osv: "Confirmed advisory match",
  detector_result: "Flagged by detector",
  file_excerpt: "Quoted file contents",
  sbom: "Recorded SBOM component",
  lockfile_entry: "Read lockfile entry",
  registry_metadata: "Read registry metadata",
  diff: "Recorded change against baseline",
};

/** One line describing what a tool did, built only from the evidence record's own facts. */
export function evidenceLine(ev: Evidence): { verb: string; detail: string[] } {
  const verb = KIND_VERB[ev.kind] ?? ev.kind.replace(/_/g, " ").replace(/^\w/, (m) => m.toUpperCase());
  const f = ev.facts ?? {};
  const detail: string[] = [];
  if (typeof f.vuln_id === "string") detail.push(f.vuln_id);
  if (Array.isArray(f.fixed_versions) && f.fixed_versions.length) detail.push(`fixed in ${f.fixed_versions.join(", ")}`);
  else if (f.fix_state === "not-fixed") detail.push("no fix published");
  if (typeof f.reason === "string") detail.push(f.reason);
  const fl = fileLine(ev);
  if (fl && !ev.facts?.purl) detail.push(fl);
  if (!detail.length && ev.excerpt) detail.push(ev.excerpt);
  return { verb, detail };
}
