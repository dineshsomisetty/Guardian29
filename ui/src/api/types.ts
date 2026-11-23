// Mirrors GUARDIAN_PLAN.md §4.1 file formats and §5.1 models (Python: guardian/core/models.py).

export type Risk = "critical" | "high" | "medium" | "low";
export type ClaimLabel = "verified" | "inferred" | "unsupported";
export type Scope = "prod" | "dev" | "unknown";

export interface RunSummary {
  run_id: string;
  target: string;
  commit: string | null;
  started_at: string;
  finished_at?: string;
  status: string;
  sbom: { file: string | null; components: number | null; direct: number | null; transitive: number | null };
  projects: string[];
  findings: { total: number; by_risk: Record<Risk, number>; by_category: Record<string, number> };
  llm: { mode: string; model: string | null };
  offline: boolean;
}

export type NodeKind = "package" | "project" | "ci" | "image" | "config";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  version?: string;
  ecosystem?: string;
  direct?: boolean | null;
  scope?: Scope;
  project?: string;
  projects?: string[];
  origin?: string | null;
  integrity?: string | null;
  deprecated?: boolean;
  has_install_script?: boolean;
  risk?: Risk | null;
  finding_ids?: string[];
}

export interface GraphEdge {
  source: string;
  target: string;
  type?: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  roots: string[];
}

export interface Claim {
  text: string;
  field: string | null;
  value: string | null;
  evidence_ids: string[];
  label: ClaimLabel;
}

export interface Finding {
  finding_id: string;
  run_id: string;
  category: string;
  title: string;
  detector: string;
  component_purl: string | null;
  scope: Scope;
  project: string | null;
  file_path: string | null;
  line: number | null;
  dependency_paths: string[][];
  vuln_id: string | null;
  aliases: string[];
  cvss: number | null;
  severity: string | null;
  fixed_versions: string[];
  affected_range: string | null;
  initial_risk: Risk | null;
  initial_risk_source: "llm" | "rule" | null;
  evidence_ids: string[];
  status: string;
  explanation: string | null;
  claims: Claim[];
}

export interface Evidence {
  evidence_id: string;
  run_id: string;
  kind: string;
  source_tool: string;
  created_at: string;
  facts: Record<string, unknown>;
  excerpt: string | null;
  file_path: string | null;
  line: number | null;
  artifact_path: string | null;
  sha256: string | null;
}

export interface Changes {
  base: string;
  head: string;
  added: string[];
  removed: string[];
  changed: { name: string; from: string; to: string; from_range?: string; to_range?: string; major_jump: boolean }[];
  integrity_changed: { purl: string; from: string; to: string }[];
  install_scripts_added: string[];
  evidence_ids: string[];
}

export interface AgentEvent {
  ts: string;
  run_id: string;
  agent: string;
  type: string;
  summary: string;
  finding_id: string | null;
  evidence_ids: string[];
  data: Record<string, unknown>;
}

export interface RunData {
  base: string;
  summary: RunSummary;
  graph: GraphData;
  findings: Finding[];
  changes: Changes | null;
  trace: AgentEvent[];
}
