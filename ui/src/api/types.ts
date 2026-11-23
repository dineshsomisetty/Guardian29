export type Priority = "critical" | "high" | "medium" | "low";
export type ClaimLabel = "verified" | "inferred" | "unsupported";

export interface RunSummary {
  run_id: string;
  target: string;
  commit: string;
  started_at: string;
  status: "created" | "discovering" | "detecting" | "analysing" | "planning_loop" | "reporting" | "done" | "failed";
  sbom: { file: string; components: number; direct: number; transitive: number };
  projects: string[];
  findings: {
    total: number;
    by_risk: Record<Priority, number>;
    by_category: Record<string, number>;
  };
  llm: { mode: "live" | "record" | "replay"; model: string };
  offline: boolean;
}

export interface GraphNode {
  id: string;
  kind: "package" | "ci" | "image" | "config" | "root";
  label: string;
  version?: string;
  ecosystem?: string;
  direct?: boolean;
  scope?: "prod" | "dev" | "unknown";
  project?: string;
  origin?: string;
  integrity?: string;
  deprecated?: boolean;
  risk: Priority;
  finding_ids: string[];
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

export interface Evidence {
  evidence_id: string;
  run_id: string;
  kind: string;
  source_tool: string;
  created_at: string;
  facts: Record<string, unknown>;
  excerpt?: string;
  file_path?: string;
  line?: number;
  artifact_path?: string;
  sha256?: string;
}

export interface Finding {
  finding_id: string;
  run_id: string;
  category: string;
  title: string;
  detector: string;
  component_purl?: string;
  scope: "prod" | "dev" | "unknown";
  project?: string;
  file_path?: string;
  line?: number;
  dependency_paths: string[][];
  vuln_id?: string;
  aliases: string[];
  cvss?: number;
  severity?: string;
  fixed_versions: string[];
  affected_range?: string;
  provenance?: {
    origin?: string;
    integrity?: string;
    signature_verified?: boolean | null;
    attestation_present?: boolean | null;
    repository_url?: string;
    evidence_ids: string[];
  } | null;
  initial_risk: Priority | null;
  evidence_ids: string[];
  status: string;
}

export interface Claim {
  text: string;
  field?: string | null;
  value?: string | null;
  evidence_ids: string[];
  label: ClaimLabel;
}

export interface CompatHint {
  from_version: string;
  to_version: string;
  semver_delta: string;
  engines_ok?: boolean | null;
  peer_dep_changes: string[];
  deprecated_target?: boolean | null;
  level: string;
}

export interface RemediationPlan {
  plan_id: string;
  plan_hash: string;
  finding_id: string;
  attempt: number;
  action: string;
  target_version?: string | null;
  rationale: Claim[];
  expected_risk_reduction: string;
  compatibility_impact?: CompatHint | null;
  rollback: string;
  evidence_ids: string[];
}

export interface ValidationResult {
  attempt_id: string;
  plan_id: string;
  finding_id: string;
  build_ok: boolean;
  unit_tests: Record<string, number>;
  integration_tests: Record<string, number>;
  artifact_rescanned?: string | null;
  target_finding_resolved: boolean;
  new_findings: string[];
  sbom_diff_evidence_id?: string | null;
  detector_evidence_ids: string[];
  risk_before: number;
  risk_after: number;
  verdict: string;
  final_confidence: string;
  log_evidence_ids: string[];
}

export interface ReportAvailability {
  json_available: boolean;
  html_available: boolean;
}

export interface Changes {
  base: string;
  head: string;
  added: string[];
  removed: string[];
  changed: Array<{ name: string; from: string; to: string; major_jump: boolean }>;
  integrity_changed: Array<{ purl: string; from: string; to: string }>;
  install_scripts_added: string[];
  evidence_ids: string[];
}

export interface AgentEvent {
  ts: string;
  run_id: string;
  agent: string;
  type: string;
  summary: string;
  finding_id?: string;
  evidence_ids: string[];
  data: Record<string, unknown>;
}
