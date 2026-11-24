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
  remediation?: RemediationEntry[];
  pending_plan?: PendingPlan | null;
  /** batch mode: the group of fixes waiting for decisions */
  pending_batch?: { batch_id: string; round: number; count: number } | null;
}

export interface RemediationEntry {
  finding_id: string;
  title?: string;
  category?: string;
  status?: string;
  attempts: { plan_id: string; action?: string; target?: string; verdict?: string; attempt_id?: string }[];
}

export interface PendingPlan {
  plan_id: string;
  plan_hash: string;
  finding_id?: string;
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

export interface FactorValue {
  value: number;
  tier: string;
  unknown: boolean;
  label: ClaimLabel;
  evidence_ids: string[];
}

export interface RiskFactors {
  S: FactorValue;
  E: FactorValue;
  R: FactorValue;
  P: FactorValue;
  X: FactorValue;
  provenance_modifier: number;
  provenance_evidence_ids: string[];
}

export interface RiskAssessment {
  finding_id: string;
  score: number;
  band: Risk;
  confidence: "high" | "medium" | "low";
  override_applied: string | null;
  factors: RiskFactors;
  summary: string;
  claims: Claim[];
}

export interface PatchOp {
  op: string;
  file_path: string;
  args: Record<string, unknown>;
}

export interface RemediationPlan {
  plan_id: string;
  plan_hash: string;
  finding_id: string;
  attempt: number;
  action: string;
  ops: PatchOp[];
  target_version: string | null;
  rationale: Claim[];
  expected_risk_reduction: string;
  compatibility_impact: {
    from_version: string;
    to_version: string;
    semver_delta: string;
    engines_ok: boolean | null;
    peer_dep_changes: string[];
    deprecated_target: boolean | null;
    level: string;
  } | null;
  rollback: string;
  evidence_ids: string[];
}

export interface Approval {
  plan_id: string;
  plan_hash: string;
  decision: "approve" | "reject" | "accept_risk";
  comment: string | null;
  decided_by: string;
  ts: string;
}

export interface ValidationResult {
  attempt_id: string;
  plan_id: string;
  finding_id: string;
  build_ok: boolean | null;
  unit_tests: Record<string, number>;
  integration_tests: Record<string, number>;
  artifact_rescanned: string | null;
  target_finding_resolved: boolean;
  new_findings: string[];
  sbom_diff_evidence_id: string | null;
  detector_evidence_ids: string[];
  risk_before: number;
  risk_after: number;
  verdict: string;
  final_confidence: "high" | "medium" | "low";
  log_evidence_ids: string[];
  /** true when this plan was tested together with the other approved fixes of the round */
  combined?: boolean;
  round?: number | null;
}

export type RecDecision = "approve" | "reject" | "accept_risk";
export type RecOutcome =
  | "awaiting_decision" | "validating" | "verified" | "failed" | "rejected" | "accepted" | "no_alternative" | "needs_person";

export interface RecAlternative {
  action: string;
  target_version: string | null;
  summary: string;
}

export interface Recommendation {
  rec_id: string;
  round: number;
  finding_ids: string[];
  primary_finding_id: string;
  kind: "fix" | "no_alternative";
  plan_id: string | null;
  plan_hash: string | null;
  alternatives: RecAlternative[];
  reason: string | null;
  previous: { plan_id: string; outcome: "failed" | "rejected"; detail: string; reason_type?: string | null } | null;
  decision: RecDecision | null;
  outcome: RecOutcome;
  steer_note?: string | null;
  steer_source?: "llm" | "rules" | null;
}

export interface RecommendationsFile {
  round: number;
  /** one-at-a-time debugging: increases with every submitted step */
  step?: number;
  status: "awaiting_decisions" | "validating" | "done";
  batch_id: string | null;
  items: Recommendation[];
}

export interface ReportJson {
  run_id: string;
  target: string;
  commit: string | null;
  generated_at: string;
  inventory: { components: number; direct: number; transitive: number };
  ranking: string[];
  remaining_risk: { finding_id: string; status: string; score: number }[];
  final_confidence: string;
  audit: { events: number; llm_calls: number; tool_calls: number };
  guardrail_events: AgentEvent[];
  actions: { plan: RemediationPlan; approval: Approval | null; validations: ValidationResult[] }[];
}

export interface RunListItem {
  id: string;
  target: string;
  status: string;
  mode: string | null;
  commit: string | null;
}

export type SourceKind = "api" | "static" | "sample";

export interface RunData {
  runId: string;
  summary: RunSummary;
  graph: GraphData;
  findings: Finding[];
  changes: Changes | null;
  risk: RiskAssessment[];
  plans: RemediationPlan[];
  validation: ValidationResult[];
  approvals: Approval[];
  /** batch-mode recommendations; null for sequential runs */
  recommendations: RecommendationsFile | null;
}
