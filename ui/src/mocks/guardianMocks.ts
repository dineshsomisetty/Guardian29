import type {
  AgentEvent,
  Changes,
  Evidence,
  Finding,
  GraphData,
  Priority,
  RemediationPlan,
  RunSummary,
  ValidationResult,
} from "../api/types";

export const summaryMock: RunSummary = {
  run_id: "run_20261123_1630",
  target: "juice-shop",
  commit: "a41f2bc",
  started_at: "2026-11-23T16:00:00+05:30",
  status: "done",
  sbom: { file: "sbom.cdx.json", components: 1523, direct: 112, transitive: 1411 },
  projects: ["root", "frontend"],
  findings: {
    total: 87,
    by_risk: { critical: 2, high: 9, medium: 30, low: 46 },
    by_category: { cve: 80, lockfile: 1, unpinned_ci: 1, untrusted_image: 2, typosquat: 1, unexpected_change: 2 },
  },
  llm: { mode: "live", model: "demo-model" },
  offline: false,
};

const packageNames = ["express", "lodash", "jsonwebtoken", "sanitize-html", "body-parser", "axios", "marked", "mime"];
const generatedNodes = Array.from({ length: 1000 }, (_, index) => {
  const name = index < packageNames.length ? packageNames[index] : `package-${index}`;
  const risk: Priority = index === 0 ? "high" : index === 8 ? "medium" : "low";
  return {
    id: `pkg:npm/${name}@${1 + (index % 4)}.${index % 20}.0`,
    kind: "package" as const,
    label: name,
    version: `${1 + (index % 4)}.${index % 20}.0`,
    ecosystem: "npm",
    direct: index < 112,
    scope: index % 5 === 0 ? "dev" as const : "prod" as const,
    project: index % 3 === 0 ? "frontend" : "root",
    origin: "https://registry.npmjs.org",
    integrity: `sha512-mock-${index}`,
    deprecated: false,
    risk,
    finding_ids: index === 0 ? ["fd_jsonwebtoken"] : index === 8 ? ["fd_ci_pin"] : [],
  };
});

export const graphMock: GraphData = {
  roots: ["root", "frontend"],
  nodes: [
    { id: "root", kind: "root", label: "Juice Shop", risk: "low", finding_ids: [] },
    { id: "frontend", kind: "root", label: "Frontend", risk: "low", finding_ids: [] },
    ...generatedNodes,
    { id: "ci:.github/workflows/ci.yml", kind: "ci", label: "ci.yml", risk: "medium", finding_ids: ["fd_ci_pin"] },
    { id: "image:node:24", kind: "image", label: "node:24", risk: "medium", finding_ids: ["fd_image_pin"] },
    { id: "config:.npmrc", kind: "config", label: ".npmrc", risk: "medium", finding_ids: ["fd_lockfile"] },
  ],
  edges: [
    { source: "root", target: generatedNodes[0].id, type: "depends" },
    { source: "frontend", target: generatedNodes[1].id, type: "depends" },
    ...Array.from({ length: 998 }, (_, index) => ({
      source: generatedNodes[index].id,
      target: generatedNodes[index + 1].id,
      type: "depends",
    })),
  ],
};

export const findingsMock: Finding[] = [
  {
    finding_id: "fd_jsonwebtoken", run_id: "run_20261123_1630", category: "cve", title: "jsonwebtoken 0.4.0 vulnerable",
    detector: "grype", component_purl: "pkg:npm/jsonwebtoken@0.4.0", scope: "prod", project: "root",
    dependency_paths: [["root", "pkg:npm/express-jwt@0.1.3", "pkg:npm/jsonwebtoken@0.4.0"]],
    vuln_id: "CVE-2022-23529", aliases: ["GHSA-27h2-hvpr-p74q"], cvss: 9.8, severity: "critical",
    fixed_versions: ["9.0.2"], affected_range: "<9.0.2", initial_risk: "critical",
    evidence_ids: ["ev_scanner_001", "ev_graph_001"], status: "open",
  },
  {
    finding_id: "fd_ci_pin", run_id: "run_20261123_1630", category: "unpinned_ci",
    title: "GitHub Action uses a mutable tag", detector: "ci_pin",
    scope: "unknown", project: "root", file_path: ".github/workflows/ci.yml", line: 18,
    dependency_paths: [["ci:.github/workflows/ci.yml"]],
    aliases: [], fixed_versions: [], initial_risk: "medium",
    evidence_ids: ["ev_ci_001"], status: "open",
  },
];

export const changesMock: Changes = {
  base: "ftp/package.json.bak",
  head: "package.json",
  added: ["pkg:npm/foo@1.0.0"],
  removed: ["pkg:npm/bar@2.0.0"],
  changed: [{ name: "baz", from: "1.2.0", to: "3.0.0", major_jump: true }],
  integrity_changed: [{ purl: "pkg:npm/qux@1.0.0", from: "sha512-A", to: "sha512-B" }],
  install_scripts_added: [],
  evidence_ids: ["ev_diff_001"],
};

export const traceMock: AgentEvent[] = [
  { ts: "2026-11-23T16:00:01Z", run_id: "run_20261123_1630", agent: "supervisor", type: "decision", summary: "Routed discovery because a new run started", evidence_ids: [], data: {} },
  { ts: "2026-11-23T16:00:02Z", run_id: "run_20261123_1630", agent: "discovery", type: "handoff", summary: "Passed SBOM and dependency graph", evidence_ids: ["ev_graph_001"], data: {} },
  { ts: "2026-11-23T16:00:08Z", run_id: "run_20261123_1630", agent: "detection", type: "tool_result", summary: "Grype found 87 findings", evidence_ids: ["ev_scanner_001"], data: {} },
  { ts: "2026-11-23T16:00:10Z", run_id: "run_20261123_1630", agent: "evidence_analyst", type: "llm_result", summary: "Produced grounded initial-risk claims", evidence_ids: ["ev_scanner_001", "ev_graph_001"], data: {} },
];

export const evidenceMock: Record<string, Evidence> = {
  ev_scanner_001: {
    evidence_id: "ev_scanner_001",
    run_id: summaryMock.run_id,
    kind: "scanner_output",
    source_tool: "grype@demo",
    created_at: summaryMock.started_at,
    facts: { vuln_id: "CVE-2022-23529", cvss: 9.8, component_purl: "pkg:npm/jsonwebtoken@0.4.0" },
    excerpt: "Scanner identified an affected jsonwebtoken release.",
  },
  ev_graph_001: {
    evidence_id: "ev_graph_001",
    run_id: summaryMock.run_id,
    kind: "graph",
    source_tool: "guardian.graph",
    created_at: summaryMock.started_at,
    facts: { dependency_path: ["root", "express-jwt@0.1.3", "jsonwebtoken@0.4.0"] },
  },
  ev_ci_001: {
    evidence_id: "ev_ci_001",
    run_id: summaryMock.run_id,
    kind: "detector_result",
    source_tool: "detector:ci_pin",
    created_at: summaryMock.started_at,
    facts: { file_path: ".github/workflows/ci.yml", line: 18, pinned: false },
    excerpt: "Action reference uses a mutable tag.",
  },
};

export const plansMock: RemediationPlan[] = [
  {
    plan_id: "plan_jsonwebtoken_01",
    plan_hash: "demo-plan-hash-01",
    finding_id: "fd_jsonwebtoken",
    attempt: 1,
    action: "upgrade",
    target_version: "9.0.2",
    rationale: [{
      text: "Upgrade to the lowest fixed version supported by scanner evidence.",
      field: "fixed_version",
      value: "9.0.2",
      evidence_ids: ["ev_scanner_001"],
      label: "verified",
    }],
    expected_risk_reduction: "Target finding resolved; rescan required.",
    compatibility_impact: {
      from_version: "0.4.0",
      to_version: "9.0.2",
      semver_delta: "major",
      engines_ok: true,
      peer_dep_changes: [],
      level: "high",
    },
    rollback: "Revert the local Guardian patch branch.",
    evidence_ids: ["ev_scanner_001"],
  },
];

export const validationMock: ValidationResult[] = [
  {
    attempt_id: "attempt_01",
    plan_id: "plan_jsonwebtoken_01",
    finding_id: "fd_jsonwebtoken",
    build_ok: false,
    unit_tests: { passed: 42, failed: 1, skipped: 0 },
    integration_tests: { passed: 0, failed: 0, skipped: 4 },
    target_finding_resolved: false,
    new_findings: [],
    detector_evidence_ids: [],
    risk_before: 92,
    risk_after: 92,
    verdict: "failed_tests",
    final_confidence: "high",
    log_evidence_ids: ["ev_scanner_001"],
  },
  {
    attempt_id: "attempt_02",
    plan_id: "plan_jsonwebtoken_01",
    finding_id: "fd_jsonwebtoken",
    build_ok: true,
    unit_tests: { passed: 43, failed: 0, skipped: 0 },
    integration_tests: { passed: 4, failed: 0, skipped: 0 },
    artifact_rescanned: "guardian:validated",
    target_finding_resolved: true,
    new_findings: [],
    detector_evidence_ids: ["ev_scanner_001"],
    risk_before: 92,
    risk_after: 0,
    verdict: "verified",
    final_confidence: "high",
    log_evidence_ids: ["ev_scanner_001"],
  },
];
