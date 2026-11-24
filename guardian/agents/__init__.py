"""Guardian agents, in pipeline order. Each module exposes one or more LangGraph node functions.

The graph itself (nodes, routing, interrupts) is wired in guardian/graph/workflow.py; agents never call each other,
they only read and write the shared run state, the evidence/finding store and the files under runs/<run_id>/.

  1. discovery        Deterministic tool agent. Prepares an isolated work copy, resolves lockfiles, generates the
                      SBOM and builds the dependency graph. No LLM.
                      Writes: work/ (copy), sbom.cdx.json, evidence kinds `sbom` and `graph`.
  2. detection        Deterministic tool agent. Runs Grype/OSV and the detectors (lockfile, typosquat, CI/image
                      pinning, install scripts, unexpected changes, package risk, policy), dedupes CVEs and adds
                      dependency paths. No LLM. Writes: findings.json and the scanner/detector evidence/*.json.
  3. evidence_analyst LLM agent. Explains each finding and gives an initial risk; every claim is grounded against
                      evidence (VERIFIED / INFERRED set by code). Over budget or without an LLM it falls back to a
                      rule. Writes: findings.json updates (explanation, claims, initial_risk), no new evidence.
  4. investigator     LLM agent (bounded ReAct loop, 8 tool calls per run) for non-CVE heuristic findings: looks
                      things up with read-only tools and adds a grounded "Conclusion:" claim. Deterministic plan
                      without an LLM. Writes: findings.json updates and evidence (registry_metadata, file_excerpt,
                      diff).
  5. risk_analyst     Scores findings in code (S, E, R, P, X factors + provenance); the LLM only writes the summary
                      text. Chooses what to remediate. Writes: risk.json and evidence (epss, kev, reachability,
                      exposure, scope, provenance).

  Then, depending on GUARDIAN_BATCH_REMEDIATION / settings.remediation_mode:

  Sequential loop (one finding at a time, repeated until the queue is empty):
  6a. remediation     Builds one concrete, evidence-backed fix plan for the current finding, hash-bound for approval
                      (deterministic candidates; an LLM may pick between them). Writes: plans/<plan_id>.json,
                      pending_plan.json, evidence for the upgrade candidates.
  7a. human_gate      Pauses the graph (interrupt) until a person approves, rejects or modifies the plan; the decision
                      is re-checked in code. Writes: approvals.jsonl (append-only), clears pending_plan.json.
  8a. validator       Applies the approved plan to a fresh copy and re-runs the detectors (and the Docker sandbox
                      when available); verdict verified / regressed / not_resolved / failed_*. No LLM.
                      Writes: validation/<attempt_id>.json, the patched attempt copy (PR.md, local branch).

  Batch mode (every finding gets a recommendation; one human decision round):
  6b. batch recommend Groups findings and proposes a fix (or "no alternative" with the reason) for each; built from the
                      remediation candidates and code, not free LLM text.
                      Writes: recommendations.json, pending_batch.json, plans/*.json.
  7b. batch_gate      Pauses until the human decides every item; record_batch re-checks and stores the decisions.
                      Writes: approvals.jsonl.
  8b. validator       validate_batch applies the approved fixes together and re-runs detectors; failed or rejected
                      items return to recommend for the next alternative (max 3 attempts per item).
                      Writes: validation/<attempt_id>.<plan_id>.json.

  9. reporter         Read-only summary of what happened per finding. No LLM. Writes: report.json, report.html and
                      the per-finding outcome lines in trace.jsonl (the run driver adds run_summary.json).

Cross-cutting: every agent writes events to trace.jsonl and audit.jsonl (via core/audit.py), calls tools only through
tools/registry.call_tool (allowlist, typed args, budgets), and passes any LLM input as untrusted <data>.
"""
