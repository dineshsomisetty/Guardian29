# Day 2 contracts (supervisor-owned)

Frozen CP1 contracts are unchanged: `guardian/core/models.py` (additive fields only, marked `# ADDITIVE`),
`sbom.cdx.json`, `graph.json`, `findings.json`, `evidence/*.json`, `trace.jsonl`, `run_summary.json`.
Everything below is **additive**. Backend and UI both build against this file.

## Graph (9 agent nodes + 1 router)

```
discovery -> detection -> evidence_analyst -> investigator -> risk_analyst
  -> [ remediation -> human_gate -> record_decision -> validator ]* -> reporter
```

* `human_gate` contains only `interrupt()`. `record_decision` is a pure router that checks the Approval
  again (G5.1/G5.2) and is not an agent; the UI pipeline strip shows 9 agent nodes and folds
  `record_decision` into `human_gate`.
* The validator is reachable only from `record_decision` with route `validate`, which needs an `approve`
  Approval matching both `plan_id` and `plan_hash`.
* 3 attempts per finding, then `escalated` (G5.4).

## Trace (`trace.jsonl`, `AgentEvent`)

`agent` is one of `discovery|detection|evidence_analyst|investigator|risk_analyst|remediation|human_gate|
validator|reporter|supervisor|guardrail`. Types: `agent_start|tool_call|tool_result|llm_call|llm_result|
handoff|decision|guardrail|gate_wait|gate_resume|agent_end|error`. `decision` events are the D1..Dn markers.
`guardrail` events carry `data.rule` (e.g. `G3.1`).

## New run files

| File | Shape | Writer |
|---|---|---|
| `risk.json` | `list[RiskAssessment]` (models.py) for every scored finding | risk_analyst |
| `plans/<plan_id>.json` | `RemediationPlan`; its `evidence_ids` include one `patch_diff` Evidence whose `excerpt` is the unified diff | remediation |
| `pending_plan.json` | `{plan_id, plan_hash, finding_id}` while paused | remediation |
| `approvals.jsonl` | one `Approval` per line | record_decision |
| `validation/<attempt_id>.json` | `ValidationResult`; `log_evidence_ids` point at `build_log` / `test_result` Evidence (`excerpt` = log tail); `sbom_diff_evidence_id` points at `sbom_diff` Evidence | validator |
| `sbom.after.cdx.json` | Syft SBOM of the patched copy (last attempt) | validator |
| `report.json` | see below | reporter |
| `report.html` | Jinja2 render of `report.json` | reporter |

### `sbom_diff` Evidence facts

```json
{"added": ["pkg:npm/a@1.0.0"], "removed": ["pkg:npm/b@2.0.0"],
 "changed": [{"name": "c", "from": "1.0.0", "to": "2.0.0"}],
 "components_before": 1523, "components_after": 1521}
```

### Investigator output

The investigator appends `Claim`s (label set by grounding code) to `Finding.claims` and Evidence of kinds
`registry_metadata`, `file_excerpt`, `diff`; its conclusion is one `Claim` whose `text` starts with
`Conclusion:` and whose label is `verified` or `inferred`.

### `report.json`

```json
{"run_id": "...", "target": "...", "commit": "...", "generated_at": "...",
 "summary": {...run_summary...},
 "inventory": {"components": 0, "direct": 0, "transitive": 0},
 "findings": [{"finding": {...Finding...}, "risk": {...RiskAssessment...} | null,
               "evidence": [{...Evidence (excerpt truncated to 2000 chars)...}],
               "paths": [["root", "...", "purl"]]}],
 "ranking": ["fd_..."],
 "actions": [{"plan": {...RemediationPlan...}, "approval": {...Approval...} | null,
              "validations": [{...ValidationResult...}]}],
 "remaining_risk": [{"finding_id": "...", "status": "accepted|escalated|assessed|...", "score": 0}],
 "final_confidence": "high|medium|low",
 "guardrail_events": [{...AgentEvent...}],
 "audit": {"events": 0, "llm_calls": 0, "tool_calls": 0}}
```

## API (additive to §4.4)

* `GET /runs/{id}/risk` -> `risk.json` (`[]` if missing)
* `GET /runs/{id}/report.json`, `GET /runs/{id}/report.html`
* Existing: `/runs`, `/runs/{id}`, `/summary`, `/graph`, `/changes`, `/findings`, `/findings/{fid}`,
  `/evidence/{eid}`, `/plans`, `/plans/{pid}`, `/validation`, `/approvals`, `POST .../decision`
  `{plan_hash, decision, comment, decided_by}`, `GET /events` (SSE, `id:` = line index, `data:` = AgentEvent).
