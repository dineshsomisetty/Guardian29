# Day 1 coverage (branch `dev1/day1-evening`)

Walks `GUARDIAN_PLAN.md` §17.3 (Slide 4, Day 1) row by row, then the Day-1 evening rows of §3.4 for Dev1, Dev2 and
Dev3 that this branch covers. Status: **done** (built and tested), **partial** (built, with a stated gap),
**deferred** (not built here). Test names are in `tests/`; run all with `uv run pytest`.

## 1. Slide 4: Day 1 (§17.3)

| Requirement | Status | Proof |
|---|---|---|
| Analyse manifests and lockfiles | done | `guardian/tools/resolve.py`, `adapters/npm.py`; `tests/integration/test_golden.py::test_summary` |
| Direct and transitive deps; names and versions | done | `graph.json` from `core/graph_build.py`; `tests/unit/test_detectors.py::test_graph_paths_origin_integrity_scope` |
| SBOM (CycloneDX or SPDX) | done | `runs/<id>/sbom.cdx.json` (Syft); `tests/unit/test_sbom_dev_deps.py` |
| Dependency graph | done | `graph.json`, React UI graph view (`ui/`) |
| Where each component originates | done | origin + integrity per node; `tests/integration/test_golden.py::test_path_nodes_have_origin_and_integrity` |
| Inspect at least one container image or CI/CD workflow | partial | CI workflows and Dockerfiles are inspected (`ci_pin`, `image_pin` detectors; `test_detectors_find_cp1_anomalies`). No built-image SBOM/scan (D2-11 deferred) |
| Correlate with known vulnerabilities | done | Grype + OSV cross-check, `guardian/tools/scanners.py`; `tests/integration/test_pipeline.py::test_cp1_pipeline_outputs` |
| Capture CVE, severity, available fix | done | `findings.json` (fix versions, affected range) |
| Trace vulnerable transitive deps to source | done | `paths_to()`; `test_graph_paths_origin_integrity_scope`; golden `test_expected_finding` |
| At least one supply-chain anomaly | done | lockfile, typosquat, unpinned CI, tag-only image, `.bak` diff; this branch adds install-script and compare-ref findings: `tests/unit/test_changes_install.py::test_compare_ref_yields_all_four_finding_kinds` |
| Present evidence: what, component, path, evidence, initial risk | done | `findings.json` + UI; `test_golden.py::test_every_finding_cites_existing_evidence` |
| Checkpoint: what is in it / what changed / what is risky | done | `run_summary.json`, `changes.json`; `test_golden.py::test_changes`. "Risky" is the rule-based + LLM initial risk, not the §7 score (Dev4, unmerged) |
| Outcome flow: repo -> SBOM -> graph -> risk detection -> evidence | done | `uv run python -m guardian run --repo targets/juice-shop`; `test_pipeline.py::test_cp1_pipeline_outputs` |

## 2. Day-1 evening checkpoints (§3.4)

### Dev1: agents and orchestration

| Requirement | Status | Proof |
|---|---|---|
| 18:00 Tool registry: allowlist, typed args, budgets, approval check (D1-04) | done | `guardian/tools/registry.py`; `tests/guardrails/test_g3_tools.py` (G3.1 to G3.4, G3.6) |
| G3.5 network only to the allowlist | deferred | no host allowlist in code; cached, offline-safe calls only (`GUARDIAN_OFFLINE`) |
| LLM token budget (G3.6) | done | `guardian/agents/evidence_analyst.py`, `guardrails/budgets.py`; `test_g3_tools.py::test_llm_token_budget_accounting` |
| 19:30 LLM record/replay with no network (D1-13) | done | `tests/integration/test_replay_offline.py::test_replay_matches_recording_without_backend_or_network` |
| Full graph with human gate | partial | `guardian/graph/workflow.py`: discovery, detection, evidence_analyst, risk_analyst, remediation, human_gate, record_decision, validator, reporter. No investigator (D1-08); reporter only summarises; §7 risk analyst is the Day-1 selector, not the score |
| Gate pauses and resumes with the same plan_id | done | `tests/integration/test_human_gate.py::test_pause_resume_verify_and_replan` |
| SQLite checkpointer; resume in a new process | done | `runs/<id>/checkpoints.sqlite`; `workflow.resume`; CLI `decide` runs as a separate process from `run` |
| Demo: stop at gate, approve via CLI/API, continue | done | `guardian run ...`, `guardian plans`, `guardian decide ...`; API: `test_api.py::test_decision_paths` (resume is faked there; the real resume is in the gate test) |
| Heuristic findings only remove / replace / escalate (G5.3); max 3 attempts (G5.4) | done | `guardian/agents/remediation.py`; `test_human_gate.py::test_not_resolved_replans_then_escalates` (G5.4). No test targets G5.3 directly |
| Validation of an approved plan | partial | `guardian/agents/validator.py` applies the plan to a fresh copy and re-runs the file detectors. Build, tests, image rescan not run: `build_ok` is null, confidence MEDIUM. Sandbox is D2-08, deferred |
| CVE remediation | deferred | risk_analyst plans typosquat, lockfile, unpinned_ci only; needs §7 score, compat hint, sandbox |
| Tag `v0.5-day1` | deferred | no tag created here |

### Dev2: tools, graph, sandbox

| Requirement | Status | Proof |
|---|---|---|
| 18:00 D2-06 install-script detection | done | `guardian/tools/detectors/install_scripts.py`; `test_changes_install.py::test_install_scripts_reads_registry_once_and_caches`, `..._offline_with_empty_cache_still_finds_packages`, `..._registry_failure_degrades_to_unavailable` |
| D2-06 integrity / major-jump / new-dependency detection | done | `guardian/tools/detectors/unexpected_change.py`; `test_diff_locks_flags_same_algorithm_different_digest`, `test_diff_manifests_added_removed_changed_and_major_jump`, `test_diff_locks_install_script_added_distinguishes_new_packages` |
| Planted change detected; `changes.json` from compare-ref | done | `run --compare-ref <ref>`; `test_compare_ref_yields_all_four_finding_kinds`, `test_compare_ref_findings_are_capped_per_kind` |
| 19:30 Core patch ops with diff tests (D2-07) | done | `guardian/tools/patching.py` (set/remove/replace dependency, `pin_action_sha`, `generate_lockfile`); `tests/unit/test_patching.py` |
| Refuses paths outside the work copy | done | `test_patching.py::test_apply_ops_refuses_path_escape_without_writing`, `test_confined_accepts_inside_and_refuses_escape`, `test_apply_plan_path_escape_is_refused` |
| Dry-run diff before approval | done | `test_plan_preview_writes_nothing` |
| Day-1 end: image SBOM merged into graph (D2-11, P1) | deferred | not built; Dockerfiles are checked for tag-only images only |
| Docker sandbox (D2-08) | deferred | Day 2 |

### Dev3: UI and API

| Requirement | Status | Proof |
|---|---|---|
| 18:00 FastAPI core routes (§4.4) | done | `guardian/api/app.py`; `tests/unit/test_api.py::test_get_routes`, `test_start_run`, `test_404s` |
| 19:30 SSE `/runs/{id}/events` | done | `test_api.py::test_sse_finished_run`, `test_sse_gate_idle_ends` |
| 19:30 Approval endpoint bound to plan_hash, comment required | done | `test_api.py::test_decision_paths` |
| API safety: localhost CORS, strict ids | done | `test_api.py::test_cors`, `test_traversal_rejected` |
| `GET /runs/{id}/report.json` / `report.html`, `POST /watch` | deferred | Day 2 (no report generator on this branch) |
| Day-1 end: UI shows live trace; approve in UI resumes run | deferred | the React UI has no approval panel and does not read the SSE stream yet (D3-04/D3-06); approval works through CLI or API |

## 3. Guardrails covered (G1 to G7)

| Guardrail | Status | Test or check that proves it |
|---|---|---|
| G1 Secrets | partial | G1.1 `tests/guardrails/test_g1_g2.py::test_g1_1_file_read_denies_sensitive`; G1.2 `test_g1_2_redaction`. G1.3/G1.4 have no dedicated test |
| G2 Untrusted content | done | `test_g1_g2.py::test_g2_wrap_neutralises_closing_tag_and_flags_injection` |
| G3 Tools | partial | G3.1 `test_g3_tools.py::test_g3_1_tool_outside_agent_allowlist_is_blocked`, `test_g3_1_allowlist_matches_specs`; G3.2 `test_g3_2_bad_args_are_blocked`, `test_g3_2_bad_plan_id_is_blocked`; G3.3 `test_g3_3_apply_plan_without_approval_is_blocked`, `test_g3_3_wrong_plan_hash_is_blocked`, `test_g3_3_plan_edited_after_approval_is_blocked`, `test_g3_3_reject_decision_is_blocked`; G3.4 `test_g3_4_forbidden_tool_names_are_blocked` and `scripts/check_forbidden.py` (run by `make check`); G3.6 `test_g3_6_tool_call_budget_blocks_the_next_call`, `test_g3_6_wall_clock_budget_blocks`. G3.5 network allowlist: not implemented |
| G4 Grounding | partial | `tests/guardrails/test_grounding.py` (`test_unknown_evidence_id_rejected`, `test_invented_cve_rejected`, `test_every_claim_labelled_verified_or_inferred`, `test_claim_without_evidence_is_unsupported_and_removed`); G4.1 repair retry `tests/integration/test_pipeline.py::test_schema_repair_retry_then_escalate`. G4.5 (target_version from evidence) is enforced by the plan builder using lookup evidence; no dedicated test |
| G5 Actions | partial | G5.1 `test_human_gate.py::test_validator_unreachable_without_approval`, `test_pause_resume_verify_and_replan` (wrong hash refused); G5.2 same test (reject without comment refused) and `test_api.py::test_decision_paths`; G5.4 `test_not_resolved_replans_then_escalates`; G5.5 `scripts/check_forbidden.py` (no `git push` in `guardian/`); the validator writes only under `runs/<id>/attempts/`. G5.3 has no dedicated test. No local branch / PR.md output yet |
| G6 Sandbox | partial | only G6.6 (patching confined to the work copy): `test_patching.py::test_apply_ops_refuses_path_escape_without_writing`, `test_apply_plan_path_escape_is_refused`. G6.1 to G6.5 and G6.7 need the Docker sandbox (Day 2, deferred) |
| G7 Audit and reliability | partial | G7.1 append-only store `tests/unit/test_models_store.py::test_store_append_only_and_reload`; every call is written to `trace.jsonl` (`test_pipeline.py::test_cp1_pipeline_outputs`); G7.2 guardrail blocks emit `guardrail` events (`test_g3_tools.py`); G7.3 `test_replay_offline.py` and `test_pipeline.py::test_recorded_run_replays_offline_on_a_fresh_run`; G7.4 caching for registry, `git ls-remote` and LLM calls is covered by `test_install_scripts_reads_registry_once_and_caches`, `test_resolve_action_sha_queries_then_caches`; throttling: registry fetches in the install-script detector are sequential with a 0.2 s gap (`install_scripts._THROTTLE_S`), no general rate limiter yet |

## 4. What this branch does not cover

Dev4 threat intel, the §7 score, the outdated detector and reports (exist on the unmerged branch `origin/dev04`);
the investigator agent (D1-08); Docker sandbox build, test and image rescan (D2-08); image SBOM (D2-11); UI approval
panel and live SSE view (D3-04, D3-06); CVE remediation; G3.5 and G6.1 to G6.5 / G6.7.
