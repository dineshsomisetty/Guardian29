# Requirements coverage: the problem statement, line by line

Source: *Software Supply Chain Guardian*, Amrita × Bosch hackathon problem statement (6 slides).
Every line of the slides is listed below with its status, what Guardian does, and where the proof is.

**Status:** ✅ done (built and tested) · 🟡 partial (built, with the stated gap) · ❌ not done.
**Proof** points at code, a test (`tests/...::name`) or a real run (`runs/<id>/`).

Real runs used as proof (DeepSeek live, then replayed offline with the network blocked):

| Run | Target | Result |
|---|---|---|
| `run_juice_final` | OWASP Juice Shop (npm), DeepSeek live (record) | 1,656 packages (154 direct, 1,502 transitive), 91 findings, top risk 90.17 (`jsonwebtoken` 0.1.0 via `express-jwt` 0.1.3), plan `express-jwt` → 3.4.0, paused at the human gate |
| `run_juice_final_offline` | same, `GUARDIAN_OFFLINE=1` + LLM replay, network blocked | identical 91 findings, 52 LLM answers from cache, **0 network attempts, 0 errors** |
| `run_pygoat_final` / `_offline` | PyGoat (pip, Django) | 58 packages, 470 findings, top risk 88.65 (`django` 3.2.18), plan `django` → 4.2.26 in the exact requirements file; offline replay **0 network attempts, 0 errors** |
| batch `runs/batch_*.json` | Juice Shop, PyGoat, NodeGoat (npm) | 1,656 / 58 / 1,091 packages; top risks 90 / 89 / 84; all paused at the gate |
| `run_webgoat2` | OWASP WebGoat (Maven/Java) | 49 Maven packages from `pom.xml`, 36 CVEs (top `xstream` 1.4.5, 76.33), OSV cross-check 37 advisories, plan: pin `actions/checkout@v7` to its commit SHA |
| sandbox, PyGoat (unmodified) | Docker, `--network none` for build/test | install 84 s; `compileall` + `manage.py check` passed; **Django test suite 54/54 passed** |
| sandbox, Juice Shop (unmodified) | Docker, `--network none` for build/test | `tsc` build passed; unit `test:server` **439/441**, the same 2 `jwtForgedChallenge` failures as without any fix (baseline), so not blamed on a fix; API suite needs the built Angular frontend: 0/61 even unpatched, disclosed as not runnable in the sandbox |
| `run_e2e_juice` (earlier) | Juice Shop, approved `express-jwt` 0.1.3 → 8.5.1 | sandbox **build failed** (`tsc` TS2349: express-jwt 8 changed its API) → re-plan → escalated: the sandbox caught a breaking upgrade before it reached the repo |

---

## Slide 2. Problem statement

| Line | Status | What Guardian does | Proof |
|---|---|---|---|
| "Build an Agentic AI Solution" | ✅ | 9 cooperating agents in a LangGraph state machine; 3 of them reason with an LLM (evidence analyst, investigator ReAct loop, risk summaries) | `guardian/graph/workflow.py`; `tests/integration/test_investigator.py::test_graph_has_exactly_the_contract_nodes` |
| "that **continuously** analyzes the software supply chain" | ✅ | `guardian watch --run <id> [--interval 1h]` re-checks the stored inventory for newly disclosed advisories and re-scores, without re-discovery | `guardian/watch.py`; `tests/unit/test_watch_batch.py::test_cli_watch_once` |
| "to identify dependency risks, vulnerabilities, and suspicious changes" | ✅ | CVEs (Grype + OSV), typosquats, install scripts, integrity / unexpected / major-version changes, unpinned CI, tag-only images, package risk, policy | `guardian/tools/detectors/`; `test_changes_install.py::test_compare_ref_yields_all_four_finding_kinds` |
| "before they impact applications" | ✅ | nothing is changed until a human approves; fixes are proven in a sandbox copy first | human gate (§5 below) |
| "connects evidence from the supply chain with application context" | ✅ | reachability (is the package imported in production code), exposure (exposed port + server path), production vs dev scope | `guardian/tools/reachability.py`, `guardian/tools/risk_tools.py`; `test_risk_remediation.py::test_risk_score_equals_compute_and_factors_have_sources` |
| "prioritizes meaningful risks" | ✅ | explainable 0–100 score + band + confidence | §7 score, `guardian/core/scoring.py` |
| "recommends safe actions" | ✅ | evidence-backed plans with diff, expected risk reduction, compatibility, rollback | `guardian/agents/remediation.py` |
| 1 Discover: "direct and transitive dependencies, container components, package versions, and their relationships" | ✅ | dependency graph with direct/transitive, version, scope, origin, integrity; Dockerfile base images and CI workflows as graph nodes | `graph.json`; `test_detectors.py::test_graph_paths_origin_integrity_scope` |
| 1 Discover: "Generate or consume an SBOM and build a dependency view" | ✅ | Syft CycloneDX `sbom.cdx.json`; React Flow dependency map | `runs/run_juice_record/sbom.cdx.json`; UI "Dependency map" |
| 2 Detect: "known vulnerabilities" | ✅ | Grype, cross-checked with OSV-Scanner, deduplicated by package + id/alias | `guardian/tools/scanners.py` |
| 2 Detect: "typosquatted packages" | ✅ | `ngy-cookie` (looks like `ngx-cookie`) found in Juice Shop | `test_golden.py::test_expected_finding` |
| 2 Detect: "unexpected dependencies" | ✅ | `--compare-ref` / `.bak` diff: new dependency findings | `test_changes_install.py::test_diff_manifests_added_removed_changed_and_major_jump` |
| 2 Detect: "unsafe install scripts" | ✅ | 14 packages with install scripts in Juice Shop (lockfile `hasInstallScript` + registry) | `test_changes_install.py::test_install_scripts_reads_registry_once_and_caches` |
| 2 Detect: "untrusted images" | ✅ | tag-only `FROM` images (e.g. `node:24`) | `guardian/tools/detectors/image_pin.py`; golden `image:node:24` |
| 2 Detect: "integrity changes" | ✅ | same version, different lockfile digest | `test_diff_locks_flags_same_algorithm_different_digest` |
| 3 Analyze: "Correlate severity with exploitability, reachability, exposure, provenance, and application context" | ✅ | S (CVSS), E (EPSS percentile, CISA KEV), R (import reachability), P (prod/dev), X (exposure), + provenance modifier | `guardian/core/scoring.py::compute`; `test_kev_override_and_not_applicable_weights` |
| 3 Analyze: "determine which findings actually require attention" | ✅ | bands Critical/High/Medium/Low; only the top findings enter the remediation loop | `risk_analyst.select` |
| 4 Remediate: "upgrade, replace, pin, remove, mitigate, block, or request further review, with supporting evidence" | ✅ | all seven actions exist; target values come only from evidence (G4.5) | `guardian/agents/remediation.py`, `guardian/tools/patching.py`; `tests/unit/test_d2_image_block_mitigate.py`, `test_g45_blocks_target_absent_from_evidence` |
| 5 Validate: "Build and test proposed changes" | ✅ | Docker sandbox: install, then build + unit + integration tests with `--network none`; results judged against the unpatched project (a failure that exists without the fix is disclosed, not blamed on it) | `guardian/tools/sandbox.py`; real runs above (PyGoat 54/54, Juice Shop 439/441 = baseline); `test_failures_that_already_fail_unpatched_are_not_blamed_on_the_fix` |
| 5 Validate: "rescan the resulting application" | ✅ | Syft + Grype on the patched copy; optional built-image rescan | `sandbox.rescan_patched`; `test_image_build_rescan_limits_ignore_and_cleanup` |
| 5 Validate: "verify that the risk has been reduced" | ✅ | target finding gone + risk before → after | `ValidationResult.risk_before/after` |
| 5 Validate: "detect newly introduced problems" | ✅ | new vulnerabilities, unexpected new packages, new detector or policy findings → `regressed` | `test_new_vuln_is_regressed`; `test_validator_flags_only_new_or_increased_policy_violations` |
| 5 Validate: "provide a clear evidence-based report" | ✅ | `report.json` + `report.html` | §Slide 6 report |

## Slide 3. Important guidelines

### Examples of supply-chain risks

| Risk | Status | Proof |
|---|---|---|
| Vulnerable direct dependency | ✅ | e.g. `sanitize-html@1.4.2` in Juice Shop; direct CVE upgrade plans (`test_remediation_retry_picks_other_version_and_target_in_evidence`) |
| Vulnerable transitive dependency | ✅ | `jsonwebtoken@0.1.0` via `express-jwt@0.1.3`, path traced to the direct parent; fix by upgrading the parent (`test_transitive_fix_prefers_smallest_parent_major_that_provably_pulls_fixed_child`) |
| Typosquatted or malicious package | ✅ | `ngy-cookie`, `epilogue-js`; investigator conclusion; replace/remove/block only (G5.3) |
| Suspicious package update or install script | ✅ | install-script detector, maintainer change, release bursts (`test_maintainer_change_burst_confusion_and_provenance_gap`) |
| Untrusted container image or artifact | ✅ | tag-only images → pin to digest plan (`test_image_pin_plan_digest_comes_from_evidence_and_diff_is_previewed`) |
| Unexpected lockfile or dependency change | ✅ | missing lockfile (`.npmrc package-lock=false`), lockfile diffs |
| Unpinned or unsafe CI/CD component | ✅ | 7 unpinned GitHub Actions → pin to commit SHA (`test_ls_remote_prefers_peeled_tag_and_validates_sha`) |

### Sample application guidelines

| Guideline | Status | How |
|---|---|---|
| Free, open-source application from a public repository | ✅ | OWASP Juice Shop (MIT), PyGoat, NodeGoat, pinned commits (`scripts/fetch_targets.ps1`) |
| Realistic dependency tree with direct and transitive dependencies | ✅ | Juice Shop: 154 direct, 1,502 transitive |
| Containerized and runnable within the team's own sandbox | ✅ | targets ship Dockerfiles; Guardian's sandbox is local Docker |
| Build, test and scan locally | ✅ | `guardian run`; sandbox build/test; `scripts/harness.sh` |
| Document repository, setup steps, dependencies and tools | ✅ | `README.md`, `docs/targets.md`, `docs/decisions.md` |

### Out of scope (and how Guardian stays out of it)

| Rule | Status | Guardrail |
|---|---|---|
| No scanning or attacking real production systems | ✅ | only local folders under `targets/`; API refuses other roots (`test_runs_are_confined_to_target_roots_and_capped`) |
| No access outside the authorized sandbox | ✅ | outbound host allowlist (G3.5, `tests/guardrails/test_g3_network.py`); build/test with `--network none` |
| No publishing packages | ✅ | no publish tool exists (G3.4); harness greps for `npm publish` |
| No real credentials or secrets | ✅ | secrets never read (G1.1), redacted (G1.2), keys only in `.env` |
| No automatic merge / deploy / release without human approval | ✅ | human gate bound to `plan_hash`; nothing is pushed; local branch + `PR.md` only (`tests/integration/test_local_pr.py`) |
| No impact on others or shared infrastructure | ✅ | every external call cached and throttled; sandbox CPU/memory/time limits |

## Slide 4. Day 1: the Guardian's eyes

| Line | Status | Proof |
|---|---|---|
| Analyze package manifests and lockfiles | ✅ | `package.json`, `package-lock.json`, `requirements*.txt`, `pom.xml` (WebGoat: 49 Maven packages; Maven is scanned and prioritised, not patched) |
| Identify direct and transitive dependencies | ✅ | `graph.json` |
| Capture component names and versions | ✅ | SBOM + graph nodes |
| Generate or consume an SBOM (CycloneDX or SPDX) | ✅ | CycloneDX |
| Build the dependency graph | ✅ | UI dependency map |
| Identify where each component originates | ✅ | `origin` (resolved URL) + `integrity` per node (`test_path_nodes_have_origin_and_integrity`) |
| Inspect at least one container image or CI/CD workflow | ✅ | Dockerfiles + CI workflows; digest lookup of images (`resolve_image_digest`, real: `node:24`) |
| Correlate components with known vulnerabilities | ✅ | Grype + OSV |
| Capture CVE, severity and available fixes | ✅ | `vuln_id`, `cvss`, `severity`, `fixed_versions`, `affected_range` |
| Trace vulnerable transitive dependencies back to their source | ✅ | `dependency_paths`; inspector "How it gets in" breadcrumb |
| Identify at least one supply-chain anomaly | ✅ | several (typosquat, install scripts, unpinned CI, tag-only images, missing lockfile) |
| Show what was detected / which component / dependency path / supporting evidence / initial risk level | ✅ | findings table + inspector; `test_every_finding_cites_existing_evidence` |
| Checkpoint: what is in it, what changed, what appears risky | ✅ | Overview page, `changes.json`, risk bands |

## Slide 5. Day 2: the Guardian's brain and shield

| Line | Status | Proof |
|---|---|---|
| Combine severity with exploitability, reachability and exposure | ✅ | score formula, factor table in the UI |
| Consider whether the dependency is used in production | ✅ | factor P (prod 1.0, dev 0.3) |
| Distinguish urgent risks from lower-priority findings | ✅ | bands + KEV override |
| Explainable risk score and confidence level | ✅ | per-factor value, weight, contribution and evidence; confidence lowered per unknown factor |
| Analyze at least one non-CVE supply-chain risk | ✅ | investigator on `ngy-cookie` (`tests/integration/test_investigator.py`) |
| Compare package versions, manifests or lockfiles | ✅ | `--compare-ref`, `.bak` diff, `changes.json` |
| Identify suspicious scripts, provenance gaps or integrity changes | ✅ | install-script, provenance-gap, integrity-change detectors |
| Clearly separate verified evidence from AI-generated inference | ✅ | labels set by code (G4.3); UI shows "Verified fact" vs "AI inference" (`test_every_claim_labelled_verified_or_inferred`) |
| Upgrade to a safe version | ✅ | npm and pip |
| Replace or remove the dependency | ✅ | typosquat plans |
| Pin a trusted version | ✅ | pin action SHA, pin image digest, generate lockfile |
| Update the container base image | ✅ | the image detector records the newest explicit release on the same line from Docker Hub (cached, offline-safe); remediation offers pin-digest first, then update-to-that-release + digest. Real (Juice Shop): `FROM node:24` → attempt 1 `node:24@sha256:9d26…`, attempt 2 `node:24.22.3@sha256:9d26…`; `node:20.19.2-bookworm-slim` → `20.19.6-bookworm-slim`. A moving tag never gets an older release (no downgrades). `tests/unit/test_image_tags.py`, `test_update_base_image_only_with_newer_tag_from_evidence` |
| Block the unsafe component | ✅ | `block_package` + `guardian.yaml` denylist |
| Escalate for security review | ✅ | after 3 attempts or no safe plan (G5.4) |
| Expected risk reduction, compatibility impact and rollback option | ✅ | `simulate_after`, `compat_hint`, rollback text in every plan |
| Apply the remediation in a controlled branch or sandbox | ✅ | fresh copy under `runs/<id>/attempts/`; local branch for a verified fix |
| Build the application | ✅ | sandbox build phase (real: Juice Shop `tsc`) |
| Run unit and integration tests | ✅ | `test:server` + `test:api` (npm), `manage.py test` (Django). Real: PyGoat Django suite 54/54; Juice Shop unit 439/441 (= baseline). Juice Shop's API suite needs the built Angular frontend and is disclosed as not runnable in the sandbox |
| Rescan the resulting artifact | ✅ | patched tree always; built image with `GUARDIAN_IMAGE_BUILD=1`. Real: PyGoat's own Dockerfile built in the sandbox (177 s, limits, keys/.env excluded), Syft + Grype on the image found 797 matches (OS packages included), image removed afterwards |
| Compare before-and-after SBOM | ✅ | `sbom_diff` evidence, UI table |
| Detect newly introduced vulnerabilities or dependencies | ✅ | `regressed` verdict |
| Report: original finding and supporting evidence | ✅ | `report.json.findings` |
| Report: recommended and approved action | ✅ | `report.json.actions` (plan + approval) |
| Report: build and test results | ✅ | validations per action |
| Report: before-and-after risk status | ✅ | `risk_before`, `risk_after` |
| Report: remaining or accepted risk | ✅ | `remaining_risk` |
| Report: final confidence and audit trail | ✅ | `final_confidence`, `trace.jsonl`, `audit.jsonl` |
| Final demo: "from detection to verified remediation" (prioritized risk → recommended fix → human approval → build & test → rescan → verified) | ✅ | the whole loop runs on real targets; the Juice Shop sandbox run showed the "failed attempt → re-plan" path for real |

## Slide 6. Stretch goals and deliverables

| Item | Status | Proof / gap |
|---|---|---|
| 1 Reachability analysis | 🟡 | import-level (is the vulnerable package imported in production code), adjusts factor R. Function-level "vulnerable code actually called" is not done |
| 2 Automated remediation (PR) | ✅ | local branch + `PR.md` with fix, rationale, validation results, rollback; never pushed (`tests/integration/test_local_pr.py`) |
| 3 Provenance verification | 🟡 | npm registry signatures/attestations + repository/maintainer signals → provenance gaps and score modifier. Cosign / in-toto / SLSA verification not done |
| 4 Advanced package risk | ✅ | dependency confusion, maintainer change, unusual release activity (`tests/unit/test_package_risk.py`) |
| 5 Policy-as-code | ✅ | `guardian.yaml` + `policies/guardian.rego`; native evaluator always, Conftest/OPA when installed; re-checked after each fix |
| 6 Continuous monitoring | ✅ | `guardian watch` |
| Working prototype | ✅ | CLI + API + UI, three targets |
| Architecture overview | ✅ | `docs/architecture.md` |
| Source code and setup, configuration, sample policies, prompts, known limitations | ✅ | `README.md`, `.env.example`, `guardian.yaml`, `policies/`, `guardian/prompts/`, README "Known limitations" |
| Live demonstration | ✅ | `GUARDIAN_PLAN.md` §13 script; offline replay as backup (0 network calls, proven) |
| Guardian report: inventory + paths, findings + evidence, ranking + actions, validation, remaining/accepted risk | ✅ | `report.json` / `report.html`; UI export |
| Responsible AI & security note | ✅ | `docs/responsible_ai.md` |

## Summary

* **All core requirements (slides 2–5) are done.** Disclosed limitation: Juice Shop's API test suite needs its
  built Angular frontend and is reported as not runnable in the sandbox (its unit suite and PyGoat's Django
  suite run for real).
* **Stretch goals:** 4 of 6 done; reachability and provenance are partial (import-level, registry-level).
* **All deliverables exist.**
