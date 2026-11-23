# Guardian — working context (CP1 build + Day-1 evening)

**GUARDIAN_PLAN.md is the source of truth.** This repository is a standalone build of all five developers' CP1
tasks (plan §3.1, up to the 16:30 checkpoint), made to be reviewed and run on its own. Branch `dev1/day1-evening`
adds the remediation loop with a human gate (below). Row-by-row coverage: `docs/day1_coverage.md`.

## Status vs CP1 (plan §3.2)

| CP1 item | Where |
|---|---|
| One command runs the 3-node agent graph | `uv run python -m guardian run --repo targets/juice-shop` (~55 s with the LLM step) |
| CycloneDX SBOM + component count | `runs/<id>/sbom.cdx.json` (Syft 1.57.2), `run_summary.json` → UI count strip |
| Graph: direct vs transitive, root + frontend | `guardian/core/graph_build.py` (edges from package-lock.json) → `graph.json` |
| Vulnerable transitive dep traced to direct parent | Grype findings + `paths_to()`, e.g. root › express-jwt@0.1.3 › jsonwebtoken@0.1.0 |
| ≥1 anomaly, shown in list + graph pseudo-node | lockfile (.npmrc:1), typosquat ngy-cookie (frontend/package.json:59), epilogue-js (ftp/package.json.bak), 7 unpinned actions, 5 tag-only images |
| Origin + integrity per node | lockfile `resolved` + `integrity` on every package node |
| What changed | `ftp/package.json.bak` vs `package.json` → `changes.json` |
| Finding: component, path, evidence ids, initial risk, labelled explanation | `findings.json` + evidence analyst (DeepSeek) with grounding |
| Agent trace visible | `trace.jsonl` → UI custody log + CLI printout |

## Status vs Day-1 evening (plan §3.4, §17.3)

| Item | Where | State |
|---|---|---|
| D1-04 guarded tool registry (G3.1 allowlist, G3.2 typed args, G3.3 approval, G3.4 no publish tools, G3.6 budgets) | `tools/registry.py`, `guardrails/{budgets,approval}.py` | done |
| D2-06 install-script + compare-ref detection | `tools/detectors/{install_scripts,unexpected_change}.py`, `run --compare-ref` | done |
| D2-07 patch ops + dry-run diff, work-copy confinement | `tools/patching.py` | done (no `docker` in the loop) |
| D1-05 graph with human gate, SQLite checkpointer, resume in a new process | `graph/workflow.py`, `agents/{risk_analyst,remediation,human_gate,validator,reporter}.py`, `core/plans.py` | done; reporter is a summary only |
| D3-03 / D3-09 API + SSE + decision endpoint | `api/app.py` | done; UI does not use it yet |
| D1-13 replay without network | `tests/integration/test_replay_offline.py` | done |
| Not on this branch | Dev4 intel / §7 score / outdated detector / reports (on unmerged `origin/dev04`); investigator (D1-08); Docker sandbox build/test/rescan (D2-08); image SBOM (D2-11); UI approval panel + live SSE (D3-04/D3-06); CVE remediation | open |

## Pipeline now

`discovery -> detection -> evidence_analyst -> risk_analyst -> [remediation -> human_gate -> record_decision ->
validator]* -> reporter`. State is checkpointed in `runs/<id>/checkpoints.sqlite` (thread id = run id).

- risk_analyst: up to `GUARDIAN_MAX_PLANS` (3) findings, one per category (typosquat, lockfile, unpinned_ci). CVEs wait for Day 2.
- remediation: deterministic candidates from evidence; plan = ops + dry-run diff + labelled rationale + `plan_hash`;
  a retry never repeats a plan; max 3 attempts, then `escalated` (G5.4); heuristic findings only replace/remove/escalate (G5.3).
- human_gate: `interrupt()` only (C6). record_decision re-checks G5.1/G5.2 and appends `approvals.jsonl`.
- validator: applies the approved plan to a fresh copy `runs/<id>/attempts/<attempt_id>/work`, re-runs the file detectors.
  Verdicts `verified | regressed | not_resolved | failed_build`. Build, tests and image rescan are NOT run on Day 1:
  `build_ok` is null, `checks_skipped` is listed, confidence MEDIUM at best.
- Files: `plans/`, `pending_plan.json`, `approvals.jsonl`, `validation/`, `attempts/` (`core/plans.py`).
- CLI: `run [--compare-ref REF] [--max-plans N]`, `plans [--run ID]`, `decide --plan PID --plan-hash <12+ chars> --decision approve|reject|accept_risk [--comment] [--by]`, `serve-runs`, `api`.
- API (`api/app.py`): plan §4.4 routes except report.json/report.html and `/watch`; SSE `/runs/{id}/events`; the decision
  endpoint needs the full `plan_hash`, and a comment for reject/accept_risk. Localhost only, no authentication, CORS for `localhost:5173`.

## Setup / run

```
uv sync --extra dev
pwsh scripts/install_tools.ps1          # Syft, Grype, OSV-Scanner (SHA-256 verified) into tools/bin
copy .env.example .env                  # set DEEPSEEK_API_KEY
uv run python -m guardian run --repo targets/juice-shop
uv run python -m guardian serve-runs    # http://localhost:8001/latest/...
cd ui; npm install; npm run dev         # http://localhost:5173
make check                              # ruff + forbidden-pattern grep + pytest
```

## LLM

Default provider **DeepSeek** (`deepseek-chat`, `https://api.deepseek.com`, key `DEEPSEEK_API_KEY`) through the
OpenAI-compatible backend in JSON-object mode; the JSON schema is put in the system prompt and the reply is
validated by our own Pydantic parser + grounding (G4). `GUARDIAN_LLM_MODE=record` stores responses in
`data/cache/llm/`; `replay` serves them with no network. Anthropic SDK path kept (`GUARDIAN_LLM_PROVIDER=anthropic`).
Without a key, the evidence analyst logs an error and falls back to the rule-based initial risk.

## Ownership map of what was built here

- Dev1: `guardian/core/{models,store,audit,config}.py`, `guardian/graph/*`, `guardian/agents/*`, `guardian/llm/*`,
  `guardian/guardrails/*`, `guardian/tools/{registry,file_read}.py`, `guardian/serve.py`, CLI.
- Dev2: `core/workspace.py`, `core/graph_build.py`, `tools/{resolve,sbom,scanners,binaries}.py`, `adapters/npm.py`,
  `tools/detectors/{lockfile,typosquat}.py`, `scripts/install_tools.ps1`, fixture lockfiles.
- Dev3: `ui/` (React + Vite + TS + React Flow + dagre), design world "Chain of Custody" (PRODUCT.md, .impeccable/).
- Dev4: `data/popular_packages/npm.txt`, `tools/detectors/{similarity,ci_pin,image_pin,unexpected_change}.py`,
  `adapters/{github_actions,dockerfile}.py`, `core/scoring.py` (initial risk).
- Dev5: `tests/golden/`, `scripts/{static_view.py,fetch_targets.ps1}`, `docs/`, README.

## Decisions taken today

- Graph edges come from each project's `package-lock.json` (Node resolution), not Syft's CycloneDX
  `dependencies`: also gives scope, origin and integrity. Recorded in the graph evidence.
- Lockfiles are resolved with `--package-lock-only --ignore-scripts --package-lock=true` (overrides `.npmrc`);
  results committed as fixtures and reused when the manifest hash matches (C3).
- Syft excludes `ftp/`, `test/`, `data/static/` (legacy/challenge files); `ftp/` is analysed by the diff and
  typosquat detectors instead.
- Syft runs with `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true`: it omits devDependencies by default, which left 615 packages out of the SBOM and out of Grype's scan (found by `scripts/cp1_check.py`).
- `serve-runs` refuses `/work/` paths: the work copy contains the target's key files (G1.1).
- Contract additions: `Finding.explanation`, `Finding.claims`, `Finding.initial_risk_source`, `run_summary.finished_at`.

## Day-1 evening decisions

- An approval is bound to `plan_id` + `plan_hash` (SHA-256 over the plan content). Editing a plan after approval, or
  approving another plan, is refused by the registry (G3.3) and by `record_decision` (G5.1).
- Plan candidates are rule-based, not LLM-chosen: a plan the human sees must be reproducible from evidence. The LLM
  stays in the evidence analyst. Only categories whose fix is a patch op we have and whose detector can be re-run are planned.
- Every patch is applied to a fresh copy of the target under `attempts/`; the target is never written (G6.6 confinement in `patching.py`).
- `pin_action_sha` resolves tag -> SHA with `git ls-remote`, cached; offline it uses the cache only.
- LLM token budget (G3.6) is per run: `GUARDIAN_MAX_LLM_TOKENS` (600000). Tool-call and wall-clock budgets are per agent (`guardrails/budgets.py`).
- Contract changes (additive): `ValidationResult.build_ok` is `bool | None` (None = not run); `run_summary.json` gains
  `remediation`, `pending_plan`, `budget` and status values `running` / `awaiting_human`; `changes.json` may carry
  `legacy` plus `compare_ref` / `compare_sha`; `GraphState` gained `repo`, `work_dir`, `sbom_path`, `compare_ref`,
  `plan_queue`, `current`, `attempt`, `plan_id`, `decision`, `route`, `last_validation`; new settings `GUARDIAN_MAX_LLM_TOKENS`, `GUARDIAN_MAX_PLANS`.
- The compare-ref diff and the install-script detector emit findings in existing categories: `unexpected_change`, `major_jump`, `integrity_change`, `install_script`.
