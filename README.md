# Guardian — agentic software supply chain guardian

Guardian analyses a repository's software supply chain and shows what is in it, what is risky and what changed.
A LangGraph pipeline of agents — **discovery** (resolve lockfiles with `--ignore-scripts`, Syft CycloneDX SBOM,
dependency graph with origin + integrity per package, CI workflows and Dockerfiles), **detection** (Grype with an
OSV-Scanner cross-check, plus lockfile / typosquat / unpinned-CI / tag-only-image / what-changed detectors) and
the **evidence analyst** (an LLM that explains each finding and proposes an initial risk, citing evidence ids that
a code-level grounding check verifies) — writes every fact as evidence and every step as a trace event. A
**risk analyst**, **remediation** agent, **human gate** and **validator** then turn a few findings into
reviewable patch plans that change nothing until a person approves them. The rule is:
*tools produce facts, agents make decisions and explanations, humans approve changes.* The plan
(`GUARDIAN_PLAN.md`) adds the §7 score, threat intel, reports and sandboxed build/test validation on Day 2.

## Setup (Windows, PowerShell)

Needs: Python ≥ 3.11 with [uv](https://docs.astral.sh/uv/), Git, Node.js + npm (lockfile resolution and the UI).

```powershell
uv sync --extra dev                                                    # Python deps (or: make setup)
powershell -ExecutionPolicy Bypass -File scripts/install_tools.ps1     # Syft 1.57.2, Grype 0.122.1, OSV-Scanner 2.7.1 -> tools/bin (SHA-256 verified)
powershell -ExecutionPolicy Bypass -File scripts/fetch_targets.ps1     # Juice Shop @ c9f99228d, PyGoat @ 2aa4cc1 -> targets/
Copy-Item .env.example .env                                            # then set DEEPSEEK_API_KEY in .env
```

LLM settings live in `.env` (`GUARDIAN_LLM_PROVIDER=deepseek|anthropic|openai_compat`, `GUARDIAN_LLM_MODE=live|record|replay`).
Never commit `.env`.

## Run

```powershell
uv run python -m guardian run --repo targets/juice-shop
```

Output goes to `runs/<run_id>/` (`runs/LATEST` holds the newest id): `run_summary.json`, `sbom.cdx.json`,
`graph.json`, `findings.json`, `evidence/*.json`, `changes.json`, `trace.jsonl`, plus the remediation files
described below (`plans/`, `pending_plan.json`, `approvals.jsonl`, `validation/`, `attempts/`,
`checkpoints.sqlite`). A Juice Shop run takes about a minute once tools are installed (≈55 s including the
DeepSeek step) and then stops at the human gate.

## View

React UI:
```powershell
uv run python -m guardian serve-runs        # serves runs/ on http://localhost:8001 (refuses runs/<id>/work/)
cd ui; npm install; npm run dev             # http://localhost:5173
```

Static fallback (no server, one self-contained file):
```powershell
uv run python scripts/static_view.py                    # latest run
uv run python scripts/static_view.py runs/<run_id>      # -> runs/<run_id>/static_view.html, open in a browser
```

## Day 1 evening: remediation loop with a human gate

After the evidence analyst, the graph continues:
`risk_analyst -> remediation -> human_gate -> record_decision -> validator -> reporter` (`guardian/graph/workflow.py`).

- **risk_analyst** picks up to `GUARDIAN_MAX_PLANS` (default 3) findings, at most one per fixable category:
  typosquat, lockfile, unpinned CI action. CVE upgrades are not planned yet (Day 2).
- **remediation** builds a plan from evidence (candidates are deterministic, not LLM-chosen): ops, a dry-run diff,
  a labelled rationale, expected risk reduction, rollback and a `plan_hash`. After a rejection or failed
  validation it never repeats a plan; at most 3 attempts per finding, then the finding is `escalated`.
  Heuristic findings (typosquat) only get replace / remove / escalate.
- **human_gate** contains only `interrupt()`. The run stops with status `awaiting_human`; state is in
  `runs/<id>/checkpoints.sqlite`, so it can be resumed from another process with the same `plan_id`.
- **record_decision** re-checks that the decision names the pending `plan_id` + `plan_hash` and that reject /
  accept_risk carry a comment, then appends to `approvals.jsonl`. Only an `approve` reaches the validator.
- **validator** applies the approved plan to a fresh copy under `runs/<id>/attempts/<attempt_id>/work` (the target
  is never modified) and re-runs the file detectors on it.

```powershell
uv run python -m guardian run --repo targets/juice-shop [--compare-ref <git ref>] [--max-plans N]
uv run python -m guardian plans [--run <id>]          # shows finding, rationale, diff and the plan_hash
uv run python -m guardian decide --run <id> --plan <plan_id> --plan-hash <first 12+ chars> --decision approve|reject|accept_risk [--comment "..."] [--by name]
uv run python -m guardian api [--port 8000]           # HTTP API + SSE trace on localhost, no authentication
```

`--compare-ref` diffs manifests and lockfiles against a git ref of the target and adds `unexpected_change`,
`major_jump`, `integrity_change` and `install_script` findings (capped per kind). `--max-plans 0` skips the loop.

API (`guardian/api/app.py`): `POST /runs`, `GET /runs`, `/runs/{id}`, `/summary`, `/graph`, `/changes`, `/findings`,
`/findings/{fid}`, `/evidence/{eid}`, `/plans`, `/plans/{plan_id}`, `/validation`, `/approvals`, SSE `/runs/{id}/events`,
and `POST /runs/{id}/plans/{plan_id}/decision` (body: `decision`, full `plan_hash`, `comment`, `decided_by`).
It binds to 127.0.0.1, allows CORS only from the Vite dev server (`localhost:5173`) and validates every id.
There is no report route and no `/watch` yet. The React UI does not use these endpoints yet.

**What `verified` means on Day 1.** The patch applied cleanly to a fresh copy, the detector that raised the
finding no longer fires on it, and no new finding of that kind appeared. It does **not** mean the project still
builds or passes tests: build, tests and image rescan are not run on Day 1, so `build_ok` is `null`, the
result lists the skipped checks, and confidence is MEDIUM at best. Nothing is committed, pushed or merged.

**Real run on Juice Shop** (`run_day1_demo`, commit c9f99228d, `--compare-ref c91808770^ --max-plans 3`, LLM in replay mode):

| Step | Result |
|---|---|
| Inventory | 1,656 packages (154 direct, 1,502 transitive), 3,203 edges, roots `root` + `frontend`; CycloneDX SBOM with 1,993 components |
| Detection | 89 findings: 57 CVE (Grype, 56 OSV duplicates merged), 14 dependency install scripts (e.g. `@scarf/scarf`, `sqlite3`), 7 unpinned actions, 5 tag-only images, 2 typosquats, 1 lockfile, and from `--compare-ref`: 2 new dependencies + 1 major-version jump |
| Remediation loop | 3 plans, each approved with `guardian decide` in a separate process: `ngy-cookie` -> `ngx-cookie` in `frontend/package.json`; `.npmrc` lockfile re-enabled + resolved lockfiles added; `actions/checkout@v6` pinned to `d23441a48e516b6c34aea4fa41551a30e30af803` (resolved with `git ls-remote`) |
| Validation | all 3 `verified` at detector level (target finding gone, nothing new); build/tests not run (Day 2 sandbox) |

The LLM ran in replay mode without a key: batches not in the committed cache fell back to the rule-based initial risk (8 of 89 findings got an LLM assessment); a `record` run with a key fills the cache.

## Tests

```powershell
make check            # ruff + forbidden-pattern check + pytest   (or: uv run pytest)
uv run pytest tests/integration/test_golden.py -q   # latest real run vs tests/golden/juice_shop_expected.yaml
```
The golden test is skipped when there is no run in `runs/`.

## Repo layout

| Path | What |
|---|---|
| `guardian/agents/` | discovery, detection (incl. Grype/OSV dedupe), evidence_analyst (LLM), risk_analyst, remediation, human_gate (+ record_decision), validator, reporter (summary only) |
| `guardian/graph/` | LangGraph workflow, supervisor routing, SQLite checkpointer + resume, `graph.json` / `run_summary.json` |
| `guardian/core/` | data model, evidence/finding store, audit trace, workspace, graph build, initial-risk rule, `plans.py` (plan, pending-plan, approval and validation files) |
| `guardian/tools/` | guarded tool registry (G3), lockfile resolve, SBOM, scanners, `file_read`, detectors (incl. install scripts, compare-ref diff), `patching.py` (patch ops, dry-run diff) |
| `guardian/api/` | FastAPI app: run views, SSE trace, decision endpoint |
| `guardian/adapters/` | npm, GitHub Actions, Dockerfile parsers |
| `guardian/guardrails/` | redaction, untrusted-data wrapping, grounding of LLM claims, `budgets.py` (G3.6), `approval.py` (plan hash; G3.3, G5.1, G5.2) |
| `guardian/llm/`, `guardian/prompts/` | LLM provider (DeepSeek / Anthropic / OpenAI-compatible, record/replay), system prompts |
| `ui/` | React + Vite UI (graph, findings, what changed, agent trace) |
| `scripts/` | tool install, target fetch, static viewer, forbidden-pattern check |
| `tests/` | unit, guardrail and integration tests; `golden/` expectations; `fixtures/` resolved Juice Shop lockfiles |
| `data/` | popular package names (typosquat), caches |
| `docs/` | decisions, targets, CP1 talk track, `day1_coverage.md` (Day-1 plan coverage, guardrail tests) |
| `targets/`, `runs/`, `tools/bin/` | gitignored: cloned targets, run output, installed binaries |

## Known limitations

- **LLM explanations need a DeepSeek key** (or a recorded replay cache). Without one the evidence analyst logs an
  error and every finding keeps the **rule-based initial risk** (CVSS band / category default); the run still
  completes. The latest CP1 run (`run_20261123_150644`) had no key, so it has no LLM explanations.
- Up to 200 findings per run (`GUARDIAN_MAX_LLM_FINDINGS`; anomalies first, then CVEs by risk) go to the LLM; any
  beyond that keep the rule-based risk. LLM tokens per run are capped by `GUARDIAN_MAX_LLM_TOKENS` (600000).
- OSV-Scanner is a **cross-check** merged into Grype findings by (purl, id/alias), not an independent pipeline.
- **No container image SBOM/scan yet**: Dockerfiles are checked for tag-only base images only.
- Juice Shop commits no lockfile. A run reuses the committed fixture lockfile (`tests/fixtures/juice-shop/`) when the
  target's `package.json` is byte-identical; otherwise it resolves with `npm install --package-lock-only
  --ignore-scripts` (needs network; ~62 s root + ~45 s frontend). Only npm is wired end to end; PyGoat (pip) is
  fetched but not yet analysed.
- **Remediation covers typosquat, lockfile and unpinned-CI findings only.** CVE upgrade plans are not built. Plan
  candidates are deterministic; the LLM does not choose the action.
- **Validation is a detector re-run only.** There is no sandbox, build, test run or image rescan, so no plan can be
  called "builds and passes" (see "What `verified` means"). The reporter only summarises outcomes.
- The API has no authentication (localhost only), no report routes and no watch trigger. The React UI has no
  approval panel and no live SSE view yet; approval is via CLI or API.
- **Not built on this branch:** Dev4's threat intel, §7 priority score and outdated-package detector (on the
  unmerged `origin/dev04` branch), the investigator agent, EPSS/KEV/reachability, reports, watch mode.
  Day 2: Docker sandbox build/test/rescan, image SBOM, CVE remediation.

## Credits

Graph rendering: React Flow (xyflow, MIT) and dagre (MIT).
