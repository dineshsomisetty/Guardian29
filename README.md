# Guardian — agentic software supply chain guardian

**Know what you build. Trust what you ship.**

Guardian analyses a repository's software supply chain end to end: it **discovers** what the application is built
from, **detects** vulnerable and suspicious components, **prioritises** them with an explainable risk score,
**recommends** a safe fix, waits for a **human approval**, then **validates** the fix in a Docker sandbox (build,
tests, rescan, SBOM diff) and writes an evidence-based **report**.

The rule throughout: *tools produce facts, agents reason and explain, humans approve changes.*
Every fact is stored as Evidence; every AI statement is labelled **verified fact** or **AI inference** by code.

| Document | What it covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | diagram of agents, tools, data sources, AI interactions, approval points, evidence storage |
| [docs/responsible_ai.md](docs/responsible_ai.md) | where AI is used, hallucination control, approvals, secrets protection, limitations |
| [docs/requirements_coverage.md](docs/requirements_coverage.md) | the problem statement, line by line, with proof for each item |
| [docs/generality_and_scale.md](docs/generality_and_scale.md) | six real repositories (npm, pip, Maven; GitHub and GitLab CI): results, time, memory, what they exposed |
| [GUARDIAN_PLAN.md](GUARDIAN_PLAN.md) | the full execution plan and guardrails G1–G7 |

## Setup (Windows, PowerShell)

Needs: Python ≥ 3.11 with [uv](https://docs.astral.sh/uv/), Git, Node.js 22+ and npm, Docker Desktop (sandbox).

```powershell
uv sync --extra dev                                                    # Python deps
powershell -ExecutionPolicy Bypass -File scripts/install_tools.ps1     # Syft, Grype, OSV-Scanner -> tools/bin (SHA-256 verified)
powershell -ExecutionPolicy Bypass -File scripts/fetch_targets.ps1     # Juice Shop, PyGoat (pinned) -> targets/
Copy-Item .env.example .env                                            # then set DEEPSEEK_API_KEY (or another provider)
cd ui; npm ci; cd ..
```

LLM settings live in `.env`: `GUARDIAN_LLM_PROVIDER=deepseek|anthropic|openai_compat`,
`GUARDIAN_LLM_MODE=live|record|replay`. `record` caches every LLM response under `data/cache/llm/`; `replay` with
`GUARDIAN_OFFLINE=1` then runs end to end with **zero network calls**. Never commit `.env`.

## Run

```powershell
uv run python -m guardian run --repo targets/juice-shop                     # one target, stops at the human gate
uv run python -m guardian run --repos targets/juice-shop targets/pygoat     # several targets + summary table
uv run python -m guardian plans --run <run_id>                              # the plan waiting for a decision
uv run python -m guardian decide --run <run_id> --plan <plan_id> --plan-hash <hash> --decision approve|reject|accept_risk [--comment "..."] [--by name]
uv run python -m guardian watch --run <run_id> --once                      # continuous monitoring: re-assess with fresh advisories
```

Output goes to `runs/<run_id>/`: `sbom.cdx.json`, `graph.json`, `findings.json`, `evidence/`, `risk.json`,
`plans/`, `approvals.jsonl`, `validation/`, `sbom.after.cdx.json`, `trace.jsonl`, `audit.jsonl`,
`report.json`, `report.html`, `checkpoints.sqlite`. A verified fix also leaves a local branch and `PR.md` in
`runs/<run_id>/attempts/<attempt_id>/` (never pushed).

## View (UI)

```powershell
uv run python -m guardian api                 # http://127.0.0.1:8000 (FastAPI + live SSE trace)
cd ui; npm run dev                            # http://localhost:5173
```

The UI opens on an **Overview**: what was scanned, how risky it is in plain words, the top risks and why they
matter, and the next action. Then: the live 9-step pipeline, the dependency map (risk paths highlighted), the
findings table with a forensic inspector, the **approval gate** (fix, diff, evidence, score breakdown,
rollback), **validation** (build/test logs, before→after score, SBOM diff, attempt timeline) and report export.

### Security of the API

* **No tokens configured** → local dev mode; the API refuses to bind anything but loopback.
* **Tokens** → `GUARDIAN_API_TOKENS="alice:<token>:approver,ci:<token>:operator,bob:<token>:viewer"`, then
  `guardian api --host 0.0.0.0`. Viewers read, operators start runs, only approvers decide, and the recorded
  approver is the authenticated identity.
* Runs may only target directories under `GUARDIAN_TARGET_ROOTS` (default `targets/`); at most
  `GUARDIAN_MAX_ACTIVE_RUNS` (default 2) run at once.

## How it works (9 agents)

`discovery → detection → evidence_analyst → investigator → risk_analyst → remediation → human_gate → validator → reporter`

| Agent | What it does |
|---|---|
| Discovery | copies the target, resolves lockfiles with `--ignore-scripts`, builds a CycloneDX SBOM (Syft) and the dependency graph with origin + integrity |
| Detection | Grype + OSV-Scanner; typosquats, install scripts, missing lockfile, unpinned CI actions, tag-only images, unexpected changes (`--compare-ref`), package risk, policy-as-code |
| Evidence analyst (LLM) | explains each finding and proposes an initial risk; every claim is grounded against evidence |
| Investigator (LLM, ReAct) | digs into suspicious non-CVE findings with up to 8 read-only tool calls |
| Risk analyst | `score = 100 × (0.30 S + 0.25 E + 0.20 R + 0.15 P + 0.10 X)` from severity, EPSS/KEV, reachability, production use, exposure; computed in code; LLM writes the summary only |
| Remediation | upgrade / replace / remove / pin / block / update base image / mitigate, target versions only from evidence, unified diff, expected risk reduction, rollback, plan hash |
| Human gate | pauses (`interrupt()`); resumes only with an approval for that exact plan hash |
| Validator | fresh copy → patch → lockfiles → Docker build + unit/integration tests with `--network none` → rescan → SBOM diff → detectors + policy re-run; up to 3 attempts, then escalation |
| Reporter | `report.json` + `report.html` |

## Tests

```powershell
bash scripts/harness.sh          # ruff, pytest, security greps (no shell=True / git push / npm publish), UI typecheck + build
uv run pytest -q                 # tests only
```

Golden tests check the newest real Juice Shop run against `tests/golden/juice_shop_expected.yaml`.

## Targets

| Target | Ecosystem | Why |
|---|---|---|
| OWASP Juice Shop | npm (Node, Angular), Docker | large realistic tree (1,656 packages), typosquats, install scripts, unpinned CI |
| PyGoat | pip (Django), Docker | second ecosystem, old Django with many advisories |
| OWASP NodeGoat | npm | older dependencies (optional extra) |
| OWASP WebGoat | Maven (Java) | `pom.xml` parsing, Java dependency findings (optional extra) |
| vulnerable-rest-api | npm (Node + React) | no root package: `client/` + `server/` projects |
| vuln_django_play | pip (Django), GitLab CI | GitLab pipelines as a supply-chain source |

## Known limitations

- Reachability is import-level (is the package imported in production code?), not function-level.
- The built-image rescan (G6.7) is opt-in (`GUARDIAN_IMAGE_BUILD=1`): it runs the target's Dockerfile with network on.
- CVE upgrades are planned for npm and pip; Maven is scanned (SBOM, CVEs) but not patched.
- Sandbox tests are judged against the unpatched project: failures that already happen without the fix are
  disclosed, not blamed on it (Juice Shop: unit 439/441 and API 559/580 on the unmodified app; the 21 API
  failures need the internet, which the sandbox never gives tests).
- Web builds that fetch resources (Juice Shop's Angular build inlines web fonts) run while the dependency
  image is built, inside the container; validation builds and tests always run with `--network none`.
- Rego policies are mirrored by a native Python evaluator; `conftest`/`opa` is used only if installed.
- LLM explanations need a provider key or a recorded replay cache; without one the rule-based risk is used.

## Contributors

Five-person team, one owned area each, equal standing (areas as defined in `GUARDIAN_PLAN.md`):

| Role | Area | Contributor |
|---|---|---|
| Dev1 | Agentic AI workflow: agents, orchestration, guardrails, remediation loop | Nibiru7899 |
| Dev2 | Tools, graph, sandbox | Somisetty Dinesh |
| Dev3 | UI and API | tarunkumar |
| Dev4 | Threat intel, scoring, detectors, reports | dheeraj856 |
| Dev5 | Targets, decisions, docs | Kavya Penikalapati |

## Credits

Graph rendering: React Flow (xyflow, MIT) and dagre (MIT). Scanners: Syft, Grype (Anchore), OSV-Scanner (Google).
