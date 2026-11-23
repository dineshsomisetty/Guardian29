# Guardian — agentic software supply chain guardian

Guardian analyses a repository's software supply chain and shows what is in it, what is risky and what changed.
A LangGraph pipeline of agents — **discovery** (resolve lockfiles with `--ignore-scripts`, Syft CycloneDX SBOM,
dependency graph with origin + integrity per package, CI workflows and Dockerfiles), **detection** (Grype with an
OSV-Scanner cross-check, plus lockfile / typosquat / unpinned-CI / tag-only-image / what-changed detectors) and
the **evidence analyst** (an LLM that explains each finding and proposes an initial risk, citing evidence ids that
a code-level grounding check verifies) — writes every fact as evidence and every step as a trace event. The rule is:
*tools produce facts, agents make decisions and explanations, humans approve changes.* The plan
(`GUARDIAN_PLAN.md`) adds prioritisation, remediation with human approval and sandboxed validation on Day 2.

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
`graph.json`, `findings.json`, `evidence/*.json`, `changes.json`, `trace.jsonl`. A Juice Shop run takes about
about a minute once tools are installed (≈55 s including the DeepSeek step).

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

## Tests

```powershell
make check            # ruff + forbidden-pattern check + pytest   (or: uv run pytest)
uv run pytest tests/integration/test_golden.py -q   # latest real run vs tests/golden/juice_shop_expected.yaml
```
The golden test is skipped when there is no run in `runs/`.

## Repo layout

| Path | What |
|---|---|
| `guardian/agents/` | discovery, detection (incl. Grype/OSV dedupe), evidence_analyst (LLM) |
| `guardian/graph/` | LangGraph workflow, supervisor routing, `graph.json` / `run_summary.json` |
| `guardian/core/` | data model, evidence/finding store, audit trace, workspace, graph build, initial-risk rule |
| `guardian/tools/` | tool contract + registry, lockfile resolve, SBOM, scanners, `file_read`, detectors |
| `guardian/adapters/` | npm, GitHub Actions, Dockerfile parsers |
| `guardian/guardrails/` | redaction, untrusted-data wrapping, grounding of LLM claims |
| `guardian/llm/`, `guardian/prompts/` | LLM provider (DeepSeek / Anthropic / OpenAI-compatible, record/replay), system prompts |
| `ui/` | React + Vite UI (graph, findings, what changed, agent trace) |
| `scripts/` | tool install, target fetch, static viewer, forbidden-pattern check |
| `tests/` | unit, guardrail and integration tests; `golden/` expectations; `fixtures/` resolved Juice Shop lockfiles |
| `data/` | popular package names (typosquat), caches |
| `docs/` | decisions, targets, CP1 talk track |
| `targets/`, `runs/`, `tools/bin/` | gitignored: cloned targets, run output, installed binaries |

## Known limitations (Checkpoint 1)

- **LLM explanations need a DeepSeek key** (or a recorded replay cache). Without one the evidence analyst logs an
  error and every finding keeps the **rule-based initial risk** (CVSS band / category default); the run still
  completes. The latest CP1 run (`run_20261123_150644`) had no key, so it has no LLM explanations.
- Up to 200 findings per run (`GUARDIAN_MAX_LLM_FINDINGS`; anomalies first, then CVEs by risk) go to the LLM; any beyond that keep the rule-based risk.
- OSV-Scanner is a **cross-check** merged into Grype findings by (purl, id/alias), not an independent pipeline.
- **No container image SBOM/scan yet**: Dockerfiles are checked for tag-only base images only.
- Juice Shop commits no lockfile. A run reuses the committed fixture lockfile (`tests/fixtures/juice-shop/`) when the
  target's `package.json` is byte-identical; otherwise it resolves with `npm install --package-lock-only
  --ignore-scripts` (needs network; ~62 s root + ~45 s frontend). Only npm is wired end to end; PyGoat (pip) is
  fetched but not yet analysed.
- Day-2 features are **not built**: EPSS/KEV/reachability prioritisation, remediation plans, human approval gate,
  sandboxed build/test, rescan and before/after SBOM, reports, watch mode.

## Credits

Graph rendering: React Flow (xyflow, MIT) and dagre (MIT).
