# Guardian — working context (CP1 build)

**GUARDIAN_PLAN.md is the source of truth.** This repository is a standalone build of all five developers' CP1
tasks (plan §3.1, up to the 16:30 checkpoint), made to be reviewed and run on its own.

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
