# Guardian — working context

Short, current state of the project. **GUARDIAN_PLAN.md is the source of truth**; this file says where we are
against it and what the integration contracts look like in code. Update it when something here changes.

## Status (2026-11-23, before CP1 16:30)

| Dev | Tasks | State |
|---|---|---|
| Dev1 | D1-01 skeleton, models, store, audit, LangGraph | **done** — `make check` green |
| Dev1 | D1-02 LLM provider + evidence analyst + grounding | **done** (tested with fake LLM; live call needs `ANTHROPIC_API_KEY`) |
| Dev1 | D1-03 wiring, dedupe, `run_summary.json`, `serve-runs` | **done on Dev1 side**; real Juice Shop run waits on Dev2/Dev4 tools |
| Dev2 | D2-01..D2-05 | not in repo yet |
| Dev3 | D3-01..D3-08 | not in repo yet |
| Dev4 | D4-01, D4-02, D4-11, D4-12 | not in repo yet |
| Dev5 | D5-01 (Juice Shop in `targets/`) | not in repo yet |

## Run it

```
make setup                                        # uv sync --extra dev
make check                                        # ruff + forbidden-pattern grep + pytest
python -m guardian run --repo targets/juice-shop  # or: make run
make serve-runs                                   # http://localhost:8001/latest/run_summary.json
```
Env: copy `.env.example` → `.env`. `GUARDIAN_LLM_MODE=live|record|replay`. Without a key or cache entry the
evidence analyst logs an error and falls back to the rule-based initial risk — the run still completes.

## Pipeline (CP1)

`START → discovery → (supervisor) → detection → (supervisor) → evidence_analyst → END`
(`guardian/graph/workflow.py`). Discovery and detection are deterministic tool agents; the evidence analyst is
the LLM agent. Every routing choice is a `decision` event in `trace.jsonl`.

## Tool contract (Dev2 / Dev4 — please implement against this)

Every tool is a plain function:

```python
from guardian.tools.registry import ToolContext, ToolOutput

def detect(ctx: ToolContext) -> ToolOutput:
    # ctx.run_id, ctx.run_dir, ctx.repo, ctx.work_dir, ctx.sbom_path, ctx.graph, ctx.artifacts, ctx.settings
    return ToolOutput(findings=[...], evidence=[...], artifacts={...}, summary="one line for the trace")
```

- Create `Evidence` for every fact; every `Finding.evidence_ids` must point at evidence you return in the same
  output (the store rejects unknown ids). Do **not** write `findings.json`/`evidence/` yourself.
- Special artifact keys: `work_dir` (Path), `sbom_path` (Path), `graph` (object), `changes` (dict → written to
  `changes.json`). Other keys land in `ctx.artifacts` for later tools.
- A tool that raises or is missing is logged as an `error` event and skipped; the run continues.
- Bindings (edit `BINDINGS` in `guardian/tools/registry.py` if your module/function name differs):

| Step | Binding | Owner |
|---|---|---|
| workspace | `guardian.core.workspace:prepare_workspace` → `artifacts.work_dir` | Dev2 D2-02 |
| lockfiles | `guardian.tools.resolve:resolve_lockfiles` | Dev2 D2-02 |
| SBOM | `guardian.tools.sbom:generate_sbom` → `runs/<id>/sbom.cdx.json`, Evidence `kind="sbom"`, `artifacts.sbom_path` | Dev2 D2-02 |
| graph | `guardian.core.graph_build:build_graph` → Evidence `kind="graph"`, `artifacts.graph` | Dev2 D2-03 |
| Grype / OSV | `guardian.tools.scanners:grype_scan`, `:osv_scan` | Dev2 D2-04 |
| detectors | `guardian.tools.detectors.{lockfile,typosquat,ci_pin,image_pin}:detect` | Dev2 D2-05 / Dev4 D4-12 |
| what changed | `guardian.tools.detectors.unexpected_change:mini_diff` → `artifacts.changes` (§4.1 shape) | Dev4 D4-11 |
| initial risk rule | `guardian.core.scoring:initial_risk(finding) -> Priority` | Dev4 D4-02 |

**Graph object** (Dev2): `stats() -> {components, direct, transitive, projects}`, `paths_to(purl, max_paths=5)
-> list[list[str]]`, `to_json() -> dict` (§4.1 `graph.json`), optional `add_pseudo_nodes(findings)`. Dev1's
runner adds `risk` + `finding_ids` to nodes and creates pseudo-nodes (`ci:`, `image:`, `config:`) for
non-package findings if `add_pseudo_nodes` is absent.

**Findings**: CVE findings need `component_purl`, `vuln_id`, `aliases` (dedupe key = purl + id/alias). Paths
are filled from `graph.paths_to` if you leave `dependency_paths` empty. Non-package findings need `file_path`
(+ `line`), which becomes the pseudo-node id.

## Contract additions (additive, announce at sync — §9.4)

`Finding` gained `explanation: str | None`, `claims: list[Claim]`, `initial_risk_source: "llm"|"rule"|None`
(the evidence analyst's output, for the UI findings list). `run_summary.json` also has `finished_at`.
`serve-runs` serves `/latest/<file>` (reads `runs/LATEST`, no symlink needed on Windows) and `/index.json`.

## Decisions (Dev1)

- **LLM: Claude Opus 5.5 (`claude-opus-5-5`) via the official Anthropic SDK**, structured JSON output
  (`output_config.format`), effort `low` (per-finding classification), server-side refusal fallback on.
  The plan said "LangChain chat model"; we call the SDK directly behind `guardian/llm/provider.py` — one less
  layer and native structured output. `GUARDIAN_LLM_PROVIDER=openai_compat` + `LLM_BASE_URL` covers a local model.
- Evidence analyst sends the top `GUARDIAN_MAX_LLM_FINDINGS` (default 40) by rule risk, batches of 8, 4 in
  parallel; the rest get the rule risk (logged as a supervisor `decision`).
- Grounding is code, not prompt: invented CVE/GHSA/purl → claim rejected; unknown evidence id → rejected;
  VERIFIED only when `field`/`value` matches cited evidence facts; claims without evidence removed.
