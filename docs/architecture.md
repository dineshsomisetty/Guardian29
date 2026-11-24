# Guardian architecture

Guardian is an agentic supply-chain guardian: it **discovers** what an application is built from, **detects**
vulnerable and suspicious components, **prioritises** them with an explainable score, **proposes** a safe fix,
waits for a **human approval**, then **validates** the fix in a sandbox and **reports** the evidence.

Everything below maps to the problem statement's five steps: Discover → Detect → Analyze → Remediate → Validate.

## 1. Agents, tools, data sources, AI interactions, approval points, evidence storage

```mermaid
flowchart LR
    subgraph IN["Inputs (read-only)"]
        REPO["Target repo<br/>package.json, lockfiles,<br/>requirements.txt, pom.xml,<br/>Dockerfile, CI workflows"]
    end

    subgraph AGENTS["LangGraph workflow (9 agents, SQLite checkpoints)"]
        direction LR
        D1["1 Discovery<br/><i>tool agent</i>"] --> D2["2 Detection<br/><i>tool agent</i>"]
        D2 --> D3["3 Evidence analyst<br/><b>LLM</b>"]
        D3 --> D4["4 Investigator<br/><b>LLM ReAct, max 8 tool calls</b>"]
        D4 --> D5["5 Risk analyst<br/>score in code, <b>LLM</b> summary"]
        D5 --> D6["6 Remediation<br/>plan + diff + hash"]
        D6 --> HG{{"7 Human gate<br/>interrupt() only"}}
        HG -- "approve (plan_id + plan_hash)" --> D8["8 Validator<br/>Docker sandbox"]
        HG -- "reject: different plan" --> D6
        D8 -- "failed: re-plan (max 3)" --> D6
        D8 --> D9["9 Reporter<br/>JSON + HTML"]
        HG -- "accept risk" --> D9
    end

    subgraph TOOLS["Tools (registry: allowlist per agent, typed args, budgets)"]
        T1["Syft (SBOM)"]
        T2["Grype + OSV-Scanner"]
        T3["Detectors: typosquat, install scripts,<br/>lockfile, unpinned CI, tag-only image,<br/>unexpected change, integrity, policy"]
        T4["Intel: EPSS, CISA KEV, OSV,<br/>npm registry, reachability, exposure"]
        T5["Patch ops: upgrade, replace, remove,<br/>pin SHA / digest, block, lockfile"]
        T6["Sandbox: docker build/test<br/>--network none, rescan, SBOM diff"]
    end

    subgraph AI["LLM provider (DeepSeek / Anthropic / OpenAI-compatible)"]
        LLM["record / replay cache<br/>data/cache/llm"]
    end

    subgraph STORE["Evidence storage: runs/&lt;run_id&gt;/"]
        S1["sbom.cdx.json, graph.json"]
        S2["findings.json, evidence/*.json"]
        S3["risk.json, plans/, approvals.jsonl"]
        S4["validation/, sbom.after.cdx.json"]
        S5["trace.jsonl, audit.jsonl"]
        S6["report.json, report.html"]
    end

    HUMAN(["Human approver<br/>UI or CLI, role 'approver'"])

    REPO --> D1
    D1 --- T1
    D2 --- T2 & T3
    D5 --- T4
    D6 --- T5
    D8 --- T6
    D3 & D4 & D5 <--> LLM
    HUMAN -- "decision bound to plan_hash" --> HG
    AGENTS --> STORE
```

Legend: **tool agents** (Discovery, Detection) never call an LLM, so facts cannot be hallucinated.
**Judgement agents** (Evidence analyst, Investigator, Risk analyst summary) call the LLM, and their output is
grounded against stored Evidence before it is saved. The **human gate** is the only way to the validator.

## 2. What each agent does

| # | Agent | Uses AI? | Input | Output |
|---|---|---|---|---|
| 1 | Discovery | no | target repo | work copy, resolved lockfiles (`--ignore-scripts`), CycloneDX SBOM, dependency graph with origin + integrity |
| 2 | Detection | no | SBOM, graph, files | Findings with Evidence: CVEs (Grype, OSV cross-check), typosquats, install scripts, missing lockfile, unpinned CI, tag-only images, unexpected changes, policy violations |
| 3 | Evidence analyst | yes | finding + its evidence (inside `<data>` blocks) | explanation, initial risk, claims labelled VERIFIED / INFERRED by code |
| 4 | Investigator | yes, ReAct | suspicious non-CVE findings | up to 8 read-only tool calls (registry metadata, file excerpt, manifest diff) and a labelled conclusion |
| 5 | Risk analyst | summary only | findings + EPSS, KEV, reachability, exposure, scope, provenance | `score = 100 × (0.40 S + 0.15 E + 0.20 R + 0.15 P + 0.10 X)`, band, confidence, computed in Python |
| 6 | Remediation | no (deterministic) | top findings + safe-version and compatibility evidence | one plan per attempt: ops, unified diff, target from evidence, expected risk reduction, rollback, `plan_hash` |
| 7 | Human gate | no | the saved plan | pauses (`interrupt()`); resumes only with an Approval for that `plan_id` and `plan_hash` |
| 8 | Validator | no | approved plan | applies it to a fresh copy, re-resolves lockfiles, builds and tests in Docker with no network, rescans, diffs SBOMs, re-runs detectors; verdict |
| 9 | Reporter | no | everything above | `report.json` (machine) and `report.html` (human) |

## 3. Approval points

1. **Before any change:** every plan stops at the human gate. The decision is bound to the plan's SHA-256
   hash: if the plan changed after it was shown, the approval does not apply (G5.1).
2. **Reject and accept risk need a written reason** (G5.2), and the reason is stored in `approvals.jsonl`.
3. **Who may decide:** with API tokens configured, only the `approver` role; the recorded `decided_by` is the
   authenticated identity, not a form field.
4. **Nothing is merged or pushed** (G5.5): a verified fix becomes a local branch with a `PR.md` in the attempt's
   copy. There is no tool for publish, push, merge or deploy (G3.4), and the harness greps for them.

## 4. Data sources

| Source | Used for | Offline behaviour |
|---|---|---|
| Syft (pinned binary in `tools/bin`) | component inventory / SBOM | reads local files |
| Grype (pinned binary in `tools/bin`) | vulnerability matches | requires a downloaded local vulnerability DB |
| OSV-Scanner (pinned binary in `tools/bin`) | advisory cross-check | Guardian reuses a cached result; skips on an offline cache miss |
| OSV API (`api.osv.dev`) | safe versions, advisories | disk cache |
| FIRST EPSS (`api.first.org`) | exploit probability | disk cache |
| CISA KEV (`www.cisa.gov`) | known exploited | disk cache |
| npm registry / PyPI | metadata, install scripts, maintainers, version heads | disk cache |
| GitHub (`git ls-remote`) | action tag → commit SHA | disk cache |
| Docker registries | image digests | disk cache |
| LLM provider | explanations, investigation, summaries | record / replay cache |

All outbound HTTP goes through `guardian/guardrails/network.py` (G3.5 host allowlist).
`GUARDIAN_OFFLINE=1` plus `GUARDIAN_LLM_MODE=replay` runs end to end with zero network calls (tested).

## 5. Evidence storage and audit

Every fact is an `Evidence` record (`runs/<id>/evidence/<ev_id>.json`) created by a tool, never by the LLM.
Findings, claims, risk factors and plans cite evidence ids. `trace.jsonl` holds every agent event (tool calls,
LLM calls, decisions D1..Dn, guardrail hits); `audit.jsonl` is the append-only audit log (G7.1).
LangGraph state is checkpointed in `runs/<id>/checkpoints.sqlite`, so a run paused at the gate can be resumed
by another process hours later.

## 6. Scalability

| Concern | Measure |
|---|---|
| Large dependency trees (Juice Shop: 1,656 components) | graph shows roots, direct deps and paths to findings only (§4.3); renders in well under 2 s |
| LLM cost | per-run caps on findings sent to the LLM and on tokens; record/replay cache |
| External APIs | disk cache, throttling, allowlist; batch EPSS (≤100 CVEs per call) |
| Many runs | runs are independent folders; API caps concurrent runs (`GUARDIAN_MAX_ACTIVE_RUNS`, HTTP 429) |
| Live trace | SSE reads `trace.jsonl` from a byte cursor (linear, not quadratic) |
| Sandbox | deps image cached by lockfile hash; CPU, memory, process and time limits per container |

## Validation speed

Measured on Juice Shop (recorded runs under `runs/`, per-phase `seconds` in the build_log / test_result evidence, trace
timestamps): one validation took 12-20 minutes. Install of the deps image 260-390 s whenever the patched lockfile
differed (the Angular frontend install + production build was rebuilt every time), integration tests ~330-385 s, unit
tests ~45-57 s, server build ~15 s, `resolve_lockfiles` up to ~90 s on the first try, syft + grype rescan 10-20 s, plus
the unpatched baseline (the same cost again) when no baseline was cached.

What changed (no G6 rule, G5 approval binding, G3.6 budget or verdict rule is relaxed):

* Deps image: one BuildKit stage per npm project, merged by `COPY --from`, so a changed root lockfile no longer
  invalidates the frontend install/build layers; registry downloads use a BuildKit cache mount (never part of the image,
  npm still verifies lockfile integrity). The image cache is checked before any build context is assembled, and a
  per-tag lock stops the baseline and patched runs from building the same image twice. No BuildKit: automatic retry
  without the mounts. Same image layout as before. `GUARDIAN_DEPS_CACHE_MOUNT=0` turns the mounts off.
* Unit and integration tests run concurrently after the build, each in its own container (same limits, `--network none`,
  non-root, `--rm`, explicit removal) on a private snapshot of the built tree. Results are judged in step order, so the
  verdict is the one the sequential order gives. `GUARDIAN_SANDBOX_PARALLEL=0` restores strictly sequential phases;
  `GUARDIAN_SANDBOX_MAX_CONTAINERS` (default 3) bounds test containers running at once in the process.
* Baseline prewarm: right after discovery the unpatched baseline starts in a daemon thread (cache key = lockfile hash +
  recipe, shared across runs in `data/cache/sandbox_baseline`), so approval -> verdict normally finds it cached. An
  in-flight baseline is joined, never run twice; a failed prewarm is swallowed and the validation recomputes.
  `GUARDIAN_PREWARM_BASELINE=0` disables it. It uses Docker CPU while the human is reading the report.
* Every `sandbox_validate` summary now lists the seconds of each phase.

Not changed on purpose: the integration suite always runs (no proof that a fix touches nothing it covers), the
signature audit stays inside the deps image (it costs seconds there), and per-phase timeouts keep their meaning.

## 7. Code map

| Area | Path |
|---|---|
| Workflow, state, run driver | `guardian/graph/` |
| Agents | `guardian/agents/` |
| Tools and detectors | `guardian/tools/` |
| Guardrails G1–G7 | `guardian/guardrails/` |
| LLM provider, record/replay | `guardian/llm/` |
| Data model (contract) | `guardian/core/models.py` |
| Reports | `guardian/reporting/` |
| API (FastAPI + SSE + auth) | `guardian/api/` |
| UI (React, React Flow) | `ui/` |

## 8. A route through the source for new readers

Read the following files in order to follow one finding from request to report.
Paths in this table are relative to the repository root.

| Start here | Question it answers |
|---|---|
| `guardian/cli.py`, `guardian/api/app.py` | How does a CLI command or UI request start/resume a scan? |
| `guardian/graph/workflow.py`, `guardian/graph/state.py` | Which node runs next, and which IDs survive a pause? |
| `guardian/tools/registry.py` | Which tools may an agent call, and how are facts stored as evidence? |
| `guardian/tools/sbom.py`, `guardian/tools/scanners.py` | How do Syft and Grype become inventory and vulnerability findings? |
| `guardian/tools/threat_intel.py`, `guardian/tools/risk_tools.py` | How do external responses and local checks become scoring evidence? |
| `guardian/agents/risk_analyst.py:build_factors` | How are evidence records converted into S, E, R, P, and X? |
| `guardian/core/scoring.py:compute` | How do those values produce score, band, and confidence? |
| `guardian/agents/remediation.py`, `guardian/agents/batch.py` | How are fix candidates proposed and decisions collected? |
| `guardian/guardrails/approval.py`, `guardian/agents/validator.py` | Why is approval bound to a particular plan, and what is validated? |
| `guardian/reporting/build.py`, `guardian/reporting/render.py` | How do run files become a validated report and an HTML export? |
| `ui/src/api/client.ts`, `ui/src/components/ValidationView.tsx` | How do stored results reach the browser? |

There are two different graphs. `core/graph_build.py` builds the **dependency graph**
of packages. LangGraph in `graph/workflow.py` builds the **execution graph** of agents.
Seeing a package node in the UI does not mean an LLM discovered or verified that package.

The diagram above shows the sequential approval loop. The current default setting is
`GUARDIAN_REMEDIATION_MODE=batch`: recommendations go through `recommend → batch_gate →
record_batch → validate_batch`. Decisions are collected before approved fixes are tested
together. Sequential mode uses `remediation → human_gate → record_decision → validator`.
Both reuse the analysis, evidence, and approval infrastructure. `max_plans == 0` disables
remediation; it does not disable discovery, detection, scoring, or reporting.

## 9. Trace a risk score back to its source

The current executable weights in `core/scoring.py:WEIGHTS` are **40/15/20/15/10** for
S/E/R/P/X. Older plans and saved runs may use different weights. Recompute a historical
run using its source revision and any recorded weight data, rather than silently applying today's code.
These weights and fallback values are project heuristics, not a calibrated probability.

| Factor | How the value is obtained | When information is missing |
|---|---|---|
| S | Scanner CVSS clamped to 0..10, divided by 10; non-CVE categories use `CATEGORY_SEVERITY` | Missing CVSS uses 0.5 and is marked unknown |
| E | KEV membership takes precedence; otherwise use the largest available EPSS percentile among CVE aliases | CVE without usable data uses 0.5 and is marked unknown |
| R | Supported function rule gives called=1; import evidence gives 0.6; no matched import gives 0.1 | Unknown is 0.5; not-applicable R transfers its weight to S |
| P | Dependency-graph scope, then the finding's scope: prod=1, dev=0.3 | Unknown is 0.7; applicable configuration findings use prod scope |
| X | Exposed-port signal plus server-path import gives network=1; internal=0.5 | Unknown is 0.5; unknown X does not reduce scoring confidence |

Non-CVE malicious-indicator findings receive E=1; other non-CVE categories use E=0.5.
This is a category rule, not proof that exploitation occurred. An EPSS **percentile**
is a rank relative to other vulnerabilities; it is not the raw EPSS probability.

For example, CVSS 9.8, unknown exploitation data, imported code, production scope,
and network exposure give:

```text
S: 0.98 × 40 = 39.2 points
E: 0.50 × 15 =  7.5 points  (unknown default, not 50% attack probability)
R: 0.60 × 20 = 12.0 points
P: 1.00 × 15 = 15.0 points
X: 1.00 × 10 = 10.0 points
Total:          83.7 / 100 → Critical; confidence Medium because E is unknown
```

The provenance modifier adds five points under its defined failure rule, capped at 100.
A KEV-listed, reachable production finding receives at least High priority, even when
its numeric score is lower. This override changes the band, not the score.

Each factor records its value, tier, evidence IDs, and unknown flag in `risk.json`.
Open the referenced files in `evidence/` to inspect the original facts. A label such as
`INFERRED` can describe a deterministic fallback; it does not necessarily mean an LLM
estimated it. Confidence is a separate missing-input indicator, not another risk score.

## 10. Understand what approval and validation prove

Plans are saved before review. An approval names the plan ID and its content hash;
changing a plan invalidates that approval. The sequential gate only calls `interrupt()`
because LangGraph re-enters the node on resume. Decision recording and write-tool checks
then enforce the binding. Batch mode applies the same principle to its submitted plans.

A separate working copy protects the original files from edits. It is **not** execution
isolation. Docker supplies the validation environment, with non-root execution,
resource limits, and network-disabled build/test containers. Dependency-image setup
uses the network; some frontend preparation happens there. The optional built-image
rescan also has its own documented network-enabled build limitation.

Read the actual result fields in `validation/` and the linked log evidence:

| Result | What a reader can conclude |
|---|---|
| Target absent on re-scan | The relevant detector/scanner no longer reports the targeted issue |
| `build_ok: true` | The recorded build phase succeeded |
| Empty unit/integration counts | No corresponding test counts were recorded; do not call this a pass |
| Failed tests also present in the unpatched baseline | The failures may predate the fix; inspect the comparison and notes |
| `group_failure: true` | A combination failed; this does not identify which fix caused it |
| Targeted test evidence | Only the named subset ran; it is not a full regression result |
| Docker unavailable or sandbox off | Execution checks are skipped and must stay visible as skipped |

`GUARDIAN_DEMO_VALIDATOR=1` uses simulated preview behavior. It demonstrates the workflow,
not real container execution. Keep this distinct from a real Docker run with a deliberately
limited test scope. A display label or a lower score is not a substitute for execution logs.

`report.json` is the structured report; `report.html` is its rendered presentation.
An interim report can exist while another decision is pending. That report describes
completed work so far, not completion of every remediation. The workflow checkpoint,
pending decision, and remaining-risk sections explain what still needs attention.
