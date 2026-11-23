# Guardian — guide for AI coding agents

Read this, then `context.md` (current state + code contracts), then GUARDIAN_PLAN.md §0–§5 and your tasks in §6.

## Before you write code
1. Ask which developer you work for (Dev1–Dev5). Only edit paths that developer owns (plan §8). Need a change
   elsewhere? Put it under "Requests to other owners" in the PR / chat — don't edit it.
2. Show the plan before code. Small commits on `devN/<task-id>-short-name`, Conventional Commits + task id,
   e.g. `feat(tools): grype wrapper [D2-04]`.
3. Don't invent CLI flags or library APIs. Check `--help` or current docs, and say what you checked.
4. If blocked or ambiguous: stop and report.

## Hard rules (enforced by CI or guardrails)
- No `shell=True`, no `git push` / `npm publish` inside `guardian/` (`scripts/check_forbidden.py`).
- Never run a target's install scripts outside the sandbox: `--ignore-scripts` during discovery.
- Never read or print `encryptionkeys/`, `ctf.key`, `.env*`, `*.pem`, `*.key` — use
  `guardian.tools.file_read.file_read`, which denies them (G1.1).
- No secrets in code, prompts, evidence, fixtures or events. Keys only from env (G1.3).
- Tools produce facts (`Evidence`); agents never create Evidence. Every `Finding` cites ≥1 evidence id.
- Untrusted text (package metadata, file excerpts, scanner text) reaches an LLM only via
  `guardian.guardrails.untrusted.wrap` (`<data>` blocks, G2).
- LLM output is checked by `guardian.guardrails.grounding` — never trust a label or id the model writes.
- Contract files (`guardian/core/models.py`, §4 file formats, `guardian/graph/state.py`) change additively only,
  announced in chat, Dev1 + Dev2 agree.

## Where things are
| Path | What |
|---|---|
| `guardian/core/models.py` | Pydantic data model (§5.1) |
| `guardian/core/store.py` | append-only JSON evidence/finding store |
| `guardian/core/audit.py` | `trace.jsonl` (AgentEvents) + `audit.jsonl` |
| `guardian/tools/registry.py` | `ToolContext` / `ToolOutput` contract, `BINDINGS` agent → tools |
| `guardian/graph/workflow.py` | LangGraph graph, supervisor routing, run driver, `graph.json` / `run_summary.json` |
| `guardian/agents/` | discovery, detection (dedupe), evidence_analyst (LLM) |
| `guardian/llm/provider.py` | Anthropic / OpenAI-compatible backends, live/record/replay |
| `guardian/guardrails/` | redact (G1.2), untrusted (G2), grounding (G4) |
| `guardian/prompts/` | system prompts (deliverable) |
| `tests/integration/fake_tools.py` | reference implementations of the tool contract |

## Done means
`make check` green, a test for each task's acceptance line (§6), and — for tools — your function plugged into
`BINDINGS` producing Evidence + Findings in a real `python -m guardian run`.
