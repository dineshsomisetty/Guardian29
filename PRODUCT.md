# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

React + Vite + TypeScript + React Flow (dagre layout), set by GUARDIAN_PLAN.md §2.1 / D3-01. Reads static run
files from `make serve-runs` (http://localhost:8001/latest/). FastAPI routes come later (D3-03) with the same
JSON shapes.

## Users

Primary: hackathon judges and mentors (Bosch software-supply-chain challenge) watching a live demo on a
projector or shared screen during the 3-minute Checkpoint-1 talk (16:30) and the final Day-2 demo. They read it
from across a room first, then ask pointed questions ("why is this risky?", "how do you control
hallucination?") while a developer clicks into detail. Secondary: the five-person team rehearsing and debugging runs.

## Product Purpose

Guardian is an agentic AI that analyses a software project's supply chain: it discovers every dependency
(SBOM + dependency graph), detects vulnerabilities and supply-chain anomalies, and explains each risk with
evidence. CP1 success: in one view, show what is in the app, what changed, and what is risky — produced by a
visible multi-agent pipeline.

## Positioning

"Tools produce facts. Agents make decisions and explanations. Humans approve changes." Every claim the AI makes
cites evidence IDs and is labelled by code as VERIFIED (matches tool facts) or INFERRED; invented CVEs are
rejected. The first read for a viewer is that agents reasoned over evidence — the trace of agent roles,
hand-offs and routing decisions, and the VERIFIED/INFERRED labels — not just a CVE list.

## Operating Context

- Live demo flow (§3.3): run the command → agent trace (discovery → detection → evidence analyst) → header
  counts → graph: direct vs transitive, click a vulnerable package, show path to its direct parent, origin +
  integrity → one CVE and one anomaly with evidence → "what changed" diff.
- Target app: OWASP Juice Shop (two npm projects: root + frontend), ~1,670 packages, ~70 findings, 7 CI
  pseudo-nodes / 5 image nodes / config nodes.

## Capabilities and Constraints

- Run files per §4.1: `run_summary.json`, `graph.json` (package nodes with version, scope, project, origin,
  integrity, risk, finding_ids; pseudo-nodes `ci:`, `image:`, `config:`), `findings.json`, `evidence/<id>.json`,
  `changes.json`, `trace.jsonl` (AgentEvent).
- Graph scale rule (§4.3): render only roots, direct deps, nodes on a path to a finding, pseudo-nodes; collapse
  the rest with a count. Must render < 2 s.
- Risk levels: critical / high / medium / low. Claim labels: verified / inferred (unsupported claims removed).
- Initial risk may come from the LLM ("llm") or the rule fallback ("rule"); show which, honestly.
- No binding offline, brand or accessibility constraints were given.

## Brand Commitments

Name: Guardian. No logo or brand assets exist.

## Evidence on Hand

Real run output under `runs/<run_id>/` from Juice Shop (commit c9f99228d). No customers, testimonials or
benchmarks exist; do not invent any.

## Product Principles

1. Evidence before assertion: every risk shown links to the tool evidence behind it.
2. Show the reasoning, not just the result: agent roles, hand-offs and decisions are first-class.
3. Honest labels: VERIFIED vs INFERRED vs rule-based is always visible, never blurred.
4. Legible at a distance, precise up close.
