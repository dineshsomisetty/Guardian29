"""Guardian: a software supply chain guardian that finds, ranks and (with human approval) fixes risky dependencies.

Given a target repository, Guardian inventories its dependencies (SBOM and dependency graph), detects
vulnerable or suspicious components, scores each finding's risk with evidence, proposes remediation plans,
stops at a human approval gate, then validates approved fixes in a sandbox and writes a report. Every step is
recorded in an audit trace. Run it with `python -m guardian ...` (see guardian/cli.py).

Sub-packages:
  agents      the LLM-backed agents (investigator, risk analyst, remediation, validator, ...) that do the reasoning
  tools       deterministic tools the agents call: scanners, threat intel, file reading, sandbox, registry
  core        shared data models, settings, scoring, run store, plans/recommendations and the audit log
  graph       the LangGraph workflow that wires the agents into a run and resumes it after a human decision
  guardrails  safety rules (G-numbered): approval checks, redaction, allowlists, limits on what agents may do
  llm         the model client with live / record / replay modes so runs are reproducible offline
  api         FastAPI service (REST + live trace over SSE) with token auth for the UI and CI
  reporting   builds and renders report.json / report.html from a finished run
  adapters    parsers for ecosystem files: npm, PyPI, Dockerfile, GitHub Actions, GitLab CI
"""
