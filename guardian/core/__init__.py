"""Guardian core: the data and bookkeeping that every agent and tool shares. No agent logic lives here.

Package map:
    models.py      pydantic data model (Evidence, Finding, RiskAssessment, RemediationPlan, Approval, ...)
    config.py      Settings from the environment / .env (LLM provider and mode, budgets, remediation mode)
    store.py       JsonStore: append-only Evidence + Findings of one run (runs/<id>/evidence, findings.json)
    audit.py       AuditLog: trace.jsonl (UI events) and audit.jsonl (machine record), G7.1 / G7.2
    scoring.py     initial-risk rule and the full S/E/R/P/X risk score (pure functions, recomputable)
    plans.py       run files of the remediation loop: plans, approvals, validations, pending gate state
    recs.py        batch-mode recommendations.json (one Recommendation per fix and its outcome)
    graph_build.py dependency graph (networkx) built from lockfiles / SBOM, with paths_to()
    workspace.py   work copy of the target repository (no .git) that all later steps use
"""