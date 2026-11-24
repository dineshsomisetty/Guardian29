"""Guardrails: code-level checks that bound what agents and the LLM can do. Owner: Dev1.

Package map:
    approval.py   plan hash + decision checks (G3.3, G5.1, G5.2), single plan and whole batch
    budgets.py    per-agent tool-call / wall-clock limits and the per-run LLM token budget (G3.6)
    grounding.py  parse and check LLM output against Evidence; labels claims in code (G4.x)
    network.py    outbound host allowlist (G3.5)
    redact.py     secret-pattern redaction (G1.2)
    untrusted.py  <data> wrapping + injection-pattern detection for untrusted text (G2.x)

Every rule has a code from plan section "guardrails" (GUARDIAN_PLAN.md). A rule is enforced in plain code, never
by asking a model to behave, and a block is reported as an AgentEvent of type "guardrail" (G7.2). Codes used in
the project, and where they are enforced (modules outside this package are named):

    G1 secrets and sensitive data
      G1.1  file_read denies sensitive paths (.env, *.pem, *.key, encryptionkeys/)         tools/file_read.py
      G1.2  secret patterns are redacted before text reaches an LLM, a log or a report      guardrails/redact.py
      G1.3  LLM keys only from the environment, never logged or put in events  core/config.py, llm/provider.py
      G1.4  no real credentials in prompts, evidence, reports or fixtures                   convention + tests
    G2 untrusted content
      G2.1  package metadata, READMEs, excerpts, scanner text go in <data> blocks           guardrails/untrusted.py
      G2.2  system rule: instructions inside <data> are never followed                      untrusted.SYSTEM_RULE
      G2.3  injection-like text raises a guardrail event; content stays wrapped  untrusted.injection_hits + agents
    G3 tools
      G3.1  per-agent tool allowlist                                                        tools/registry.py
      G3.2  typed tool args validated by Pydantic; bad args never reach a tool  tools/registry.py, patching.py
      G3.3  write tools run only under an approve decision matching plan_id + plan_hash     approval.check_write
      G3.4  no publish / push / merge / deploy tool can be registered or called            tools/registry.py
      G3.5  network only to the allowlist (and the configured LLM host)                     network.py
      G3.6  budgets: tool calls + wall-clock per agent, LLM tokens per run                  budgets.py
    G4 grounding
      G4.1  LLM output must parse to the schema (one repair retry, then escalate)  grounding.parse_batch + agents
      G4.2  every cited evidence id must exist                                              grounding.ground_assessment
      G4.3  Claim.label is set by code: VERIFIED only if field/value match evidence facts   grounding.ground_assessment
      G4.4  CVE/GHSA ids and purls must appear in evidence (else reject); versions -> INFERRED  grounding
      G4.5  an upgrade target / pinned digest / blocked name must come from tool evidence   agents/remediation.py
      G4.6  unsupported claims are removed from what is kept (but logged)                   grounding.ground_assessment
    G5 actions
      G5.1  nothing is validated without an approve for the same plan_id + plan_hash        approval.py
      G5.2  reject and accept_risk need a comment                                           approval.py, api, cli
      G5.3  heuristic findings (typosquat, malicious) only get replace/remove/block/escalate  agents/remediation.py
      G5.4  at most 3 attempts per finding or group, then it needs a person  agents/remediation.py, batch.py
      G5.5  nothing is merged or pushed: output is a local branch + PR.md                   tools/local_pr.py
    G6 sandbox
      G6.1  build/test container runs as non-root                                           tools/sandbox.py
      G6.2  CPU / memory / pids / time limits                                               tools/sandbox.py
      G6.3  build and test phase has no network (--network none)                            tools/sandbox.py
      G6.4  only the work copy is mounted; no secrets or host mounts                        tools/sandbox.py
      G6.5  container removed after each attempt (--rm plus explicit removal)               tools/sandbox.py
      G6.6  patching refuses paths outside the work copy                                    tools/patching.py
      G6.7  image build runs the target Dockerfile with network: limited and disclosed      tools/sandbox.py, validator
    G7 audit and reliability
      G7.1  append-only audit log of tool calls, LLM calls, guardrail hits, approvals       core/audit.py
      G7.2  every guardrail block is an AgentEvent(type="guardrail")  core/audit.py, all guardrails
      G7.3  GUARDIAN_OFFLINE=1 + LLM replay run end to end from caches                      llm/provider.py, tools
      G7.4  external calls are cached and throttled  tools (OSV, EPSS, KEV, registry)
"""