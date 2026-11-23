# Responsible AI & Security note

## Where AI is used (and where it is not)

| Step | AI? | What the LLM may do |
|---|---|---|
| Discovery, Detection | **no** | SBOM, CVE matches and anomaly detection are produced by tools (Syft, Grype, OSV-Scanner, detectors) |
| Evidence analyst | yes | explain a finding and propose an initial risk, citing evidence ids |
| Investigator | yes | choose up to 8 read-only tool calls (registry metadata, file excerpt, manifest diff), then conclude |
| Risk analyst | summary only | the score, band and confidence are computed in Python from evidence; the LLM writes the summary |
| Remediation, validation, reporting | **no** | plans, target versions, patch diffs, verdicts are deterministic |

## How hallucinations are controlled (G4)

* Output must parse to a schema; one repair retry, then the finding is escalated (G4.1).
* Every cited evidence id must exist (G4.2).
* Claim labels (VERIFIED / INFERRED) are set by code, never by the LLM: VERIFIED only when the claimed field and
  value match an Evidence record's facts (G4.3).
* CVE/GHSA ids, versions and package URLs in LLM text must appear in cited evidence, else the claim is relabelled
  INFERRED or rejected (G4.4).
* A fix's target version must come from `safe_version_lookup` evidence; a plan citing any other version is
  refused (G4.5). Unsupported claims are removed from the report (G4.6).
* The UI and report always show "Verified fact" and "AI inference" separately.

## Untrusted content and prompt injection (G2)

Package metadata, READMEs, file excerpts and scanner text reach the LLM only inside `<data>` blocks; the system
prompt says instructions inside them are never followed. Injection patterns trigger a `guardrail` event, and the
content stays wrapped.

## Which actions need human approval (G5)

* **Every change.** The workflow pauses at the human gate (`interrupt()`); the validator is unreachable without
  an `approve` decision for the exact `plan_id` **and** `plan_hash` (G5.1).
* Reject and accept-risk need a written reason (G5.2).
* Heuristic findings (typosquat, malicious) may only be replaced, removed, blocked or escalated (G5.3).
* Three failed attempts escalate the finding to security review (G5.4).
* Nothing is merged, pushed, published or deployed; no such tool exists (G3.4, G5.5) and the harness checks it.
* With API tokens configured, only the `approver` role may decide; the recorded approver is the authenticated
  identity.

## How source code, credentials and secrets are protected (G1, G6)

* The target repo is never modified: work happens on copies under `runs/<id>/`.
* `file_read` refuses `encryptionkeys/`, `ctf.key`, `.env*`, `*.pem`, `*.key`, `id_rsa*`, `*.p12`, `*.pfx` (G1.1).
* Secret patterns (private keys, cloud/LLM/GitHub/npm tokens, JWTs, `password=`-style values) are redacted before
  text reaches an LLM, a log or a report (G1.2).
* LLM keys come only from the environment (`.env`, gitignored), are never logged or sent to the UI (G1.3).
* Dependency resolution runs `--ignore-scripts`, so no install script executes on the host.
* The sandbox runs as a non-root user with CPU, memory, process and time limits, `--cap-drop ALL`,
  `no-new-privileges`, read-only root, only the patched copy mounted, no secrets passed, `--network none` for
  build and test, and is removed after each attempt (G6).
* All outbound HTTP passes a host allowlist (G3.5); offline replay makes zero network calls.
* The API refuses to listen beyond loopback unless bearer tokens are configured; runs can only target
  directories under the allowed target roots.

## Audit (G7)

Every tool call, LLM call (with cache key), guardrail hit, decision and approval is written to `trace.jsonl` and the
append-only `audit.jsonl`; guardrail blocks are their own events.

## Known limitations

* Reachability is import-level (is the package imported in production code?), not function-level.
* The image build of the patched application (G6.7) is optional (`GUARDIAN_IMAGE_BUILD=1`) because it runs the
  target's Dockerfile with network on; by default the rescan covers the resolved dependency tree.
* LLM explanations need a provider key or a recorded replay cache; without one, rule-based risk is used and the
  run still completes.
