# Guardian — decisions

Owner: Dev5 (D5-01, D5-04). Source of truth for *why*; GUARDIAN_PLAN.md is the source of truth for *what*.
Last updated 2026-11-23, before CP1 (16:30).

## 1. Open questions — ask the mentor (plan §11)

No answers recorded yet. Do **not** fill these in from assumptions; write the mentor's words and the time.

| # | Question | Answer (mentor, time) | Impact if "no" |
|---|---|---|---|
| Q1 | What exactly must CP1 at 16:30 show — graph only, or also CVEs/anomalies? How is it evaluated (demo / slides)? | _open_ | Talk track (docs/cp1_talk_track.md) is built for "graph + risky + changed, live demo" |
| Q2 | When is the full Day-1 milestone checked today? What time is the final demo tomorrow, and when does Day 2 start? | _open_ | Plan §3.5/§3.6 assume 20:00 today and a 09:00 Day-2 start |
| Q3 | Are we allowed to call public read-only APIs (npm registry, OSV, EPSS, CISA KEV, GitHub API for tag→SHA) and our LLM provider API? | _open_ | Fall back to `GUARDIAN_OFFLINE=1` (intel cache) and LLM replay |
| Q4 | Is our own local clone/branch acceptable for the remediation-branch stretch goal? | _open_ | Remediation stays a patch file + plan, no branch |
| Q5 | Any limit on LLM provider or API cost? Is a local/open model preferred? | _open_ | `GUARDIAN_LLM_PROVIDER=openai_compat` + `LLM_BASE_URL` points at a local model |
| Q6 | Is `docker build` of the target (which runs its Dockerfile's `npm install`) acceptable inside our sandbox? | _open_ | Validation limited to SBOM rescan of the resolved tree; image build documented as limitation (G6.7) |

## 2. Why we chose X (plan §12)

| Choice | Why |
|---|---|
| Multi-agent with LangGraph | Stateful graph, loops for re-planning, built-in human-in-the-loop interrupt + checkpointing |
| Tools produce facts, LLM only reasons | Prevents hallucinated CVEs/versions; every claim cites evidence |
| Deterministic Discovery/Detection "tool agents" | Facts must not be hallucinated; judgement agents sit on top |
| CycloneDX + purl as the core format | Standard; ecosystem-agnostic; scanners understand it → generality |
| Syft | Multi-ecosystem SBOM from dirs and images |
| Grype (+ OSV-Scanner cross-check) | SBOM-driven, fix versions included; second source reduces misses |
| `--package-lock-only --ignore-scripts` | Full tree without executing untrusted code |
| EPSS + KEV + reachability + exposure | Severity alone misleads; these measure real-world risk (Day 2) |
| Human gate before any change | Brief forbids auto-merge; safety |
| Docker sandbox, `--network none` for build/test | Contain untrusted code; no exfiltration (Day 2) |
| LLM record/replay | Reproducible demo; survives network/provider outage |
| JSON-file store → SQLite | Speed today, durability tomorrow, same interface |
| Juice Shop + PyGoat | Realistic, intentionally vulnerable, two ecosystems (npm + pip) |

## 3. Decisions made today (2026-11-23)

| # | Decision | Why | Alternative kept / rejected |
|---|---|---|---|
| T1 | **Dependency edges come from each project's `package-lock.json` `packages` map** (Node's resolution rule: nearest `node_modules/<dep>` walking up), not from Syft's CycloneDX `dependencies` | Syft's npm dependency relationships were incomplete for our needs; the lockfile is the exact tree npm would install, and it also carries `resolved` (origin URL) and `integrity` for every node | Syft still produces the SBOM (component inventory, purls) that Grype/OSV scan |
| T2 | **Resolved lockfiles committed as fixtures** in `tests/fixtures/juice-shop/{root,frontend}` | Juice Shop ships no lockfile (`.npmrc` `package-lock=false`); resolving takes ~62 s (root) + ~45 s (frontend) and needs the network. Fixtures make runs, tests and the demo deterministic | `resolve_lockfiles` reuses a fixture only when the target's `package.json` is byte-identical (hash match, recorded in evidence); otherwise it resolves live |
| T3 | **LLM: DeepSeek `deepseek-chat` via its OpenAI-compatible API**, JSON mode (`response_format: json_object`), schema in the system prompt, **reply validated by our own Pydantic parser** + grounding (G4) | Available key and low cost; JSON mode guarantees parseable JSON, our validator guarantees the shape; grounding rejects ids/purls the model invents | — |
| T4 | **Python Anthropic SDK path kept as an alternative** (`GUARDIAN_LLM_PROVIDER=anthropic`, native structured output); `openai_compat` + `LLM_BASE_URL` for a local model | One provider interface (`guardian/llm/provider.py`), switch by env var; answers mentor Q5 either way | — |
| T5 | **LLM record/replay** (`GUARDIAN_LLM_MODE=live|record|replay`); replay fails closed when a cache entry is missing | Reproducible CP1/demo; works offline | — |
| T6 | **No key or cache entry → rule-based initial risk** (`guardian.core.scoring.initial_risk`, CVSS bands / category defaults), logged as an `error` event; the run still completes | A provider outage must not stop discovery/detection; the trace shows honestly which findings had LLM review | — |
| T7 | **LLM budget**: up to `GUARDIAN_MAX_LLM_FINDINGS` (default 200) findings go to the evidence analyst, non-CVE anomalies first, then CVEs by rule risk and CVSS; any beyond the budget keep the rule-based risk (logged as a supervisor `decision`) | Bounds cost and latency; on Juice Shop (72 findings) everything is explained | A larger target needs a higher budget |
| T8 | **`serve-runs` refuses `/work/` paths** (HTTP 403) | The work copy of the target contains `encryptionkeys/`, `ctf.key` and similar; the UI only needs run output files (G1.1) | — |
| T9 | **Tools pinned and checksum-verified**: Syft 1.57.2, Grype 0.122.1, OSV-Scanner 2.7.1 (`scripts/install_tools.ps1`, SHA-256 against release checksums) | Reproducible results; supply-chain hygiene for our own tooling | — |
| T10 | **Targets pinned**: Juice Shop `c9f99228d`, PyGoat `2aa4cc1` (`scripts/fetch_targets.ps1`) | Golden file line numbers and counts depend on the commit | — |
| T11 | **Golden-file QA** (`tests/golden/juice_shop_expected.yaml`, `tests/integration/test_golden.py`) checks the latest real run against stable matchers (category + file + line / purl), never run-specific ids | Catches P0 regressions between CP1 and Day 2 | — |
$0
| T13 | **Syft runs with dev dependencies included** (`SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true`) | Syft's npm lockfile cataloger omits devDependencies by default: 615 of the 1,656 graph packages (all `scope=dev`) were missing from the SBOM, so Grype never scanned build tooling and the header count did not match the SBOM. Found by the CP1 checker; Grype now agrees with OSV-Scanner on 56 of its 57 matches | — |
