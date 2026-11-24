# Generality and scale: Guardian on six real repositories

Same command, no per-target configuration: `uv run python -m guardian run --repo targets/<name>`.
LLM: DeepSeek (live, recorded for offline replay). Machine: Windows 11, 20 CPUs, Docker Desktop.
Time and peak memory are for the whole run (all agents, scanners and LLM calls) up to the human gate.

| Target | Ecosystem / layout | Packages (direct) | Findings | Time | Peak memory | Output |
|---|---|---|---|---|---|---|
| OWASP Juice Shop | npm, root + Angular `frontend/`, GitHub Actions, Dockerfile | 1,656 (154) | 91 | ~65 s | n/a | ~8 MB |
| PyGoat | pip (Django), 8 lab `requirements.txt` | 58 (58) | 470 | ~45 s | n/a | n/a |
| OWASP NodeGoat | npm (older deps) | 1,091 (36) | 326 | 127 s | 291 MB | 7.1 MB |
| vulnerable-rest-api | npm, **no root package.json**: `client/` (React) + `server/` (Express) | 475 (20) | 275 | 58 s | 268 MB | 7.5 MB |
| vuln_django_play | pip (Django), **GitLab CI** | 27 (27) | 57 | 57 s | 275 MB | 1.9 MB |
| OWASP WebGoat | **Maven (Java)**, GitHub Actions | 49 (49) | 57 | 47 s | 213 MB | 1.0 MB |

Every run paused at the human gate with an evidence-backed plan:
Juice Shop `express-jwt` 0.1.3 → 3.4.0 (pulls a fixed `jsonwebtoken`), PyGoat and vuln_django_play `Django` →
4.2.26, NodeGoat `underscore` → 1.12.1, vulnerable-rest-api `mongoose` → 7.8.3 (in `server/package.json`),
WebGoat: pin `actions/checkout@v7` to its commit SHA (Maven libraries are prioritised but not patched).

## What running new repositories found (all fixed, each with a regression test)

| Repo | Problem | Fix |
|---|---|---|
| vuln_django_play | GitLab CI ignored: only `.github/workflows` was read | GitLab adapter: job/service images and `include:` refs are findings; digest pinning patches GitLab files (`tests/unit/test_gitlab_ci.py`) |
| WebGoat | Maven packages treated as npm: reachability searched JS files, called a used library (`xstream`) "not imported" and offered "mitigate" | ecosystems kept as they are; Java/Kotlin imports matched by groupId; an ecosystem without a scanner is "unknown", never "not imported" |
| WebGoat | OSV gave Maven findings npm purls: 36 duplicate advisories that never merged with Grype's | OSV purls match Syft/Grype for every ecosystem (93 → 57 findings) |
| WebGoat | Java integration tests (`src/it`, `*IT.java`) counted as production code | JVM test conventions excluded |
| vulnerable-rest-api | `query-string` flagged as a typosquat of `querystring` | lookalikes the registry shows are established (≥ 5 years and ≥ 30 releases) are cleared, with the decision kept as evidence; `ngy-cookie` and `epilogue-js` stay flagged |
| WebGoat | empty dependency graph crashed `graph.json` | a root is always present |
| PyGoat | Django app tests (`*/tests.py`) never ran in the sandbox | Django test runner detected (54/54 pass) |
| Juice Shop | API tests need the built Angular frontend | subprojects built by the root build are prebuilt in the deps image (API 559/580 = baseline) |

## Why it scales

* **Big trees stay readable:** the graph view draws roots, direct dependencies and paths to findings only
  (Juice Shop: 57 of 1,656 drawn), so render time does not grow with the tree.
* **LLM cost is capped:** at most `GUARDIAN_MAX_LLM_FINDINGS` (40) findings go to the model per run and tokens
  are budgeted; everything else is scored by rule. A run with 470 findings (PyGoat) took ~45 s.
* **External calls are cached and throttled:** registry, OSV, EPSS, KEV, image tags and digests, OSV-Scanner
  output; repeat runs and offline demos make no network calls (tested).
* **Sandbox work is cached:** the dependency image is keyed by the lockfiles (+ prebuilt subproject sources),
  so only the first validation of a project pays the install; later attempts reuse it.
* **Many runs:** each run is its own folder; `--repos` runs several targets; the API caps concurrent runs
  (`GUARDIAN_MAX_ACTIVE_RUNS`, HTTP 429) and streams traces from a byte cursor.
* **Memory:** 210–290 MB peak per run across the six repositories.

## Known limits

* Fixes are applied for npm and pip; Maven and other ecosystems are scanned, scored and prioritised only.
* Reachability: imports for npm, pip and Maven (Java/Kotlin); function-level rules for the demo packages.
* The popular-package list for typosquats is hand-written (342 npm names); the established-package rule keeps
  false positives down but cannot find a typosquat of a package missing from the list.
