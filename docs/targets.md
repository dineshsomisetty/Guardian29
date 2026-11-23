# Targets

Owner: Dev5 (D5-01, D5-03, D5-07). Fetch both with `scripts/fetch_targets.ps1` (idempotent, pinned commits).
`targets/` is gitignored. **Never run a target's install scripts outside the sandbox** (`--ignore-scripts`).
**Never open or print** `encryptionkeys/`, `ctf.key`, `.env*`, `*.pem`, `*.key` — use `guardian.tools.file_read`.

## 1. OWASP Juice Shop (primary, npm)

| | |
|---|---|
| Repo | https://github.com/juice-shop/juice-shop |
| Pinned commit | `c9f99228d9d56afb5f5ca7925376292f7fa44b13` (2026-11-19), version `20.4.0-SNAPSHOT` |
| Projects | two npm projects → two roots in one graph: `root` (`package.json`) and `frontend` (`frontend/package.json`) |
| Lockfiles | **none committed** |

### Plan §10 facts — verified 2026-11-23 at the pinned commit

| # | Fact | Location | Status | Guardian finding |
|---|---|---|---|---|
| 1 | Lockfile generation disabled: `package-lock=false` | `.npmrc:1` | confirmed | `lockfile` |
| 2 | Old security libs `express-jwt 0.1.3`, `jsonwebtoken 0.4.0`, `sanitize-html 1.4.2` | `package.json` | confirmed | `cve` (ids from Grype/OSV) |
| 3 | `"ngy-cookie": "^6.0.0"` (Frontend Typosquatting challenge) | `frontend/package.json:59` (plan said ~58) | confirmed, line corrected | `typosquat` (looks like `ngx-cookie`) |
| 4 | Legacy typosquat `epilogue-js` (Legacy Typosquatting challenge) | `ftp/package.json.bak:46` | confirmed | `typosquat` (looks like `epilogue`) + removed in `changes.json` |
| 5 | `coverallsapp/github-action@v2` not SHA-pinned (the other actions in `ci.yml` are SHA-pinned) | `.github/workflows/ci.yml:198` | confirmed | `unpinned_ci` |
| 6 | Base images tag-only: `node:24`, `gcr.io/distroless/nodejs24-debian13`; `EXPOSE 3000` | `Dockerfile:1`, `Dockerfile:22` | confirmed | `untrusted_image` |
| 7 | Sensitive files `encryptionkeys/`, `ctf.key` present | repo | present — never read | — |
| 8 | `npm run test:server` and `test:api` exist | `package.json` scripts | scripts exist; offline run + timing **not yet measured** (D5-03, 17:00) | validator tests (Day 2) |

Extra non-package findings the run also reports (not in §10): unpinned actions in `codeql-analysis.yml`
(3, `@v3`) and `image_actions.yml` (3, incl. `calibreapp/image-actions@main`); tag-only images in
`infrastructure/Dockerfile` (2) and `test/smoke/Dockerfile` (`alpine`).

### Lockfile resolve (backup, D5-01)

```
npm install --package-lock-only --ignore-scripts --package-lock=true                       # root      ~62 s
npm install --package-lock-only --ignore-scripts --package-lock=true --legacy-peer-deps    # frontend  ~45 s
```
`--package-lock=true` is needed because `.npmrc` disables lockfiles; `frontend/` needs `--legacy-peer-deps`
(peer-dependency conflicts). Resolved lockfiles are committed as fixtures in
`tests/fixtures/juice-shop/{root,frontend}/`; a run reuses them when `package.json` is byte-identical, which is
why the full pipeline takes about a minute (LLM step included) instead of ~2.5 min.

### Run numbers (run `run_20261123_172422`, 2026-11-23)

| Metric | Value |
|---|---|
| Components | **1,656** unique package versions — 154 direct, 1,502 transitive (SBOM: 1,993 entries incl. dev dependencies and packages shared by the two projects) |
| Graph | 1,668 nodes (1,656 packages, 2 project roots, 10 pseudo-nodes: 5 image, 3 ci, 2 config), 3,213 edges |
| Findings | **72** — 7 critical, 21 high, 38 medium, 6 low |
| By category | cve 57, unpinned_ci 7, untrusted_image 5, typosquat 2, lockfile 1 |
| Dedupe | 56 Grype/OSV duplicates merged by (purl, id/alias) |
| What changed | `ftp/package.json.bak` → `package.json`: 74 added, 50 removed (incl. `epilogue-js`), 22 version changes |
| Duration | ~55 s pipeline including the DeepSeek step |
| LLM | `deepseek-chat`, mode `record` — all 72 findings explained (231 claims: 154 VERIFIED, 77 INFERRED); 4 guardrail hits (G4.4) |

Golden expectations: `tests/golden/juice_shop_expected.yaml`.

## 2. PyGoat (second target, pip)

| | |
|---|---|
| Repo | https://github.com/adeyosemanputra/pygoat |
| Pinned commit | `2aa4cc14f251e4a780e94e200aed6b36a5b15c21` (2026-11-01) |
| Ecosystem | Python / Django, `requirements.txt` (32 lines) |
| Container | `Dockerfile` (multi-stage, `FROM python:3.11-slim-bookworm AS builder`) and `docker-compose.yml` present |
| Build + timing | **not yet measured** (D5-07, 17:00–18:30) |

## 3. To fill in (Day 1 evening)

- [ ] Juice Shop `test:server`, `test:api`, image build timings (D5-03)
- [ ] PyGoat `docker build` works + timing (D5-07); if not, pick another small containerised pip app
