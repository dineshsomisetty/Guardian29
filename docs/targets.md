# Guardian target inventory

## Juice Shop (primary target)

| Field | Value |
|---|---|
| Source | `https://github.com/juice-shop/juice-shop.git` |
| Pinned commit | `c9f99228d9d56afb5f5ca7925376292f7fa44b13` |
| Local path | `targets/juice-shop` (gitignored) |
| Fetch command | `scripts/fetch_targets.sh` |
| Target status | Verified against the pinned checkout on 2026-11-23 |

### Section 10 verification record

This table is deliberately completed only from the pinned local checkout. It
keeps the plan's expected findings separate from facts verified against the
demo target.

| Plan fact | Expected location | Verification |
|---|---|---|
| `.npmrc` disables package-lock generation | `.npmrc` | Verified: `package-lock=false` at line 1 |
| Vulnerable security-library versions are present | `package.json` | Verified: `express-jwt` 0.1.3 (line 109), `jsonwebtoken` 0.4.0 (line 123), `sanitize-html` 1.4.2 (line 136) |
| `ngy-cookie` is present | `frontend/package.json` | Verified: `^6.0.0` at line 59 |
| Legacy typosquat manifest exists | `ftp/package.json.bak` | Verified: path exists; contents not executed |
| Coveralls action is not SHA-pinned | `.github/workflows/ci.yml` | Verified: `coverallsapp/github-action@v2` at line 198 |
| Docker base images are tag-only | `Dockerfile` | Verified: `node:24` (line 1) and `gcr.io/distroless/nodejs24-debian13` (line 22) |
| Sensitive-file paths exist, without reading their contents | repository paths only | Verified: `encryptionkeys/` and `ctf.key` exist; contents were not read |
| `test:server` and `test:api` scripts exist | `package.json` | Verified at lines 69 and 71; not run during discovery |

### Script-safe backup lockfiles

The target's committed `.npmrc` disables lockfile generation. The unmodified
plan command completed safely but did not create a file, as expected. The
backup fixtures below were created with
`npm_config_package_lock=true npm install --package-lock-only --ignore-scripts`.
No `node_modules` directory was created and no install script was run.

| Project | Fixture | Observed resolve time | Size | SHA-256 |
|---|---|---:|---:|---|
| root | `tests/fixtures/juice-shop/package-lock.json` | 8 s | 581,557 bytes | `01ae5cab495fadf3c391385771035c6b1eb71ee44eebd188a9669d3f2bd2e819` |
| frontend | `tests/fixtures/juice-shop/frontend.package-lock.json` | 43 s | 449,805 bytes | `f493e99ef15f00a3b6516ab6f291193738ba2ef594f2ace98c62a8528f4ef572` |

These are backup inputs for Dev2's resolver; the original target remains clean
and lockfile-less so the planned anomaly can be demonstrated.

## PyGoat (secondary target)

Pending D5-07. The project and container build must be verified before it is
adopted as the second target.
