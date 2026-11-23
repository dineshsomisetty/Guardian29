# Guardian decisions

## DEC-001 — Juice Shop target baseline

- Status: verified 2026-11-23.
- Source: `https://github.com/juice-shop/juice-shop.git`
- Commit: `c9f99228d9d56afb5f5ca7925376292f7fa44b13`
- Recorded: 2026-11-23
- Reproduction: `scripts/fetch_targets.sh`

The commit was resolved from the repository's public `HEAD` and then pinned so
the Day-1 scan does not drift. Before changing it, update
`scripts/fetch_targets.sh`, `docs/targets.md`, and re-verify every Section 10
fact in `GUARDIAN_PLAN.md`.

## DEC-002 — Generate backup lockfiles without changing the target

Juice Shop deliberately sets `package-lock=false` in its committed `.npmrc`.
The plan's normal `npm install --package-lock-only --ignore-scripts` command
therefore runs safely but creates no lockfile. For the two backup fixtures we
used the same command with the temporary process-only configuration
`npm_config_package_lock=true`. This preserves the source checkout's missing
lockfile condition for detection while producing reproducible fixtures under
`tests/fixtures/juice-shop/`.

Dev2 needs this configuration override (or an equivalent documented workspace
configuration) when resolving the two projects. Do not remove the target's
`.npmrc` during discovery: it is evidence for the missing-lockfile finding.

## Mentor decisions required

The following questions were assigned to Dev5 in `GUARDIAN_PLAN.md` §11. No
answers are present in this repository yet, so they must be confirmed with the
mentor and recorded below before the relevant work is treated as approved.

| ID | Question | Status / answer |
|---|---|---|
| M-01 | What must CP1 at 16:30 show: graph only, or CVEs and anomalies too? How is it evaluated? | Pending mentor response |
| M-02 | When is the Day-1 milestone; when do Day 2 and the final demo begin? | Pending mentor response |
| M-03 | Are public read-only APIs (npm, OSV, EPSS, CISA KEV, GitHub) and the LLM API allowed? | Pending mentor response |
| M-04 | Is a local clone/branch acceptable for the remediation-branch stretch goal? | Pending mentor response |
| M-05 | Is there an LLM/API cost limit, or a preferred local/open model? | Pending mentor response |
| M-06 | Is sandboxed `docker build`, which executes the target Dockerfile's install step, allowed? | Pending mentor response |
