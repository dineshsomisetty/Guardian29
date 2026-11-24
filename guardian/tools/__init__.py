"""The tools layer: everything an agent can run against the target, behind one guarded entry point.

Map of the package
  registry.py     ToolContext (per-run state handed to every tool), ToolOutput (findings / evidence / artifacts),
                  the BINDINGS + ToolSpec tables and `call_tool`, the ONLY way an agent runs a tool. call_tool
                  applies the G3 guardrails (allowlist, typed args, approval for writes, budgets), logs audit
                  events and stores the returned Evidence.
  binaries.py     finds pinned syft/grype/git/docker binaries and runs them as argv lists (never a shell).
  resolve.py, sbom.py, scanners.py        discovery + detection: lockfiles, CycloneDX SBOM, Grype/OSV matches.
  detectors/      one module per non-CVE detector (lockfile, typosquat, ci_pin, image_pin, install_scripts,
                  unexpected_change, package_risk); each exposes `detect(ctx)`.
  threat_intel.py, risk_tools.py, reachability.py, provenance.py, package_risk.py
                  threat intelligence (cached, offline-safe) and the risk analyst's evidence tools.
  investigate.py, file_read.py            read-only investigator tools (registry metadata, file excerpts,
                  manifest diff); file_read denies sensitive paths (G1.1).
  patching.py     remediation: dry-run diff (plan_preview) and the write tool apply_plan.
  sandbox.py      Docker validation of a patched copy (build, tests, SBOM rescan + diff).
  local_pr.py     the write tool local_fix_branch: a LOCAL git branch + PR.md, nothing is pushed.

Read-only vs write tools
  Almost every tool only reads the target or the run directory, or writes inside runs/<id>/. The two tools that
  change files of a (copy of the) target, `apply_plan` and `local_fix_branch`, are declared with writes=True and
  `call_tool` refuses them unless a matching Approval (same plan_id + plan_hash) exists (G3.3). Names containing
  publish/push/merge/deploy cannot be registered or called at all (G3.4). Network access is limited to allowlisted
  hosts and is off when GUARDIAN_OFFLINE=1 (G3.5 / G7.3); the sandbox runs tests with `--network none` (G6.3).
"""
