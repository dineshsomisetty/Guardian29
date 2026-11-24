"""Supply-chain detectors: the deterministic checks the detection agent runs over the target repository.

Each tool module exposes `detect(ctx: ToolContext) -> ToolOutput`, registered in tools/registry.py as
`detector:<name>` (unexpected_change as `changes`); outdated and similarity are helpers, not tools. A detector reads
the work copy (ctx.work_dir, or ctx.repo for the untouched original), makes no LLM call, and returns
Findings plus the Evidence rows that justify them (every Finding lists its
evidence_ids). Registry lookups go through the cached, offline-safe, G3.5-checked clients, so with
GUARDIAN_OFFLINE=1 a cache miss means "no extra facts", never an error.

Detector            Finding category(ies)                       How it decides
------------------  ------------------------------------------  ---------------------------------------------------
ci_pin              unpinned_ci                                 GitHub Actions `uses:` ref or GitLab CI `include:`
                                                                that is not a 40-char commit SHA (local ones skipped)
image_pin           untrusted_image                             Dockerfile / GitLab CI image with no @sha256 digest;
                                                                evidence lists newer explicit tags (image_tags.py)
install_scripts     install_script                              lockfile entries with hasInstallScript (project
                                                                itself excluded); script text read from the registry
lockfile            lockfile                                    a project without a lockfile, or .npmrc with
                                                                package-lock=false (checked on the original repo)
typosquat           typosquat                                   direct dependency name close to a popular package
                                                                (similarity.py) unless the registry shows it is long
                                                                established (5+ years and 30+ stable releases)
package_risk        maintainer_change, provenance_gap,          registry metadata of direct prod packages: full
                    dependency_confusion                        maintainer takeover, release bursts, missing
                                                                signatures/attestations, internal names that exist
                                                                publicly (rules in tools/package_risk.py)
unexpected_change   unexpected_change, major_jump,              diff against a baseline: the legacy ftp/*.bak
                    integrity_change, install_script            manifests, or `--compare-ref <git ref>`
outdated            "outdated" (plain dicts, wrapped by caller) deprecated version, latest release older than
                                                                max_age_years, or >= major_behind majors behind
similarity          none (library)                              Damerau-Levenshtein / affix name matching used by
                                                                typosquat and the policy check

Policy-as-code (tools/policy.py) is not in this package: it reuses `similarity.check_name`.
Evidence kinds used here: file_excerpt, registry_metadata, detector_result, diff, changes (see each module).
"""
