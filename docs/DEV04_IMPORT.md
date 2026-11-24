# Dev04 import from the integrated Guardian repository

Source: https://github.com/Nibiru7899/Guardian29/tree/6f55720
Destination base: dineshsomisetty/Guardian29 main at 3d21dcd.

This branch copies the Dev04 functional area from the source checkout: scoring,
threat intelligence, reachability and its reviewed rules, provenance, package-risk
helpers, outdated detection, CI/image pin detectors, policies, report generation,
and four related test modules. Source adapters, similarity logic, and the popular
package list were also compared/copied; files already identical to the base do
not appear in the diff. Existing source authorship and owner comments are retained.

The current integrated report builder is marked Dev1-owned, based on Dev04's
report skeleton. It is included as part of the reporting subsystem; this import
does not claim original authorship of that integration.

## Validation

The following tests passed in the complete source checkout: 20 passed.

    python -m pytest tests/unit/test_threat_intel.py tests/unit/test_package_risk.py tests/unit/test_policy_check.py tests/unit/test_reachability_called.py -q

The same selection cannot collect on this older destination base. This is a
scoped component import, not a complete runnable application upgrade.

## Requests to other owners before merging

Dev1/Dev2 integration is required for source-version dependencies absent from the
destination base, including:

- guardian/guardrails/network.py (threat-intelligence URL checks).
- guardian/adapters/pypi.py and guardian/adapters/gitlab_ci.py.
- guardian/tools/image_tags.py (newer-image-tag lookup).
- guardian/core/plans.py (risk, plans, and validation loaders used by reports).
- guardian/agents/risk_analyst.py (factor construction; also used by the
  reachability test).
- Compatible tool context, model contracts, registry bindings, workflow wiring,
  and dependencies from the complete integrated project.

The Dev1-owned risk_tools.py and package-risk detector wrapper, UI, workflow,
model contracts, scanner/sandbox infrastructure, credentials, caches, targets,
and generated scan results are not imported by this branch.
