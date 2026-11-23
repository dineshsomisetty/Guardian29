# Guardian sample policies (D4-07). Same rules as guardian/tools/policy.py, same input shape.
# Run:  conftest test input.json -p policies --namespace guardian
# Tested with OPA 1.22.4 (`opa eval -d policies/guardian.rego -i input.json data.guardian.deny`):
# a Juice-Shop-like input yields 8 denials, a pinned/locked input yields none. Not yet run through Conftest itself.
# Input flags: `denylisted: true` and `typosquat_of` must be set by the caller (the Python checker does this from guardian.yaml).
package guardian

import rego.v1

# Keep in sync with thresholds.min_package_age_days in guardian.yaml
min_package_age_days := 7

deny contains msg if {
	some a in input.actions
	not startswith(a.uses, "./")
	not startswith(a.uses, "docker://")
	parts := split(a.uses, "@")
	count(parts) < 2
	msg := sprintf("%s:%d action %s is not pinned to a commit SHA", [a.file, a.line, a.uses])
}

deny contains msg if {
	some a in input.actions
	not startswith(a.uses, "./")
	not startswith(a.uses, "docker://")
	parts := split(a.uses, "@")
	count(parts) >= 2
	not regex.match(`^[0-9a-f]{40}$`, parts[1])
	msg := sprintf("%s:%d action %s is not pinned to a commit SHA", [a.file, a.line, a.uses])
}

deny contains msg if {
	some i in input.images
	lower(i.image) != "scratch"
	not regex.match(`@sha256:[0-9a-f]{64}`, i.image)
	msg := sprintf("%s:%d base image %s is not pinned by digest", [i.file, i.line, i.image])
}

deny contains msg if {
	input.has_lockfile == false
	msg := "no lockfile committed; installs are not reproducible"
}

deny contains msg if {
	some p in input.packages
	p.typosquat_of
	msg := sprintf("package %s looks like %s", [p.name, p.typosquat_of])
}

deny contains msg if {
	some p in input.packages
	p.denylisted == true
	msg := sprintf("package %s is denylisted", [p.name])
}

deny contains msg if {
	some p in input.packages
	p.age_days < min_package_age_days
	msg := sprintf("package %s was published %d days ago", [p.name, p.age_days])
}
