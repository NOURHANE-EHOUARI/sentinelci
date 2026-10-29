# Scanners that must report in each context (SC-010, SPEC section 5). Owned by Track B.
#
# Part of the policy bundle, which the pipeline reads from the base branch and every decision records by
# digest: a change cannot drop a scanner from its own gate, even though the workflow YAML is the PR's.
package sentinel.config

import rego.v1

required_tools := {
	"pr": {"gitleaks"},
	"release": {"gitleaks"},
	"local": set(),
}
