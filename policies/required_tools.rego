# Scanners that must report in each context (SC-010, SPEC section 5). Owned by Track B.
#
# Part of the policy bundle, which the pipeline reads from the base branch and every decision records by
# digest: a change cannot drop a scanner from its own gate, even though the workflow YAML is the PR's.
package sentinel.config

import rego.v1

# Secrets (gitleaks), IaC (trivy), the CI workflow audit (zizmor, #66), SAST (opengrep) and SCA (syft for the
# SBOM, grype for its vulnerabilities, #80). In release, the laptop's image scan reports syft and grype too.
required_tools := {
	"pr": {"gitleaks", "grype", "opengrep", "syft", "trivy", "zizmor"},
	"release": {"gitleaks", "grype", "opengrep", "syft", "trivy", "zizmor"},
	"local": set(),
}
