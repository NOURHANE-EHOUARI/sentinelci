# Policy profiles (SPEC section 6.3), chosen by `policy_profile` in the target's sentinel.yaml. Owned by Track B.
#
# The profile comes from the base branch (with the policies and the waivers) and the decision records the
# sentinel.yaml by digest, so a change cannot pick a softer profile for itself. A profile only tightens rules.
#
# p1_block_above: SC-006 (P1 findings) blocks when the change has more P1 findings than this; absent: WARN only.
package sentinel.config

import rego.v1

profiles := {
	"default": {},
	"strict": {"p1_block_above": 0},
}
