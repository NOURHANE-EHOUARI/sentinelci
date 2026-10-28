# Release gate (SPEC section 6.3, task B4). Owned by Track B.
#
# Input (built by `sentinel evaluate`):
#   evaluated_at  RFC 3339 timestamp; policies never read the clock, so replay is exact
#   findings      array of Finding v1 objects (schemas/finding.v1.json)
#   waivers       array of {id, finding_id, expires_at}
#
# Output: data.sentinel.gate.decision = {verdict, violations, waivers_applied}, in the shape of
# schemas/decision.v1.json. One violation per rule, listing every finding id that triggered it.
#
# Fail closed: anything that cannot be evaluated (malformed input, unparsable expiry) blocks.
package sentinel.gate

import rego.v1

now := time.parse_rfc3339_ns(input.evaluated_at)

# A waiver applies while it has not expired. An unparsable expiry never applies.
waiver_applies(w, f) if {
	w.finding_id == f.id
	time.parse_rfc3339_ns(w.expires_at) > now
}

waived(f) if {
	some w in input.waivers
	waiver_applies(w, f)
}

waivers_applied contains w.id if {
	some w in input.waivers
	some f in input.findings
	waiver_applies(w, f)
}

# SC-001: a secret was detected and is not waived.
secret_ids contains f.id if {
	some f in input.findings
	f.category == "SECRET"
	not waived(f)
}

block contains v if {
	count(secret_ids) > 0
	v := {"rule": "SC-001", "effect": "BLOCK", "finding_ids": sort(secret_ids), "message": "Hard-coded secret"}
}

# SC-010: the gate cannot evaluate what it was given. Silence is never a pass.
input_errors contains "findings must be an array" if not is_array(object.get(input, "findings", null))

input_errors contains "waivers must be an array" if not is_array(object.get(input, "waivers", null))

input_errors contains "evaluated_at must be an RFC 3339 timestamp" if not now

block contains v if {
	count(input_errors) > 0
	v := {
		"rule": "SC-010",
		"effect": "BLOCK",
		"finding_ids": [],
		"message": concat("; ", ["Gate input is malformed", concat("; ", sort(input_errors))]),
	}
}

verdict := "BLOCK" if count(block) > 0

else := "PASS"

decision := {
	"verdict": verdict,
	"violations": sort(block),
	"waivers_applied": sort(waivers_applied),
}
