package sentinel.gate_test

import rego.v1

import data.sentinel.gate

secret := {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "category": "SECRET"}

other_secret := {"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "category": "SECRET"}

sca := {"id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "category": "SCA"}

base := {"evaluated_at": "2026-11-10T10:00:00Z", "findings": [], "waivers": []}

with_findings(fs) := object.union(base, {"findings": fs})

waiver(id, f, expires_at) := {"id": id, "finding_id": f.id, "expires_at": expires_at}

test_no_findings_pass if {
	d := gate.decision with input as base
	d == {"verdict": "PASS", "violations": [], "waivers_applied": []}
}

test_non_secret_findings_pass if {
	gate.decision.verdict == "PASS" with input as with_findings([sca])
}

test_secret_blocks_with_sc001 if {
	d := gate.decision with input as with_findings([sca, secret])
	d.verdict == "BLOCK"
	d.violations == [{
		"rule": "SC-001",
		"effect": "BLOCK",
		"finding_ids": [secret.id],
		"message": "Hard-coded secret",
	}]
}

test_secrets_grouped_in_one_sorted_violation if {
	d := gate.decision with input as with_findings([other_secret, secret])
	[v] := d.violations
	v.finding_ids == [secret.id, other_secret.id]
}

test_waived_secret_passes_and_is_recorded if {
	i := object.union(with_findings([secret]), {"waivers": [waiver("w-1", secret, "2026-12-01T00:00:00Z")]})
	d := gate.decision with input as i
	d == {"verdict": "PASS", "violations": [], "waivers_applied": ["w-1"]}
}

test_expired_waiver_does_not_apply if {
	i := object.union(with_findings([secret]), {"waivers": [waiver("w-1", secret, "2026-11-01T00:00:00Z")]})
	d := gate.decision with input as i
	d.verdict == "BLOCK"
	d.waivers_applied == []
}

test_waiver_expiring_exactly_now_does_not_apply if {
	i := object.union(with_findings([secret]), {"waivers": [waiver("w-1", secret, base.evaluated_at)]})
	gate.decision.verdict == "BLOCK" with input as i
}

test_unparsable_waiver_expiry_does_not_apply if {
	i := object.union(with_findings([secret]), {"waivers": [waiver("w-1", secret, "next year")]})
	gate.decision.verdict == "BLOCK" with input as i
}

test_waiver_for_another_finding_does_not_apply if {
	i := object.union(
		with_findings([secret, other_secret]),
		{"waivers": [waiver("w-1", secret, "2026-12-01T00:00:00Z")]},
	)
	d := gate.decision with input as i
	d.violations[0].finding_ids == [other_secret.id]
	d.waivers_applied == ["w-1"]
}

test_missing_findings_blocks_with_sc010 if {
	d := gate.decision with input as object.remove(base, ["findings"])
	d.verdict == "BLOCK"
	d.violations[0].rule == "SC-010"
	contains(d.violations[0].message, "findings must be an array")
}

test_missing_waivers_blocks_with_sc010 if {
	d := gate.decision with input as object.remove(base, ["waivers"])
	d.violations[0].rule == "SC-010"
}

test_bad_evaluated_at_blocks_with_sc010 if {
	d := gate.decision with input as object.union(base, {"evaluated_at": "yesterday"})
	d.verdict == "BLOCK"
	contains(d.violations[0].message, "evaluated_at")
}

test_missing_evaluated_at_blocks_with_sc010 if {
	gate.decision.violations[0].rule == "SC-010" with input as object.remove(base, ["evaluated_at"])
}

test_several_waivers_for_one_finding_are_all_recorded if {
	i := object.union(with_findings([secret]), {"waivers": [
		waiver("w-1", secret, "2026-12-01T00:00:00Z"),
		waiver("w-2", secret, "2027-01-15T00:00:00Z"),
	]})
	d := gate.decision with input as i
	d == {"verdict": "PASS", "violations": [], "waivers_applied": ["w-1", "w-2"]}
}
