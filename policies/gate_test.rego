package sentinel.gate_test

import rego.v1

import data.sentinel.gate

secret := {"id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "category": "SECRET", "rule_id": "generic-api-key"}

other_secret := {"id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "category": "SECRET", "rule_id": "aws-access-token"}

sca := {
	"id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	"category": "SCA",
	"rule_id": "GHSA-aaaa-bbbb-cccc",
	"cve": ["CVE-2026-12345"],
	"aliases": ["PYSEC-2026-1"],
	"package": {"purl": "pkg:pypi/example-lib@1.2.0?arch=x86_64"},
}

# Every required scanner reported ok (policies/required_tools.rego): tests start from a complete pipeline.
base := {
	"evaluated_at": "2026-11-10T10:00:00Z",
	"context": "release",
	"findings": [],
	"waivers": [],
	"tool_status": {"schema_version": 1, "lock_sha256": "x", "tools": {"gitleaks": ok_tool}},
}

without_tool_status := object.remove(base, ["tool_status"])

with_findings(fs) := object.union(base, {"findings": fs})

with_waivers(fs, ws) := object.union(with_findings(fs), {"waivers": ws})

# A valid waiver for finding f; tests patch fields with object.union / object.remove.
waiver(id, f) := {
	"id": id,
	"finding_id": f.id,
	"owner": "@Hiba-elouazi",
	"justification": "Accepted for the test.",
	"expires_at": "2026-12-01T00:00:00Z",
}

package_waiver(id, vuln, purl) := object.union(object.remove(waiver(id, sca), ["finding_id"]), {"vulnerability": vuln, "purl": purl})

sc005(d) := [v | some v in d.violations; v.rule == "SC-005"]

# ---------------------------------------------------------------- verdicts and SC-001

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

# ---------------------------------------------------------------- waivers that apply

test_waived_secret_passes_and_is_recorded if {
	d := gate.decision with input as with_waivers([secret], [waiver("w-1", secret)])
	d == {"verdict": "PASS", "violations": [], "waivers_applied": ["w-1"]}
}

test_several_waivers_for_one_finding_are_all_recorded if {
	w2 := object.union(waiver("w-2", secret), {"expires_at": "2027-01-15T00:00:00Z"})
	d := gate.decision with input as with_waivers([secret], [waiver("w-1", secret), w2])
	d == {"verdict": "PASS", "violations": [], "waivers_applied": ["w-1", "w-2"]}
}

test_waiver_for_another_finding_does_not_apply if {
	d := gate.decision with input as with_waivers([secret, other_secret], [waiver("w-1", secret)])
	d.violations[0].finding_ids == [other_secret.id]
	d.waivers_applied == ["w-1"]
}

test_unused_waiver_is_not_recorded if {
	d := gate.decision with input as with_waivers([], [waiver("w-1", secret)])
	d == {"verdict": "PASS", "violations": [], "waivers_applied": []}
}

test_package_waiver_matches_any_version_by_cve_alias_or_rule_id if {
	some vuln in ["CVE-2026-12345", "PYSEC-2026-1", "GHSA-aaaa-bbbb-cccc"]
	w := package_waiver("w-pkg", vuln, "pkg:pypi/example-lib")
	gate.waivers_applied == {"w-pkg"} with input as with_waivers([sca], [w])
}

test_package_waiver_for_another_package_or_vulnerability_does_not_apply if {
	some w in [
		package_waiver("w-pkg", "CVE-2026-12345", "pkg:pypi/other-lib"),
		package_waiver("w-pkg", "CVE-2026-99999", "pkg:pypi/example-lib"),
	]
	gate.waivers_applied == set() with input as with_waivers([sca], [w])
}

test_package_waiver_handles_scoped_npm_names if {
	f := object.union(sca, {"package": {"purl": "pkg:npm/@scope/left-pad@1.0.0"}})
	w := package_waiver("w-npm", "CVE-2026-12345", "pkg:npm/@scope/left-pad")
	gate.waivers_applied == {"w-npm"} with input as with_waivers([f], [w])
}

test_expired_waiver_does_not_apply_and_is_not_invalid if {
	w := object.union(waiver("w-1", secret), {"expires_at": "2026-11-01T00:00:00Z"})
	d := gate.decision with input as with_waivers([secret], [w])
	[v] := d.violations
	v.rule == "SC-001"
	d.waivers_applied == []
}

test_waiver_expiring_exactly_now_does_not_apply if {
	w := object.union(waiver("w-1", secret), {"expires_at": base.evaluated_at})
	gate.decision.verdict == "BLOCK" with input as with_waivers([secret], [w])
}

test_waiver_expiring_in_exactly_90_days_is_valid if {
	w := object.union(waiver("w-1", secret), {"expires_at": "2027-02-08T10:00:00Z"})
	gate.decision.verdict == "PASS" with input as with_waivers([secret], [w])
}

# ---------------------------------------------------------------- SC-005: invalid waivers

invalid_cases := {
	"no owner": [object.remove(waiver("w-1", secret), ["owner"]), "missing owner"],
	"blank owner": [object.union(waiver("w-1", secret), {"owner": "  "}), "missing owner"],
	"owner not a string": [object.union(waiver("w-1", secret), {"owner": 42}), "missing owner"],
	"no justification": [object.remove(waiver("w-1", secret), ["justification"]), "missing justification"],
	"no expiry": [object.remove(waiver("w-1", secret), ["expires_at"]), "expires_at must be an RFC 3339 date-time"],
	"date-only expiry": [object.union(waiver("w-1", secret), {"expires_at": "2026-12-01"}), "expires_at must be an RFC 3339 date-time"],
	"expiry over 90 days": [object.union(waiver("w-1", secret), {"expires_at": "2027-02-08T10:00:00.000000001Z"}), "expires more than 90 days after evaluation"],
	"bad id": [object.union(waiver("w-1", secret), {"id": "../w"}), "id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"],
	"no id": [object.remove(waiver("w-1", secret), ["id"]), "id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"],
	"unknown field": [object.union(waiver("w-1", secret), {"approved_by": "me"}), `unknown field "approved_by"`],
	"no target": [object.remove(waiver("w-1", secret), ["finding_id"]), "needs finding_id, or vulnerability and purl"],
	"both targets": [object.union(waiver("w-1", secret), {"vulnerability": "CVE-2026-12345", "purl": "pkg:pypi/x"}), "use finding_id or vulnerability and purl, not both"],
	"bad finding id": [object.union(waiver("w-1", secret), {"finding_id": "abc"}), "finding_id must be a sha256 fingerprint"],
	"vulnerability without purl": [object.remove(package_waiver("w-1", "CVE-2026-12345", "pkg:pypi/x"), ["purl"]), "vulnerability and purl must be given together"],
	"blank vulnerability": [package_waiver("w-1", " ", "pkg:pypi/x"), "missing vulnerability"],
	"purl with version": [package_waiver("w-1", "CVE-2026-12345", "pkg:pypi/example-lib@1.2.0"), "purl must be a package URL without version"],
	"purl with qualifiers": [package_waiver("w-1", "CVE-2026-12345", "pkg:pypi/example-lib?arch=x86_64"), "purl must be a package URL without version"],
	"not a purl": [package_waiver("w-1", "CVE-2026-12345", "example-lib"), "purl must be a package URL without version"],
}

test_invalid_waiver_blocks_with_sc005_and_never_applies if {
	every case in invalid_cases {
		[w, reason] := case
		d := gate.decision with input as with_waivers([secret, sca], [w])
		d.verdict == "BLOCK"
		[v] := sc005(d)
		contains(v.message, reason)
		d.waivers_applied == []
	}
}

test_sc005_names_the_waiver_and_lists_every_reason if {
	w := object.remove(waiver("w-7", secret), ["owner", "justification"])
	d := gate.decision with input as with_waivers([secret], [w])
	sc005(d) == [{
		"rule": "SC-005",
		"effect": "BLOCK",
		"finding_ids": [secret.id],
		"message": "Invalid waiver w-7 (entry 1): missing justification; missing owner",
	}]
	"SC-001" in {v.rule | some v in d.violations}
}

test_sc005_lists_findings_targeted_by_package if {
	w := object.remove(package_waiver("w-pkg", "CVE-2026-12345", "pkg:pypi/example-lib"), ["owner"])
	[v] := sc005(gate.decision) with input as with_waivers([sca, secret], [w])
	v.finding_ids == [sca.id]
}

test_waiver_that_is_not_a_mapping_is_labelled_by_position if {
	[v] := sc005(gate.decision) with input as with_waivers([], [waiver("w-1", secret), "w-2"])
	v.message == "Invalid waiver entry 2: must be a mapping"
}

test_duplicate_ids_invalidate_both_waivers if {
	d := gate.decision with input as with_waivers([secret], [waiver("w-1", secret), waiver("w-1", secret)])
	count(sc005(d)) == 2
	d.waivers_applied == []
}

test_one_invalid_waiver_does_not_disable_the_others if {
	bad := object.remove(waiver("w-bad", other_secret), ["owner"])
	d := gate.decision with input as with_waivers([secret], [waiver("w-1", secret), bad])
	d.waivers_applied == ["w-1"]
	[v] := d.violations
	v.rule == "SC-005"
}

# ---------------------------------------------------------------- SC-010: malformed input

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

# ---------------------------------------------------------------- diff-aware PR mode (input.baseline)

located(f, path) := object.union(f, {"location": {"path": path, "start_line": 1}})

pr_with(fs, baseline) := object.union(with_findings(fs), {"context": "pr", "baseline": baseline})

test_pr_secret_already_on_the_base_branch_does_not_block if {
	d := gate.decision with input as pr_with([located(secret, "app/config.py")], [located(secret, "app/config.py")])
	d.verdict == "PASS"
}

test_pr_secret_moving_lines_in_the_same_file_does_not_block if {
	moved := object.union(secret, {"location": {"path": "app/config.py", "start_line": 40}})
	gate.decision.verdict == "PASS" with input as pr_with([moved], [located(secret, "app/config.py")])
}

test_pr_new_secret_blocks if {
	d := gate.decision with input as pr_with([located(secret, "app/config.py")], [located(other_secret, "app/old.py")])
	[v] := d.violations
	v.finding_ids == [secret.id]
}

test_pr_known_secret_copied_to_another_file_blocks if {
	d := gate.decision with input as pr_with([located(secret, "web/settings.py")], [located(secret, "app/config.py")])
	[v] := d.violations
	v.rule == "SC-001"
}

# Finding 1.1: the same secret in several places is one finding, `location` plus `other_locations`.
spread(f, path, others) := object.union(
	located(f, path),
	{"schema_version": "1.1", "other_locations": [{"path": p, "start_line": 1} | some p in others]},
)

test_pr_copy_listed_in_other_locations_blocks if {
	head := spread(secret, "app/config.py", ["web/settings.py"])
	d := gate.decision with input as pr_with([head], [located(secret, "app/config.py")])
	[v] := d.violations
	v.finding_ids == [secret.id]
}

test_pr_every_place_already_on_the_base_branch_does_not_block if {
	both := spread(secret, "app/config.py", ["web/settings.py"])
	gate.decision.verdict == "PASS" with input as pr_with([both], [both])
}

test_pr_place_known_only_from_base_other_locations_does_not_block if {
	base_finding := spread(secret, "app/config.py", ["web/settings.py"])
	head := located(secret, "web/settings.py")
	gate.decision.verdict == "PASS" with input as pr_with([head], [base_finding])
}

test_pr_removing_a_copy_does_not_block if {
	base_finding := spread(secret, "app/config.py", ["web/settings.py"])
	gate.decision.verdict == "PASS" with input as pr_with([located(secret, "app/config.py")], [base_finding])
}

test_pr_new_copy_that_becomes_the_primary_location_blocks if {
	head := spread(secret, "a/first.py", ["app/config.py"])
	gate.decision.verdict == "BLOCK" with input as pr_with([head], [located(secret, "app/config.py")])
}

test_pr_without_baseline_counts_every_finding if {
	i := object.union(with_findings([secret]), {"context": "pr"})
	gate.decision.verdict == "BLOCK" with input as i
}

test_release_ignores_the_baseline if {
	i := object.union(with_findings([located(secret, "app/config.py")]), {"baseline": [located(secret, "app/config.py")]})
	gate.decision.verdict == "BLOCK" with input as i
}

test_empty_baseline_means_everything_is_new if {
	gate.decision.verdict == "BLOCK" with input as pr_with([secret], [])
}

# ---------------------------------------------------------------- tool status (input.tool_status)

tools(entries) := object.union(without_tool_status, {"tool_status": {"schema_version": 1, "lock_sha256": "x", "tools": entries}})

ok_tool := {"version": "8.30.1", "binary_sha256": "abc", "status": "ok"}

test_all_tools_ok_pass if {
	gate.decision.verdict == "PASS" with input as tools({"gitleaks": ok_tool, "opa": ok_tool})
}

test_each_failed_tool_blocks_with_sc010 if {
	d := gate.decision with input as tools({
		"gitleaks": ok_tool,
		"opengrep": {"version": "1.6.0", "status": "timeout", "detail": "opengrep timed out after 900 s"},
		"trivy": {"version": "0.76.1", "status": "integrity_mismatch", "detail": "binary modified"},
	})
	d.verdict == "BLOCK"
	d.violations == [
		{"rule": "SC-010", "effect": "BLOCK", "finding_ids": [], "message": "Scanner failure: opengrep timeout (opengrep timed out after 900 s)"},
		{"rule": "SC-010", "effect": "BLOCK", "finding_ids": [], "message": "Scanner failure: trivy integrity_mismatch (binary modified)"},
	]
}

test_tool_without_status_is_not_ok if {
	[v] := gate.decision.violations with input as tools({"gitleaks": {"version": "8.30.1"}})
	v.message == "Scanner failure: gitleaks unknown"
}

test_local_without_tool_status_passes if {
	gate.decision.verdict == "PASS" with input as object.union(without_tool_status, {"context": "local"})
}

test_pr_and_release_without_tool_status_block_with_sc010 if {
	every context in ["pr", "release"] {
		d := gate.decision with input as object.union(without_tool_status, {"context": context})
		d.violations == [{
			"rule": "SC-010",
			"effect": "BLOCK",
			"finding_ids": [],
			"message": sprintf("Tool status missing: %s requires gitleaks", [context]),
		}]
	}
}

test_required_tool_absent_from_the_status_blocks_with_sc010 if {
	[v] := gate.decision.violations with input as tools({"opa": ok_tool})
	v == {"rule": "SC-010", "effect": "BLOCK", "finding_ids": [], "message": "Scanner missing: gitleaks (required in release)"}
}

test_local_requires_no_tool if {
	gate.decision.verdict == "PASS" with input as object.union(tools({"opa": ok_tool}), {"context": "local"})
}

test_a_failed_required_tool_is_one_violation_not_two if {
	[v] := gate.decision.violations with input as tools({"gitleaks": {"version": "8.30.1", "status": "failed", "detail": "exit 2"}})
	v.message == "Scanner failure: gitleaks failed (exit 2)"
}

test_a_malformed_tool_status_is_not_also_reported_missing if {
	every ts in [[], {"tools": {}}] {
		[v] := gate.decision.violations with input as object.union(without_tool_status, {"tool_status": ts})
		contains(v.message, "tool_status must hold a non-empty tools object")
	}
}

# ---------------------------------------------------------------- SC-010 for the new inputs

test_missing_or_unknown_context_blocks_with_sc010 if {
	every i in [object.remove(base, ["context"]), object.union(base, {"context": "prod"})] {
		d := gate.decision with input as i
		contains(d.violations[0].message, "context must be one of pr, release, local")
	}
}

test_malformed_baseline_blocks_with_sc010 if {
	d := gate.decision with input as object.union(base, {"context": "pr", "baseline": "everything"})
	contains(d.violations[0].message, "baseline must be an array")
}

test_malformed_tool_status_blocks_with_sc010 if {
	every ts in [[], {"tools": {}}, {"tools": []}] {
		d := gate.decision with input as object.union(without_tool_status, {"tool_status": ts})
		contains(d.violations[0].message, "tool_status must hold a non-empty tools object")
	}
}
