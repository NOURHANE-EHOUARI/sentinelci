# Release gate (SPEC section 6.3, task B4). Owned by Track B.
#
# Input (built by `sentinel evaluate`):
#   evaluated_at  RFC 3339 timestamp; policies never read the clock, so replay is exact
#   context       pr | release | local (the decision's subject.context)
#   baseline      optional: Finding v1 objects of the base branch; in pr context only what the change
#                 introduces can block (diff-aware), elsewhere it is ignored
#   tool_status   optional: schemas/tool-status.v1.json; any tool that is not ok blocks (SC-010)
#   findings      array of Finding v1 objects (schemas/finding.v1.json)
#   waivers       entries of .sentinel/waivers.yaml (schemas/waivers.v1.json), unvalidated:
#                 checking them is this policy's job (SC-005)
#
# Output: data.sentinel.gate.decision = {verdict, violations, waivers_applied}, in the shape of
# schemas/decision.v1.json. One violation per rule, listing every finding id that triggered it.
#
# Fail closed: anything that cannot be evaluated (malformed input, invalid waiver) blocks.
package sentinel.gate

import rego.v1

now := time.parse_rfc3339_ns(input.evaluated_at)

# ---------------------------------------------------------------- waivers (SPEC section 6.4)

max_waiver_ns := ((90 * 24) * 3600) * 1000000000

waiver_fields := {"id", "finding_id", "vulnerability", "purl", "owner", "justification", "expires_at"}

waiver_objects[i] := w if {
	some i, w in input.waivers
	is_object(w)
}

non_blank(s) if {
	is_string(s)
	trim_space(s) != ""
}

rfc3339(s) if {
	is_string(s)
	time.parse_rfc3339_ns(s)
}

has(w, k) if k in object.keys(w)

# Package URL without version, qualifiers or subpath.
purl_base(p) := regex.replace(regex.replace(p, `[?#].*$`, ""), `@[^/@]*$`, "")

# SC-005: why each waiver (by index) is invalid. An invalid waiver never applies.
invalid_waiver[i] contains "must be a mapping" if {
	some i, w in input.waivers
	not is_object(w)
}

invalid_waiver[i] contains sprintf("unknown field %q", [k]) if {
	some i, w in waiver_objects
	some k in object.keys(w)
	not k in waiver_fields
}

invalid_waiver[i] contains "id must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}" if {
	some i, w in waiver_objects
	not regex.match(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, object.get(w, "id", ""))
}

invalid_waiver[i] contains "duplicate id" if {
	some i, w in waiver_objects
	some j, other in waiver_objects
	i != j
	is_string(w.id)
	other.id == w.id
}

invalid_waiver[i] contains "missing owner" if {
	some i, w in waiver_objects
	not non_blank(object.get(w, "owner", null))
}

invalid_waiver[i] contains "missing justification" if {
	some i, w in waiver_objects
	not non_blank(object.get(w, "justification", null))
}

invalid_waiver[i] contains "expires_at must be an RFC 3339 date-time" if {
	some i, w in waiver_objects
	not rfc3339(object.get(w, "expires_at", null))
}

invalid_waiver[i] contains "expires more than 90 days after evaluation" if {
	some i, w in waiver_objects
	time.parse_rfc3339_ns(w.expires_at) - now > max_waiver_ns
}

invalid_waiver[i] contains "needs finding_id, or vulnerability and purl" if {
	some i, w in waiver_objects
	not has(w, "finding_id")
	not has(w, "vulnerability")
	not has(w, "purl")
}

invalid_waiver[i] contains "use finding_id or vulnerability and purl, not both" if {
	some i, w in waiver_objects
	has(w, "finding_id")
	some k in ["vulnerability", "purl"]
	has(w, k)
}

invalid_waiver[i] contains "finding_id must be a sha256 fingerprint" if {
	some i, w in waiver_objects
	has(w, "finding_id")
	not regex.match(`^[a-f0-9]{64}$`, object.get(w, "finding_id", ""))
}

invalid_waiver[i] contains "vulnerability and purl must be given together" if {
	some i, w in waiver_objects
	not has(w, "finding_id")
	some [present, missing] in [["vulnerability", "purl"], ["purl", "vulnerability"]]
	has(w, present)
	not has(w, missing)
}

invalid_waiver[i] contains "missing vulnerability" if {
	some i, w in waiver_objects
	has(w, "vulnerability")
	not non_blank(w.vulnerability)
}

invalid_waiver[i] contains "purl must be a package URL without version" if {
	some i, w in waiver_objects
	has(w, "purl")
	not valid_waiver_purl(w.purl)
}

valid_waiver_purl(p) if {
	regex.match(`^pkg:[a-z0-9.+-]+/[^?#]+$`, p)
	purl_base(p) == p
}

valid_waivers := [w |
	some i, w in waiver_objects
	not invalid_waiver[i]
]

finding_vuln_ids(f) := ({f.rule_id} | {x | some x in object.get(f, "cve", [])}) | {x | some x in object.get(f, "aliases", [])}

waiver_targets(w, f) if w.finding_id == f.id

waiver_targets(w, f) if {
	w.vulnerability in finding_vuln_ids(f)
	purl_base(f.package.purl) == w.purl
}

# A valid waiver applies to the findings it targets until it expires.
waiver_applies(w, f) if {
	waiver_targets(w, f)
	time.parse_rfc3339_ns(w.expires_at) > now
}

waived(f) if {
	some w in valid_waivers
	waiver_applies(w, f)
}

waivers_applied contains w.id if {
	some w in valid_waivers
	some f in input.findings
	waiver_applies(w, f)
}

# Entries are named by position too, so duplicates and id-less entries stay distinguishable.
waiver_label(i, w) := sprintf("%s (entry %d)", [w.id, i + 1]) if non_blank(w.id)

else := sprintf("entry %d", [i + 1])

block contains v if {
	some i, reasons in invalid_waiver
	w := input.waivers[i]
	v := {
		"rule": "SC-005",
		"effect": "BLOCK",
		"finding_ids": sort({f.id | some f in input.findings; waiver_targets(w, f)}),
		"message": sprintf("Invalid waiver %s: %s", [waiver_label(i, w), concat("; ", sort(reasons))]),
	}
}

# ---------------------------------------------------------------- diff-aware PR mode

baseline := object.get(input, "baseline", null)

diff_aware if {
	input.context == "pr"
	is_array(baseline)
}

baseline_paths[b.id] contains object.get(b, ["location", "path"], "") if {
	diff_aware
	some b in baseline
}

# What the change introduces. Without a PR baseline every finding counts (fail safe).
introduced(_) if not diff_aware

introduced(f) if {
	diff_aware
	not baseline_paths[f.id]
}

# A known secret in a file where the base branch did not have it is a new copy. Paths, not lines, so a secret
# that only moved down its file does not count. Finding v1 keeps one location per secret (the others are only
# listed in `message`), so with full-tree scans a copy is seen only when it becomes the primary location; scans
# of the change's commits (A3's PR mode) see every copy.
introduced(f) if {
	diff_aware
	f.category == "SECRET"
	not object.get(f, ["location", "path"], "") in baseline_paths[f.id]
}

# SC-001: a secret the change introduces (anywhere in release context), not waived.
secret_ids contains f.id if {
	some f in input.findings
	f.category == "SECRET"
	introduced(f)
	not waived(f)
}

block contains v if {
	count(secret_ids) > 0
	v := {"rule": "SC-001", "effect": "BLOCK", "finding_ids": sort(secret_ids), "message": "Hard-coded secret"}
}

# SC-010: a scanner failed, timed out, did not match its pin or did not run. Its silence is not a pass.
tool_status := object.get(input, "tool_status", null)

block contains v if {
	is_object(tool_status)
	some name, tool in object.get(tool_status, "tools", {})
	status := object.get(tool, "status", "unknown")
	status != "ok"
	v := {
		"rule": "SC-010",
		"effect": "BLOCK",
		"finding_ids": [],
		"message": sprintf("Scanner failure: %s %s%s", [name, status, detail_suffix(tool)]),
	}
}

detail_suffix(tool) := sprintf(" (%s)", [tool.detail]) if {
	is_string(tool.detail)
	tool.detail != ""
} else := ""

# SC-010: the gate cannot evaluate what it was given. Silence is never a pass.
input_errors contains "findings must be an array" if not is_array(object.get(input, "findings", null))

input_errors contains "waivers must be an array" if not is_array(object.get(input, "waivers", null))

input_errors contains "evaluated_at must be an RFC 3339 timestamp" if not now

input_errors contains "context must be one of pr, release, local" if {
	not object.get(input, "context", null) in {"pr", "release", "local"}
}

input_errors contains "baseline must be an array" if {
	baseline != null
	not is_array(baseline)
}

input_errors contains "tool_status must hold a non-empty tools object" if {
	tool_status != null
	not valid_tool_status
}

valid_tool_status if {
	tools := object.get(tool_status, "tools", null)
	is_object(tools)
	count(tools) > 0
}

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
