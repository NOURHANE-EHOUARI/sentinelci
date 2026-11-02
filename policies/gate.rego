# Release gate (SPEC section 6.3, task B4). Owned by Track B.
#
# Input (built by `sentinel evaluate`):
#   evaluated_at  RFC 3339 timestamp; policies never read the clock, so replay is exact
#   context       pr | release | local (the decision's subject.context)
#   baseline      optional: Finding v1 objects of the base branch; in pr context only what the change
#                 introduces can block (diff-aware), elsewhere it is ignored
#   tool_status   schemas/tool-status.v1.json; any tool that is not ok blocks (SC-010), and so does a tool
#                 that policies/required_tools.rego requires in this context but the status leaves out;
#                 no tool status at all blocks wherever a tool is required (pr, release)
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

import data.sentinel.exposing

import data.sentinel.config

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

# Every file a finding was seen in: `location` plus, since Finding 1.1, `other_locations`.
finding_paths(f) := {object.get(f, ["location", "path"], "")} | {object.get(l, "path", "") |
	some l in object.get(f, "other_locations", [])
}

baseline_paths[b.id] contains path if {
	diff_aware
	some b in baseline
	some path in finding_paths(b)
}

# What the change introduces. Without a PR baseline every finding counts (fail safe).
introduced(_) if not diff_aware

introduced(f) if {
	diff_aware
	not baseline_paths[f.id]
}

# Secrets and dependencies have fingerprints without a path (SPEC section 13.1), so a known one can appear in a
# new place under its old id. A known secret in a file where the base branch did not have it is a new copy; a known
# vulnerable package in a manifest where the base did not have it is a service newly exposed, with its own
# exposure and reachability. Paths, not lines, so a finding that only moved down its file does not count. Every
# place counts: a 1.0 finding names one, a 1.1 finding lists the others in `other_locations`, so full-tree scans
# see a new place wherever it sorts.
path_less_fingerprint := {"SECRET", "SCA"}

introduced(f) if {
	diff_aware
	f.category in path_less_fingerprint
	some path in finding_paths(f)
	not path in baseline_paths[f.id]
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

# ---------------------------------------------------------------- rule catalogue (SPEC section 6.3)

# A finding counts for a rule when the change introduces it (any finding outside PR mode) and no waiver covers it.
counts(f) if {
	introduced(f)
	not waived(f)
}

# The priority the risk engine (B3) recorded, or the worst case for an unscored finding. risk = 100 x S x E x X x R
# with E, X and R at most 1, so 100 x severity_weight bounds it (risk-model.yaml; a test keeps them in step).
# A finding without a usable severity is treated as the worst of all.
worst_case_priority := {"CRITICAL": "P0", "HIGH": "P0", "MEDIUM": "P2", "LOW": "P3", "INFO": "P4"}

# A recorded priority counts only when the finding was scored with this bundle's risk model
# (input.risk_model_version, from risk-model.yaml): findings scored elsewhere count at their worst case.
scored_priority(f) := p if {
	p := object.get(f, ["risk", "priority"], null)
	p in {"P0", "P1", "P2", "P3", "P4"}
	object.get(f, ["risk", "model_version"], null) == input.risk_model_version
}

priority(f) := scored_priority(f)

priority(f) := object.get(worst_case_priority, object.get(f, "severity", ""), "P0") if not scored_priority(f)

# SC-003: a known exploited vulnerability that can be fixed, in an internet-facing service.
# Fail closed: an unknown exposure (no sentinel.yaml) counts as internet-facing, as in the risk model (X = 1.0).
fix_available(f) if f.enrichment.fix_available == true

fix_available(f) if count(object.get(f, ["package", "fixed_versions"], [])) > 0

kev_ids contains f.id if {
	some f in input.findings
	f.category in {"SCA", "CONTAINER"}
	f.enrichment.kev.listed == true
	fix_available(f)
	not object.get(f, ["enrichment", "exposure"], "internet-facing") in {"internal", "offline"}
	counts(f)
}

block contains v if {
	count(kev_ids) > 0
	v := {
		"rule": "SC-003",
		"effect": "BLOCK",
		"finding_ids": sort(kev_ids),
		"message": "Known exploited vulnerability with a fix, internet-facing",
	}
}

# SC-009: a high-severity CI workflow issue.
pipeline_ids contains f.id if {
	some f in input.findings
	f.category == "PIPELINE"
	f.severity in {"HIGH", "CRITICAL"}
	counts(f)
}

block contains v if {
	count(pipeline_ids) > 0
	v := {"rule": "SC-009", "effect": "BLOCK", "finding_ids": sort(pipeline_ids), "message": "High-severity CI workflow issue"}
}

# SC-011: a misconfiguration that exposes the service by itself (policies/exposing.rego), whatever its score: it
# creates the exposure the risk model's exposure factor would otherwise discount. The ids are Trivy's, so only
# Trivy findings match: another tool reporting the same rule_id was never checked against the list.
exposing_ids contains f.id if {
	some f in input.findings
	f.category == "IAC"
	f.tool.name == "trivy"
	f.rule_id in exposing.rule_ids
	counts(f)
}

block contains v if {
	count(exposing_ids) > 0
	v := {
		"rule": "SC-011",
		"effect": "BLOCK",
		"finding_ids": sort(exposing_ids),
		"message": "Misconfiguration that exposes the service by itself",
	}
}

# SC-002 (P0, BLOCK) and SC-006 (P1, WARN) for findings no more specific rule already blocks, so each finding is
# reported once, under its most specific rule.
specific_ids := ((secret_ids | kev_ids) | pipeline_ids) | exposing_ids

priority_ids[p] contains f.id if {
	some f in input.findings
	not f.id in specific_ids
	counts(f)
	p := priority(f)
}

# Why findings in a violation count at their worst case: unscored, scored with another risk model, or both.
worst_case_reasons(found) := {reason |
	some f in input.findings
	f.id in found
	not scored_priority(f)
	reason := worst_case_reason(f)
}

worst_case_reason(f) := "unscored findings" if object.get(f, ["risk", "priority"], null) == null

worst_case_reason(f) := "findings scored with another risk model" if object.get(f, ["risk", "priority"], null) != null

unscored_note(found) := sprintf(" (%s count at their worst-case priority)", [concat(" and ", sort(reasons))]) if {
	reasons := worst_case_reasons(found)
	count(reasons) > 0
} else := ""

block contains v if {
	found := priority_ids.P0
	v := {
		"rule": "SC-002",
		"effect": "BLOCK",
		"finding_ids": sort(found),
		"message": sprintf("P0 finding not waived%s", [unscored_note(found)]),
	}
}

warn contains v if {
	found := priority_ids.P1
	v := {"rule": "SC-006", "effect": "WARN", "finding_ids": sort(found), "message": sprintf("P1 finding%s", [unscored_note(found)])}
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

# SC-010: a required scanner did not report. A workflow that drops a scanner, or drops the tool status
# altogether, must not turn its silence into a pass.
required_tools := object.get(config.required_tools, input.context, set())

block contains v if {
	tool_status == null
	count(required_tools) > 0
	v := {
		"rule": "SC-010",
		"effect": "BLOCK",
		"finding_ids": [],
		"message": sprintf("Tool status missing: %s requires %s", [input.context, concat(", ", sort(required_tools))]),
	}
}

block contains v if {
	valid_tool_status
	some name in required_tools
	object.get(tool_status.tools, name, null) == null
	v := {
		"rule": "SC-010",
		"effect": "BLOCK",
		"finding_ids": [],
		"message": sprintf("Scanner missing: %s (required in %s)", [name, input.context]),
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

else := "WARN" if count(warn) > 0

else := "PASS"

decision := {
	"verdict": verdict,
	"violations": array.concat(sort(block), sort(warn)),
	"waivers_applied": sort(waivers_applied),
}
