"""Build Decision v1 records (schemas/decision.v1.json, SPEC section 6.5) from findings and policy.

The policy decides; this module only gathers inputs, records their digests and shapes the result.
Same inputs give a byte-identical decision, including `decision_id`, so `sentinel replay` can compare
whole records.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from sentinelci import __version__
from sentinelci.contracts.finding import Finding
from sentinelci.enrich.models import EMPTY_SNAPSHOT, EnrichmentError, load_service_context, load_snapshot
from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.opa import OpaRunner
from sentinelci.policy.tool_status import load_tool_status
from sentinelci.policy.waivers import load_waivers

# 1.2 only when a 1.2 input (baseline, tool status) is given: a decision without them stays readable by
# consumers that know 1.1, and both versions mean the same thing for it.
SCHEMA_VERSION = "1.1"
SCHEMA_VERSION_WITH_NEW_INPUTS = "1.2"
SCHEMA_VERSION_WITH_SERVICE_CONTEXT = "1.3"
GATE_QUERY = "data.sentinel.gate.decision"
CONTEXTS = ("pr", "release", "local")
VERDICTS = ("PASS", "WARN", "BLOCK")

# Recorded when no enrichment ran yet (S1 walking skeleton): the digest of an empty snapshot object.
EMPTY_ENRICHMENT_SNAPSHOT = EMPTY_SNAPSHOT  # one "no snapshot" value for evaluate and enrich, so one digest

# Fixed namespace for content-derived decision ids. Never change it: old ids would stop replaying.
_DECISION_ID_NAMESPACE = uuid.UUID("5b1c6a0e-3f0d-4c8e-9a51-8d3e2f6b7c40")

# Checked with fullmatch: Python's `$` also matches before a final newline, so `match` with `^...$` accepted
# "<40 hex>\n" as a commit.
_REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_COMMIT = re.compile(r"[a-f0-9]{40}")
_OCI_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
_SHA256_HEX = re.compile(r"[a-f0-9]{64}")
_VERSION_SEPARATOR = ", "


@dataclass(frozen=True)
class Subject:
    """What the decision is about (`subject` in Decision v1)."""

    repo: str
    commit: str
    context: str
    ref: str | None = None
    image_digest: str | None = None

    def __post_init__(self) -> None:
        if not _REPO.fullmatch(self.repo):
            raise EvaluationError(f"repo must look like owner/name, got {self.repo!r}")
        if not _COMMIT.fullmatch(self.commit):
            raise EvaluationError(f"commit must be a full 40-character lowercase SHA, got {self.commit!r}")
        if self.context not in CONTEXTS:
            raise EvaluationError(f"context must be one of {', '.join(CONTEXTS)}, got {self.context!r}")
        if self.image_digest is not None and not _OCI_DIGEST.fullmatch(self.image_digest):
            raise EvaluationError(f"image digest must be sha256:<64 hex>, got {self.image_digest!r}")

    def to_json(self) -> dict[str, str]:
        out = {"repo": self.repo, "commit": self.commit, "context": self.context}
        if self.ref is not None:
            out["ref"] = self.ref
        if self.image_digest is not None:
            out["image_digest"] = self.image_digest
        return out


def sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_time(value: str) -> str:
    """Normalize an RFC 3339 timestamp with an explicit offset to UTC with a `Z` suffix."""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise EvaluationError(f"evaluated_at is not an RFC 3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise EvaluationError(f"evaluated_at needs an explicit UTC offset: {value!r}")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def engine_version() -> str:
    """The `engine_version` this engine records."""
    return __version__


def now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_findings(data: bytes) -> list[dict[str, Any]]:
    """Parse findings NDJSON. Any malformed line rejects the whole file (fail closed)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvaluationError("findings file is not UTF-8") from exc
    findings: list[dict[str, Any]] = []
    # NDJSON lines end with "\n" only. str.splitlines() would also split on U+2028, U+2029 and \x85,
    # which JSON allows raw inside strings (the normalizer writes ensure_ascii=False). A trailing \r is
    # JSON whitespace.
    for lineno, line in enumerate(text.split("\n"), start=1):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
        except ValueError as exc:
            raise EvaluationError(f"findings line {lineno}: invalid JSON") from exc
        if not isinstance(finding, dict):
            raise EvaluationError(f"findings line {lineno}: expected a JSON object")
        if not isinstance(finding.get("id"), str) or not _SHA256_HEX.fullmatch(finding["id"]):
            raise EvaluationError(f"findings line {lineno}: 'id' must be a sha256 fingerprint")
        try:
            # Every field and enum of Finding v1: a `"category": "secret"` would otherwise reach the policy,
            # miss `== "SECRET"` and pass. The raw object, not the model, goes to OPA (it was digested).
            Finding.model_validate(finding)
        except ValidationError as exc:
            raise EvaluationError(
                f"findings line {lineno}: not a Finding v1 ({exc.error_count()} error(s))"
            ) from exc
        findings.append(finding)
    return findings


def _tool_versions(
    findings: Sequence[Mapping[str, Any]], explicit: Mapping[str, str], opa_version: str
) -> dict[str, str]:
    """Versions of every tool behind the decision; several versions of one tool are all listed.

    An explicit value may list several versions joined by ", ", as recorded, so a recorded `tool_versions`
    passed back in (`sentinel replay`) gives the same result.
    """
    seen: dict[str, set[str]] = {}
    tools = [f["tool"] for f in findings if isinstance(f.get("tool"), dict)]
    pairs = [(tool.get("name"), tool.get("version")) for tool in tools]
    given = [(name, v) for name, value in explicit.items() for v in value.split(_VERSION_SEPARATOR)]
    for name, version in [*pairs, *given, ("opa", opa_version)]:
        if isinstance(name, str) and name and isinstance(version, str) and version:
            seen.setdefault(name, set()).add(version)
    return {name: _VERSION_SEPARATOR.join(sorted(versions)) for name, versions in sorted(seen.items())}


def _check_policy_result(result: Any) -> dict[str, Any]:
    """Reject anything that is not a self-consistent gate result rather than guess a verdict."""
    if not isinstance(result, dict):
        raise EvaluationError("policy returned no decision object")
    verdict = result.get("verdict")
    violations = result.get("violations")
    waivers = result.get("waivers_applied")
    if verdict not in VERDICTS or not isinstance(violations, list) or not isinstance(waivers, list):
        raise EvaluationError("policy decision is missing verdict, violations or waivers_applied")
    effects = set()
    for v in violations:
        if not isinstance(v, dict) or v.get("effect") not in ("WARN", "BLOCK"):
            raise EvaluationError(f"policy returned a malformed violation: {v!r}")
        effects.add(v["effect"])
    expected = "BLOCK" if "BLOCK" in effects else "WARN" if effects else "PASS"
    if verdict != expected:
        raise EvaluationError(f"policy verdict {verdict} is inconsistent with its violations")
    return result


def evaluate(
    *,
    findings_data: bytes,
    subject: Subject,
    evaluated_at: str,
    bundle: PolicyBundle,
    opa: OpaRunner,
    tool_versions: Mapping[str, str] | None = None,
    waivers_data: bytes | None = None,
    baseline_data: bytes | None = None,
    tool_status_data: bytes | None = None,
    enrichment_snapshot: bytes | None = None,
    sbom: bytes | None = None,
    service_context: bytes | None = None,
) -> dict[str, Any]:
    """Run the release gate and return a Decision v1 record.

    `service_context` is the sentinel.yaml enrichment used (from the base branch): its exposure lowered or
    kept the findings' scores, so its digest is evidence like the snapshot's (Decision 1.3).
    """
    findings = load_findings(findings_data)
    if enrichment_snapshot is not None:  # a digest is recorded only for a snapshot that is one
        try:
            load_snapshot(enrichment_snapshot)
        except EnrichmentError as exc:
            raise EvaluationError(f"--enrichment-snapshot: {exc}") from exc
    if service_context is not None:  # likewise: only a valid sentinel.yaml is recorded
        try:
            load_service_context(service_context)
        except EnrichmentError as exc:
            raise EvaluationError(f"--service-context: {exc}") from exc
    # Each input is parsed from the same bytes that are digested: the record names exactly what was evaluated.
    waivers_data = b"" if waivers_data is None else waivers_data
    waivers = load_waivers(waivers_data)
    baseline = None if baseline_data is None else load_findings(baseline_data)
    tool_status = None if tool_status_data is None else load_tool_status(tool_status_data)
    timestamp = canonical_time(evaluated_at)

    reported = dict(tool_versions or {})
    for name, tool in (tool_status or {}).get("tools", {}).items():
        reported.setdefault(name, tool["version"])

    inputs: dict[str, Any] = {
        "findings_digest": sha256_digest(findings_data),
        "enrichment_snapshot_digest": sha256_digest(
            EMPTY_ENRICHMENT_SNAPSHOT if enrichment_snapshot is None else enrichment_snapshot
        ),
        "policy_bundle_digest": bundle.digest,
        "waivers_digest": sha256_digest(waivers_data),
        "risk_model_version": bundle.risk_model_version,
        "tool_versions": _tool_versions(findings, reported, opa.version()),
    }
    if sbom is not None:
        inputs["sbom_digest"] = sha256_digest(sbom)
    if baseline_data is not None:
        inputs["baseline_digest"] = sha256_digest(baseline_data)
    if tool_status_data is not None:
        inputs["tool_status_digest"] = sha256_digest(tool_status_data)
    if service_context is not None:
        inputs["service_context_digest"] = sha256_digest(service_context)

    gate_input: dict[str, Any] = {
        "evaluated_at": timestamp,
        "context": subject.context,
        "findings": findings,
        "waivers": waivers,
        # A finding's recorded priority counts only if it was scored with this bundle's risk model.
        "risk_model_version": inputs["risk_model_version"],
    }
    if baseline is not None:
        gate_input["baseline"] = baseline
    if tool_status is not None:
        gate_input["tool_status"] = tool_status

    result = _check_policy_result(
        opa.eval(
            GATE_QUERY,
            bundle.rego_files,
            gate_input,
        )
    )

    decision_id = decision_id_of(subject.to_json(), timestamp, inputs, __version__)
    return {
        "schema_version": SCHEMA_VERSION_WITH_SERVICE_CONTEXT
        if service_context is not None
        else SCHEMA_VERSION_WITH_NEW_INPUTS
        if baseline is not None or tool_status is not None
        else SCHEMA_VERSION,
        "decision_id": decision_id,
        "evaluated_at": timestamp,
        "subject": subject.to_json(),
        "verdict": result["verdict"],
        "violations": sorted(
            result["violations"], key=lambda v: (v.get("rule", ""), v["effect"], str(v.get("message", "")))
        ),
        "waivers_applied": sorted(result["waivers_applied"]),
        "inputs": inputs,
        "engine_version": __version__,
    }


def decision_id_of(
    subject: Mapping[str, Any], evaluated_at: str, inputs: Mapping[str, Any], engine: str
) -> str:
    """UUIDv5 of what the decision is about and what it read: the same inputs give the same id."""
    identity = {"subject": subject, "evaluated_at": evaluated_at, "inputs": inputs, "engine_version": engine}
    return str(uuid.uuid5(_DECISION_ID_NAMESPACE, json.dumps(identity, sort_keys=True)))


def dumps_decision(decision: Mapping[str, Any]) -> str:
    """Canonical serialization: identical decisions are byte-identical files."""
    return json.dumps(decision, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
