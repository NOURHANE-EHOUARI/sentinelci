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
from sentinelci.policy.bundle import PolicyBundle
from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.opa import OpaRunner
from sentinelci.policy.waivers import load_waivers

SCHEMA_VERSION = "1.1"
GATE_QUERY = "data.sentinel.gate.decision"
CONTEXTS = ("pr", "release", "local")
VERDICTS = ("PASS", "WARN", "BLOCK")

# Recorded when no enrichment ran yet (S1 walking skeleton): the digest of an empty snapshot object.
EMPTY_ENRICHMENT_SNAPSHOT = b"{}"

# Fixed namespace for content-derived decision ids. Never change it: old ids would stop replaying.
_DECISION_ID_NAMESPACE = uuid.UUID("5b1c6a0e-3f0d-4c8e-9a51-8d3e2f6b7c40")

_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_OCI_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_SHA256_HEX = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class Subject:
    """What the decision is about (`subject` in Decision v1)."""

    repo: str
    commit: str
    context: str
    ref: str | None = None
    image_digest: str | None = None

    def __post_init__(self) -> None:
        if not _REPO.match(self.repo):
            raise EvaluationError(f"repo must look like owner/name, got {self.repo!r}")
        if not _COMMIT.match(self.commit):
            raise EvaluationError(f"commit must be a full 40-character lowercase SHA, got {self.commit!r}")
        if self.context not in CONTEXTS:
            raise EvaluationError(f"context must be one of {', '.join(CONTEXTS)}, got {self.context!r}")
        if self.image_digest is not None and not _OCI_DIGEST.match(self.image_digest):
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


def now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_findings(data: bytes) -> list[dict[str, Any]]:
    """Parse findings NDJSON. Any malformed line rejects the whole file (fail closed)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvaluationError("findings file is not UTF-8") from exc
    findings: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            finding = json.loads(line)
        except ValueError as exc:
            raise EvaluationError(f"findings line {lineno}: invalid JSON") from exc
        if not isinstance(finding, dict):
            raise EvaluationError(f"findings line {lineno}: expected a JSON object")
        if not isinstance(finding.get("id"), str) or not _SHA256_HEX.match(finding["id"]):
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
    """Versions of every tool behind the decision; several versions of one tool are all listed."""
    seen: dict[str, set[str]] = {}
    tools = [f["tool"] for f in findings if isinstance(f.get("tool"), dict)]
    pairs = [(tool.get("name"), tool.get("version")) for tool in tools]
    for name, version in [*pairs, *explicit.items(), ("opa", opa_version)]:
        if isinstance(name, str) and name and isinstance(version, str) and version:
            seen.setdefault(name, set()).add(version)
    return {name: ", ".join(sorted(versions)) for name, versions in sorted(seen.items())}


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
    enrichment_snapshot: bytes | None = None,
    sbom: bytes | None = None,
) -> dict[str, Any]:
    """Run the release gate and return a Decision v1 record."""
    findings = load_findings(findings_data)
    # Parsed from the same bytes that are digested, so the record names exactly what was evaluated.
    waivers_data = b"" if waivers_data is None else waivers_data
    waivers = load_waivers(waivers_data)
    timestamp = canonical_time(evaluated_at)

    inputs: dict[str, Any] = {
        "findings_digest": sha256_digest(findings_data),
        "enrichment_snapshot_digest": sha256_digest(
            EMPTY_ENRICHMENT_SNAPSHOT if enrichment_snapshot is None else enrichment_snapshot
        ),
        "policy_bundle_digest": bundle.digest,
        "waivers_digest": sha256_digest(waivers_data),
        "risk_model_version": bundle.risk_model_version,
        "tool_versions": _tool_versions(findings, tool_versions or {}, opa.version()),
    }
    if sbom is not None:
        inputs["sbom_digest"] = sha256_digest(sbom)

    result = _check_policy_result(
        opa.eval(
            GATE_QUERY,
            bundle.rego_files,
            {"evaluated_at": timestamp, "findings": findings, "waivers": waivers},
        )
    )

    identity = {
        "subject": subject.to_json(),
        "evaluated_at": timestamp,
        "inputs": inputs,
        "engine_version": __version__,
    }
    decision_id = uuid.uuid5(_DECISION_ID_NAMESPACE, json.dumps(identity, sort_keys=True))
    return {
        "schema_version": SCHEMA_VERSION,
        "decision_id": str(decision_id),
        "evaluated_at": timestamp,
        "subject": subject.to_json(),
        "verdict": result["verdict"],
        "violations": sorted(result["violations"], key=lambda v: (v.get("rule", ""), v["effect"])),
        "waivers_applied": sorted(result["waivers_applied"]),
        "inputs": inputs,
        "engine_version": __version__,
    }


def dumps_decision(decision: Mapping[str, Any]) -> str:
    """Canonical serialization: identical decisions are byte-identical files."""
    return json.dumps(decision, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
