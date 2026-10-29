"""Decision v1 (schemas/decision.v1.json) as an immutable, read-only Pydantic model.

The policy engine (B4) produces decisions; this model is how the rest of the pipeline reads them (PR comment,
attestation, verification). It mirrors every rule of the JSON Schema, including verdict consistency, so a
malformed or tampered record is rejected instead of being reported as a PASS. Minor versions only add fields:
1.1 requires `inputs.waivers_digest`; 1.2 may also record `baseline_digest` and `tool_status_digest`; an older
version must not carry a field a later one introduced.
"""

import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Verdict = Literal["PASS", "WARN", "BLOCK"]
Effect = Literal["WARN", "BLOCK"]
DecisionContext = Literal["pr", "release", "local"]

_SHA256_HEX = r"^[a-f0-9]{64}$"
_PREFIXED_SHA256 = r"^sha256:[a-f0-9]{64}$"
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Subject(_Contract):
    repo: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    context: DecisionContext
    ref: str | None = None
    image_digest: str | None = Field(default=None, pattern=_PREFIXED_SHA256)


class Violation(_Contract):
    rule: str = Field(pattern=r"^SC-[0-9]{3}$")
    effect: Effect
    finding_ids: tuple[str, ...]
    message: str = Field(min_length=1)

    @field_validator("finding_ids")
    @classmethod
    def _ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for finding_id in value:
            if not re.fullmatch(_SHA256_HEX, finding_id):
                raise ValueError(f"finding id must be a sha256 fingerprint, got {finding_id!r}")
        return value


class Inputs(_Contract):
    findings_digest: str = Field(pattern=_PREFIXED_SHA256)
    enrichment_snapshot_digest: str = Field(pattern=_PREFIXED_SHA256)
    policy_bundle_digest: str = Field(pattern=_PREFIXED_SHA256)
    risk_model_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    tool_versions: dict[str, str] = Field(min_length=1)
    sbom_digest: str | None = Field(default=None, pattern=_PREFIXED_SHA256)
    waivers_digest: str | None = Field(default=None, pattern=_PREFIXED_SHA256)
    baseline_digest: str | None = Field(default=None, pattern=_PREFIXED_SHA256)
    tool_status_digest: str | None = Field(default=None, pattern=_PREFIXED_SHA256)

    @field_validator("tool_versions")
    @classmethod
    def _versions(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not version for version in value.values()):
            raise ValueError("tool versions must not be empty")
        return value


class Decision(_Contract):
    schema_version: Literal["1.0", "1.1", "1.2"]
    decision_id: str
    evaluated_at: str
    subject: Subject
    verdict: Verdict
    violations: tuple[Violation, ...]
    waivers_applied: tuple[str, ...]
    inputs: Inputs
    engine_version: str = Field(min_length=1)

    @field_validator("decision_id")
    @classmethod
    def _uuid(cls, value: str) -> str:
        try:
            UUID(value)
        except ValueError as exc:
            raise ValueError(f"decision_id must be a UUID, got {value!r}") from exc
        return value

    @field_validator("evaluated_at")
    @classmethod
    def _time(cls, value: str) -> str:
        if not _RFC3339.fullmatch(value):  # fullmatch: Python's `$` also matches before a final newline
            raise ValueError(f"evaluated_at must be an RFC 3339 date-time, got {value!r}")
        datetime.fromisoformat(value.replace("Z", "+00:00"))  # rejects impossible dates such as month 13
        return value

    @field_validator("waivers_applied")
    @classmethod
    def _waivers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not waiver for waiver in value) or len(set(value)) != len(value):
            raise ValueError("waivers_applied must hold unique, non-empty ids")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> "Decision":
        effects = {violation.effect for violation in self.violations}
        if self.verdict == "BLOCK" and "BLOCK" not in effects:
            raise ValueError("a BLOCK verdict needs at least one BLOCK violation")
        if self.verdict == "WARN" and effects != {"WARN"}:
            raise ValueError("a WARN verdict needs WARN violations only, and at least one")
        if self.verdict == "PASS" and self.violations:
            raise ValueError("a PASS verdict cannot have violations")
        has_waivers_digest = self.inputs.waivers_digest is not None
        if (self.schema_version != "1.0") != has_waivers_digest:
            raise ValueError("inputs.waivers_digest is required from schema 1.1 and absent in 1.0")
        new_inputs = (self.inputs.baseline_digest, self.inputs.tool_status_digest)
        if self.schema_version != "1.2" and any(digest is not None for digest in new_inputs):
            raise ValueError(
                "inputs.baseline_digest and inputs.tool_status_digest exist only from schema 1.2"
            )
        return self
