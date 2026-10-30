"""Decision v1 (schemas/decision.v1.json) as an immutable, read-only Pydantic model.

The policy engine (B4) produces decisions; this model is how the rest of the pipeline reads them (PR comment,
attestation, verification). It mirrors every rule of the JSON Schema, including verdict consistency, so a
malformed or tampered record is rejected instead of being reported as a PASS. Minor versions only add fields
(`_SINCE`), and an older version must not carry a field a later one introduced. What each version requires
is the schema's `allOf` table, copied in `_REQUIRED`: `waivers_digest` from 1.1, `service_context_digest`
in 1.3.
"""

import re
from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Verdict = Literal["PASS", "WARN", "BLOCK"]
Effect = Literal["WARN", "BLOCK"]
DecisionContext = Literal["pr", "release", "local"]

_SHA256_HEX = r"^[a-f0-9]{64}$"
_PREFIXED_SHA256 = r"^sha256:[a-f0-9]{64}$"
SchemaVersion = Literal["1.0", "1.1", "1.2", "1.3"]

# The version that introduced each optional field (an older record must not carry it) ...
_SINCE: dict[str, tuple[int, int]] = {
    "inputs.waivers_digest": (1, 1),
    "inputs.baseline_digest": (1, 2),
    "inputs.tool_status_digest": (1, 2),
    "inputs.service_context_digest": (1, 3),
}
# ... and the fields each version requires, as in the schema's allOf.
_REQUIRED: dict[str, frozenset[str]] = {
    "1.0": frozenset(),
    "1.1": frozenset({"inputs.waivers_digest"}),
    "1.2": frozenset({"inputs.waivers_digest"}),
    "1.3": frozenset({"inputs.waivers_digest", "inputs.service_context_digest"}),
}

_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @model_validator(mode="after")
    def _no_null(self) -> Self:
        # An optional field is absent or holds a value: the schema has no null.
        for name in sorted(self.model_fields_set):
            if getattr(self, name) is None:
                raise ValueError(f"{name} must be absent or hold a value, not null")
        return self


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
    service_context_digest: str | None = Field(default=None, pattern=_PREFIXED_SHA256)

    @field_validator("tool_versions")
    @classmethod
    def _versions(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not version for version in value.values()):
            raise ValueError("tool versions must not be empty")
        return value


class Decision(_Contract):
    schema_version: SchemaVersion
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

    def _present(self) -> set[str]:
        return {f"inputs.{name}" for name in self.inputs.model_fields_set}  # never null: see _no_null

    @model_validator(mode="after")
    def _consistent(self) -> "Decision":
        effects = {violation.effect for violation in self.violations}
        if self.verdict == "BLOCK" and "BLOCK" not in effects:
            raise ValueError("a BLOCK verdict needs at least one BLOCK violation")
        if self.verdict == "WARN" and effects != {"WARN"}:
            raise ValueError("a WARN verdict needs WARN violations only, and at least one")
        if self.verdict == "PASS" and self.violations:
            raise ValueError("a PASS verdict cannot have violations")
        major, minor = (int(part) for part in self.schema_version.split("."))
        present = self._present()
        for field, since in sorted(_SINCE.items()):
            if field in present and (major, minor) < since:
                raise ValueError(f"{field} exists only from schema {since[0]}.{since[1]}")
        if missing := sorted(_REQUIRED[self.schema_version] - present):
            raise ValueError(f"{missing[0]} is required in schema {self.schema_version}")
        return self
