"""Finding v1 (schemas/finding.v1.json) as immutable Pydantic models."""

import re
from datetime import date
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, Strict, StrictBool, field_validator, model_validator

Category = Literal["SECRET", "SAST", "SCA", "CONTAINER", "IAC", "PIPELINE", "LICENSE"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RunContext = Literal["pr", "release", "local"]
# 1.1 adds `other_locations`; a finding without them may stay 1.0.
SchemaVersion = Literal["1.0", "1.1"]
# `relative_path` in the schema, character for character (a test keeps them equal): not absolute, no `..`
# segment, no line break anywhere. The leading guard makes Python and ECMA-262 engines agree.
_RELATIVE_PATH = re.compile(r"^(?![^\r\n\u2028\u2029]*[\r\n\u2028\u2029])(?!/)(?!.*(^|/)\.\.(/|$)).+$")


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Tool(_Contract):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)


class Location(_Contract):
    path: str = Field(min_length=1)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)

    @field_validator("path")
    @classmethod
    def _relative(cls, path: str) -> str:
        if not _RELATIVE_PATH.search(path):
            raise ValueError("path must be relative and must not contain '..'")
        return path


class Package(_Contract):
    purl: str
    name: str
    version: str
    ecosystem: str
    fixed_versions: list[str] | None = None


class Image(_Contract):
    digest: str
    ref: str | None = None
    layer: str | None = None


class Evidence(_Contract):
    snippet: str | None = Field(default=None, max_length=2000)
    secret_hash: str | None = None


class Run(_Contract):
    repo: str
    commit: str
    context: RunContext
    ref: str | None = None
    run_id: str | None = None


# Numbers and booleans as JSON has them: "0.5" is not a number and "yes" is not true (the schema agrees).
_Number = Annotated[float, Strict()]


class EnrichedCvss(_Contract):
    score: _Number = Field(ge=0, le=10)
    version: str | None = None
    vector: str | None = None


class EnrichedEpss(_Contract):
    score: _Number = Field(ge=0, le=1)
    percentile: _Number = Field(ge=0, le=1)
    date: date


class EnrichedKev(_Contract):
    listed: StrictBool
    date_added: date | None = None


class Enrichment(_Contract):
    """Typed by the enrichment task (B2): nothing outside the contract passes, whatever produced it."""

    cvss: EnrichedCvss | None = None
    epss: EnrichedEpss | None = None
    kev: EnrichedKev | None = None
    fix_available: StrictBool | None = None
    reachability: Literal["reachable", "imported", "unknown", "not_imported"] | None = None
    exposure: Literal["internet-facing", "internal", "offline"] | None = None


class Finding(_Contract):
    schema_version: SchemaVersion = "1.0"
    id: str
    tool: Tool
    rule_id: str
    category: Category
    title: str
    severity: Severity
    run: Run
    message: str | None = None
    severity_source: str | None = None
    cwe: list[str] | None = None
    cve: list[str] | None = None
    aliases: list[str] | None = None
    location: Location | None = None
    # Every other place the same finding was seen, sorted by (path, start_line); never truncated.
    other_locations: list[Location] | None = None
    package: Package | None = None
    image: Image | None = None
    evidence: Evidence | None = None
    enrichment: Enrichment | None = None
    # Typed by the risk task (B3); kept open here.
    risk: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _other_locations_rules(self) -> "Finding":
        if self.other_locations is None:
            return self
        if self.schema_version == "1.0":
            raise ValueError("other_locations needs schema_version 1.1")
        if self.location is None:
            raise ValueError("other_locations needs a primary location")
        if not self.other_locations:
            raise ValueError("other_locations must be omitted rather than empty")
        if len(set(self.other_locations)) != len(self.other_locations):
            raise ValueError("other_locations must not repeat a location")
        return self

    def to_json_dict(self) -> dict[str, Any]:
        """Serialize exactly as the contract expects (absent optional fields are omitted)."""
        return self.model_dump(mode="json", exclude_none=True)
