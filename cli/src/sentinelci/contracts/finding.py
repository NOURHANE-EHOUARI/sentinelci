"""Finding v1 (schemas/finding.v1.json) as immutable Pydantic models."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal["SECRET", "SAST", "SCA", "CONTAINER", "IAC", "PIPELINE", "LICENSE"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
RunContext = Literal["pr", "release", "local"]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Tool(_Contract):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)


class Location(_Contract):
    path: str = Field(min_length=1)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)


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


class Finding(_Contract):
    schema_version: Literal["1.0"] = "1.0"
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
    package: Package | None = None
    image: Image | None = None
    evidence: Evidence | None = None
    # Typed by the enrichment (B2) and risk (B3) tasks; kept open here.
    enrichment: dict[str, Any] | None = None
    risk: dict[str, Any] | None = None

    def to_json_dict(self) -> dict[str, Any]:
        """Serialize exactly as the contract expects (absent optional fields are omitted)."""
        return self.model_dump(mode="json", exclude_none=True)
