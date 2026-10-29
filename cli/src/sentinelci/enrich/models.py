"""Enrichment snapshot and service context models.

They mirror schemas/enrichment-snapshot.v1.json and schemas/sentinel-config.v1.json.

Mirroring them means `sentinel enrich` needs no JSON Schema library at run time; tests check both against
the same fixtures. Identifier patterns are checked with fullmatch on character classes that exclude line
breaks, so they agree with the schemas' line-break guard.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}")
_VULN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,63}")
_PURL_BASE = re.compile(r"pkg:[a-z0-9.+-]+/[^?#@\r\n\u2028\u2029]+")
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_OWNER = re.compile(r"@[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:/[A-Za-z0-9._-]{1,100})?")
_NO_BREAK = re.compile(r"[^\r\n\u2028\u2029]+")

Exposure = Literal["internet-facing", "internal", "offline"]
DataClass = Literal["public", "internal", "confidential", "restricted"]


class EnrichmentError(Exception):
    """A snapshot or service context cannot be used (fail closed: nothing is enriched)."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


class EpssSource(_Strict):
    date: date
    model_version: str | None = None

    @field_validator("model_version")
    @classmethod
    def _token(cls, v: str | None) -> str | None:
        return None if v is None else _check(_TOKEN, v, "model version")


class KevSource(_Strict):
    catalog_version: str
    date_released: datetime | None = None

    @field_validator("catalog_version")
    @classmethod
    def _token(cls, v: str) -> str:
        return _check(_TOKEN, v, "catalog version")


class OsvSource(_Strict):
    date: date


class Sources(_Strict):
    epss: EpssSource | None = None
    kev: KevSource | None = None
    osv: OsvSource | None = None


class Cvss(_Strict):
    version: Literal["2.0", "3.0", "3.1", "4.0"]
    score: float = Field(ge=0, le=10)
    vector: str | None = None

    @field_validator("vector")
    @classmethod
    def _one_line(cls, v: str | None) -> str | None:
        return None if v is None else _check(_NO_BREAK, v, "vector")


class Epss(_Strict):
    score: float = Field(ge=0, le=1)
    percentile: float = Field(ge=0, le=1)


class Kev(_Strict):
    date_added: date


class Vulnerability(_Strict):
    aliases: list[str] | None = None
    cvss: Cvss | None = None
    fixed_versions: dict[str, list[str]] | None = None
    epss: Epss | None = None
    kev: Kev | None = None

    @model_validator(mode="after")
    def _shape(self) -> Vulnerability:
        if not self.model_fields_set:
            raise ValueError("a vulnerability entry must hold at least one value")
        for alias in self.aliases or []:
            _check(_VULN_ID, alias, "alias")
        if self.aliases is not None and len(set(self.aliases)) != len(self.aliases):
            raise ValueError("aliases must be unique")
        for purl, versions in (self.fixed_versions or {}).items():
            _check(_PURL_BASE, purl, "purl base (no version, qualifiers or subpath)")
            for version in versions:
                _check(_TOKEN, version, "fixed version")
            if len(set(versions)) != len(versions):
                raise ValueError("fixed versions must be unique")
        return self


class Snapshot(_Strict):
    schema_version: Literal[1]
    sources: Sources
    vulnerabilities: dict[str, Vulnerability]

    @model_validator(mode="after")
    def _consistent(self) -> Snapshot:
        for vuln_id in self.vulnerabilities:
            _check(_VULN_ID, vuln_id, "vulnerability id")
        entries = self.vulnerabilities.values()
        if any(v.epss for v in entries) and self.sources.epss is None:
            raise ValueError("EPSS values need the epss source (its date)")
        if any(v.kev for v in entries) and self.sources.kev is None:
            raise ValueError("KEV entries need the kev source")
        return self


class Component(_Strict):
    path: str
    exposure: Exposure | None = None
    data_classification: DataClass | None = None

    @model_validator(mode="after")
    def _overrides_something(self) -> Component:
        parts = self.path.split("/")
        if (
            not _NO_BREAK.fullmatch(self.path)
            or self.path.startswith("/")
            or "\\" in self.path
            or ".." in parts
        ):
            raise ValueError(f"component path must be relative, without '..': {self.path!r}")
        if self.exposure is None and self.data_classification is None:
            raise ValueError(f"component {self.path!r} overrides nothing")
        return self


class ServiceContext(_Strict):
    version: Literal[1]
    service: str
    exposure: Exposure
    environment: Literal["production", "staging", "development", "test"] | None = None
    data_classification: DataClass | None = None
    owners: list[str] | None = Field(default=None, min_length=1)
    policy_profile: Literal["default", "strict"] | None = None
    components: list[Component] | None = None

    @model_validator(mode="after")
    def _identifiers(self) -> ServiceContext:
        _check(_NAME, self.service, "service name")
        for owner in self.owners or []:
            _check(_OWNER, owner, "owner (@user or @org/team)")
        if self.owners is not None and len(set(self.owners)) != len(self.owners):
            raise ValueError("owners must be unique")
        return self


def _validate(model: type[BaseModel], document: Any, what: str) -> Any:
    try:
        # JSON mode: dates and date-times arrive as strings, exactly as in the files.
        return model.model_validate_json(json.dumps(document))
    except ValidationError as exc:
        raise EnrichmentError(
            f"{what} is not valid ({exc.error_count()} error(s)): {exc.errors()[0]['msg']}"
        ) from exc


def load_snapshot(data: bytes) -> Snapshot:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EnrichmentError("enrichment snapshot is not UTF-8 JSON") from exc
    snapshot: Snapshot = _validate(Snapshot, document, "enrichment snapshot")
    return snapshot


def load_service_context(data: bytes) -> ServiceContext:
    try:
        document = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise EnrichmentError("sentinel.yaml is not UTF-8 YAML") from exc
    context: ServiceContext = _validate(ServiceContext, document, "sentinel.yaml")
    return context
