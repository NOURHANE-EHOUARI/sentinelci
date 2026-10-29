"""Enrichment snapshot and service context models.

They mirror schemas/enrichment-snapshot.v1.json and schemas/sentinel-config.v1.json.

Mirroring them means `sentinel enrich` needs no JSON Schema library at run time; tests check both against
the same fixtures and probes. Identifier patterns are checked with fullmatch on character classes that
exclude line breaks, so they agree with the schemas' line-break guard. Two rules JSON Schema cannot express
are checked here only: a KEV entry must be for a CVE the KEV lookup covered, and component paths are unique.

`sentinel.yaml` is a reviewed trust boundary (its exposure lowers scores), so it is read with a loader that
refuses what could make it mean something else than it says: duplicate keys, anchors and aliases (also
"billion laughs"), and tags beyond plain scalars, lists and mappings; and it is limited to 64 KiB.
"""

from __future__ import annotations

import json
import re
from datetime import date
from typing import Any, Literal

import yaml
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,63}")
_VULN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,63}")
_PURL_BASE = re.compile(r"pkg:[a-z0-9.+-]+/[^?#@\r\n\u2028\u2029]+")
_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_OWNER = re.compile(r"@[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:/[A-Za-z0-9._-]{1,100})?")
_NO_BREAK = re.compile(r"[^\r\n\u2028\u2029]+")
_NO_SPACE = re.compile(r"[^\s\ufeff]+")  # the schema's \S, line breaks included
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
# Canonical relative path: no leading "/", no empty, "." or ".." segment, no trailing "/", no backslash.
_RELATIVE_PATH = re.compile(
    r"(?!\.{1,2}(?:/|$))[^/\\\r\n\u2028\u2029]+(?:/(?!\.{1,2}(?:/|$))[^/\\\r\n\u2028\u2029]+)*"
)
MAX_CONFIG_BYTES = 64 * 1024
# What `sentinel enrich` and `sentinel evaluate` use when no snapshot is given: one value, so one digest.
EMPTY_SNAPSHOT = b'{\n  "schema_version": "1.0",\n  "sources": {},\n  "vulnerabilities": {}\n}\n'

Exposure = Literal["internet-facing", "internal", "offline"]
DataClass = Literal["public", "internal", "confidential", "restricted"]


class EnrichmentError(Exception):
    """A snapshot or service context cannot be used (fail closed: nothing is enriched)."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _no_null_or_bool(value: Any, path: str = "") -> None:
    """Neither contract has a null or a boolean anywhere: an optional field is left out, never null, and
    `version: yes` in YAML (a boolean) must not pass for 1, as Python's True == 1 would let it."""
    if value is None or isinstance(value, bool):
        raise EnrichmentError(f"{path or 'document'}: {json.dumps(value)} is not allowed here")
    if isinstance(value, dict):
        for key, item in value.items():
            _no_null_or_bool(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _no_null_or_bool(item, f"{path}[{index}]")


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
    cves: list[str]
    date_released: AwareDatetime | None = None

    @field_validator("catalog_version")
    @classmethod
    def _token(cls, v: str) -> str:
        return _check(_TOKEN, v, "catalog version")

    @field_validator("cves")
    @classmethod
    def _covered(cls, v: list[str]) -> list[str]:
        for cve in v:
            _check(_CVE, cve, "CVE id")
        if len(set(v)) != len(v):
            raise ValueError("kev.cves must be unique")
        return v


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
    def _one_word(cls, v: str | None) -> str | None:
        return None if v is None else _check(_NO_SPACE, v, "vector (no whitespace)")


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
    schema_version: Literal["1.0"]
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
        if self.sources.kev is not None:
            covered = set(self.sources.kev.cves)
            outside = sorted(i for i, v in self.vulnerabilities.items() if v.kev and i not in covered)
            if outside:
                raise ValueError(f"KEV entries for CVEs the KEV lookup did not cover: {', '.join(outside)}")
        return self


class Component(_Strict):
    path: str
    exposure: Exposure | None = None
    data_classification: DataClass | None = None

    @model_validator(mode="after")
    def _overrides_something(self) -> Component:
        if not _RELATIVE_PATH.fullmatch(self.path):
            raise ValueError(
                f"component path must be canonical and relative (no leading or trailing '/', no empty, "
                f"'.' or '..' part, no backslash): {self.path!r}"
            )
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
        paths = [c.path for c in self.components or []]
        if len(set(paths)) != len(paths):
            raise ValueError("component paths must be unique")
        return self


def _validate(model: type[BaseModel], document: Any, what: str) -> Any:
    try:
        _no_null_or_bool(document)
    except EnrichmentError as exc:
        raise EnrichmentError(f"{what} is not valid: {exc}") from exc
    try:
        # JSON mode: dates and date-times arrive as strings, exactly as in the files.
        return model.model_validate_json(json.dumps(document))
    except ValidationError as exc:
        raise EnrichmentError(
            f"{what} is not valid ({exc.error_count()} error(s)): {exc.errors()[0]['msg']}"
        ) from exc
    except (TypeError, ValueError, RecursionError) as exc:  # not JSON-shaped, or nested too deep
        raise EnrichmentError(f"{what} is not valid: {type(exc).__name__}") from exc


def load_snapshot(data: bytes) -> Snapshot:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EnrichmentError("enrichment snapshot is not UTF-8 JSON") from exc
    snapshot: Snapshot = _validate(Snapshot, document, "enrichment snapshot")
    return snapshot


class _ConfigLoader(yaml.SafeLoader):
    """SafeLoader without duplicate keys, anchors, aliases or tags beyond str, int, bool, float, list, map."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("anchors and aliases are not allowed in sentinel.yaml")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.YAMLError(
                    f"duplicate key {key!r} in sentinel.yaml (line {key_node.start_mark.line + 1})"
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _refuse_tag(loader: yaml.SafeLoader, node: Any) -> Any:
    raise yaml.YAMLError(f"{node.tag} values are not allowed in sentinel.yaml (quote the value)")


for _tag in ("timestamp", "binary", "set", "omap", "pairs"):
    _ConfigLoader.add_constructor(f"tag:yaml.org,2002:{_tag}", _refuse_tag)


def load_service_context(data: bytes) -> ServiceContext:
    if len(data) > MAX_CONFIG_BYTES:
        raise EnrichmentError(f"sentinel.yaml is larger than {MAX_CONFIG_BYTES} bytes")
    try:
        document = yaml.load(data.decode("utf-8"), Loader=_ConfigLoader)  # noqa: S506 - restricted SafeLoader
    except (UnicodeDecodeError, yaml.YAMLError, TypeError, ValueError, RecursionError) as exc:
        raise EnrichmentError(f"sentinel.yaml cannot be read: {exc}") from exc
    context: ServiceContext = _validate(ServiceContext, document, "sentinel.yaml")
    return context
