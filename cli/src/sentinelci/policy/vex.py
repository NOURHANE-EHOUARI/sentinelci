"""VEX statements (SPEC section 6.4): `.sentinel/vex.json`, an OpenVEX v0.2.0 subset (schemas/vex.v1.json).

Read from the base branch and reviewed like the waivers, and recorded by digest. This module checks the
document against its contract and turns every statement into what the gate matches on: its status, the
vulnerability ids (name and aliases), the products (canonical purl base, and the version when the purl has
one), and when it was made. The gate (policies/gate.rego) decides which findings a `not_affected` statement
covers: none that a statement of another status is also about (OpenVEX statements override earlier ones, and
the gate does not order them), and only for 90 days after the statement was made, like a waiver.

The models mirror the schema; one table-driven test runs every fixture through both.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError, model_validator

from sentinelci.enrich.apply import canonical_purl
from sentinelci.enrich.models import _RFC3339
from sentinelci.normalize.fingerprint import purl_base
from sentinelci.policy.errors import EvaluationError

DEFAULT_VEX_PATH = ".sentinel/vex.json"
MAX_VEX_BYTES = 4 * 1024 * 1024  # about 25,000 statements
CONTEXT = "https://openvex.dev/ns/v0.2.0"
_VULN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,63}")
_PURL = re.compile(
    r"(?!pkg:oci/)pkg:[a-z0-9.+-]+/[^?#@\r\n\u2028\u2029]+(@[^?#@/\r\n\u2028\u2029]+)?(\?[^#\r\n\u2028\u2029]*)?"
)
_TEXT = re.compile(r"[^\r\n\u2028\u2029]*\S[^\r\n\u2028\u2029]*")

Justification = Literal[
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, populate_by_name=False)


def _check(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def _texts(*values: str | None) -> None:
    for value in values:
        if value is not None:
            _check(_TEXT, value, "text (no line break, not blank)")


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.upper().replace("Z", "+00:00"))  # month 13 or hour 25: ValueError


def _rfc3339(value: str) -> str:
    """The schema's `date-time`, checked as KevSource.date_released is (Pydantic's datetime also takes a space
    or "_" separator, no seconds, or Unix seconds)."""
    _check(_RFC3339, value, "RFC 3339 date-time")
    _instant(value)
    return value


Timestamp = Annotated[str, AfterValidator(_rfc3339)]


class _Vulnerability(_Strict):
    id: str | None = Field(default=None, alias="@id")
    name: str
    description: str | None = None
    aliases: list[str] | None = None

    @model_validator(mode="after")
    def _ids(self) -> _Vulnerability:
        for value in [self.name, *(self.aliases or [])]:
            _check(_VULN_ID, value, "vulnerability id")
        _texts(self.id, self.description)
        if self.aliases is not None and len(set(self.aliases)) != len(self.aliases):
            raise ValueError("aliases must be unique")
        return self


class _Product(_Strict):
    id: str = Field(alias="@id")

    @model_validator(mode="after")
    def _purl(self) -> _Product:
        _check(_PURL, self.id, "product (a package URL)")
        return self


class _Statement(_Strict):
    id: str | None = Field(default=None, alias="@id")
    timestamp: Timestamp | None = None
    last_updated: Timestamp | None = None
    vulnerability: _Vulnerability
    products: list[_Product] = Field(min_length=1)
    status: Literal["not_affected", "affected", "fixed", "under_investigation"]
    justification: Justification | None = None
    impact_statement: str | None = None
    status_notes: str | None = None
    action_statement: str | None = None
    action_statement_timestamp: Timestamp | None = None

    @model_validator(mode="after")
    def _justified(self) -> _Statement:
        if (self.status == "not_affected") != (self.justification is not None):
            raise ValueError("a justification is required for not_affected, and only for it")
        _texts(self.id, self.impact_statement, self.status_notes, self.action_statement)
        return self


class _Document(_Strict):
    context: Literal["https://openvex.dev/ns/v0.2.0"] = Field(alias="@context")
    id: str = Field(alias="@id")
    author: str
    role: str | None = None
    timestamp: Timestamp
    last_updated: Timestamp | None = None
    version: int = Field(ge=1)
    tooling: str | None = None
    statements: list[_Statement] = Field(min_length=1)

    @model_validator(mode="after")
    def _texts(self) -> _Document:
        _texts(self.id, self.author, self.role, self.tooling)
        return self


def _no_null_or_bool(value: Any) -> None:
    # The contract has no null and no boolean; `version: true` must not pass for 1 (True == 1).
    if value is None or isinstance(value, bool):
        raise EvaluationError(f"VEX document holds {json.dumps(value)}, which the contract does not allow")
    if isinstance(value, dict):
        for item in value.values():
            _no_null_or_bool(item)
    elif isinstance(value, list):
        for item in value:
            _no_null_or_bool(item)


def _product(purl: str) -> dict[str, str | None]:
    head = purl.partition("#")[0].partition("?")[0]
    name_start, at = head.rfind("/") + 1, head.rfind("@")
    return {"base": canonical_purl(purl_base(purl)), "version": head[at + 1 :] if at >= name_start else None}


def _utc(value: str) -> str:
    """One RFC 3339 spelling for the gate (`time.parse_rfc3339_ns` wants upper case `T` and `Z`)."""
    return _instant(value).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # `"status": "affected", "status": "not_affected"` would otherwise read as the last one, which a reviewer
    # of the raw file may not see.
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"duplicate key {next(k for k in keys if keys.count(k) > 1)!r}")
    return dict(pairs)


def load_vex(data: bytes) -> list[dict[str, Any]]:
    """Every statement of a VEX document, normalized for the gate (EvaluationError if invalid).

    `made` is when the statement was made: its own `last_updated` or `timestamp`, else the document's
    `timestamp`. `document_updated` is the document's `last_updated` or `timestamp`. Both are UTC; the gate
    refuses either one after `evaluated_at` (a statement dated in the future would outlive any review) and
    lets a `not_affected` statement apply for 90 days after `made`.
    """
    if len(data) > MAX_VEX_BYTES:
        raise EvaluationError(f"VEX document is larger than {MAX_VEX_BYTES} bytes")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EvaluationError(f"VEX document is not UTF-8 JSON with unique keys: {exc}") from exc
    try:
        _no_null_or_bool(document)
    except RecursionError as exc:  # json.loads accepts deeper nesting than Python recursion allows
        raise EvaluationError("VEX document is nested too deeply") from exc
    try:
        parsed = _Document.model_validate_json(json.dumps(document))
    except ValidationError as exc:
        raise EvaluationError(f"VEX document is not valid: {exc.errors()[0]['msg']}") from exc
    updated = _utc(parsed.last_updated or parsed.timestamp)
    return [
        {
            "status": s.status,  # every status: a statement of another status disputes not_affected
            "vulnerabilities": sorted({s.vulnerability.name, *(s.vulnerability.aliases or [])}),
            "products": [_product(p.id) for p in s.products],
            "justification": s.justification,
            "made": _utc(s.last_updated or s.timestamp or parsed.timestamp),
            "document_updated": updated,
        }
        for s in parsed.statements
    ]
