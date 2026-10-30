"""VEX statements (SPEC section 6.4): `.sentinel/vex.json`, an OpenVEX v0.2.0 subset (schemas/vex.v1.json).

Read from the base branch and reviewed like the waivers, and recorded by digest. This module checks the
document against its contract and turns each `not_affected` statement into what the gate matches on: the
vulnerability ids (name and aliases) and the products (canonical purl base, and the version when the purl has
one). The gate (policies/gate.rego) decides which findings it covers. Other statuses change nothing.

The models mirror the schema; one table-driven test runs every fixture through both.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError, model_validator

from sentinelci.enrich.apply import canonical_purl
from sentinelci.normalize.fingerprint import purl_base
from sentinelci.policy.errors import EvaluationError

DEFAULT_VEX_PATH = ".sentinel/vex.json"
CONTEXT = "https://openvex.dev/ns/v0.2.0"
_VULN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,63}")
_PURL = re.compile(
    r"pkg:[a-z0-9.+-]+/[^?#@\r\n\u2028\u2029]+(@[^?#@/\r\n\u2028\u2029]+)?(\?[^#\r\n\u2028\u2029]*)?"
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


class _Vulnerability(_Strict):
    id: str | None = Field(default=None, alias="@id")
    name: str
    description: str | None = None
    aliases: list[str] | None = None

    @model_validator(mode="after")
    def _ids(self) -> _Vulnerability:
        for value in [self.name, *(self.aliases or [])]:
            _check(_VULN_ID, value, "vulnerability id")
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
    timestamp: AwareDatetime | None = None
    last_updated: AwareDatetime | None = None
    vulnerability: _Vulnerability
    products: list[_Product] = Field(min_length=1)
    status: Literal["not_affected", "affected", "fixed", "under_investigation"]
    justification: Justification | None = None
    impact_statement: str | None = None
    status_notes: str | None = None
    action_statement: str | None = None
    action_statement_timestamp: AwareDatetime | None = None

    @model_validator(mode="after")
    def _justified(self) -> _Statement:
        if (self.status == "not_affected") != (self.justification is not None):
            raise ValueError("a justification is required for not_affected, and only for it")
        return self


class _Document(_Strict):
    context: Literal["https://openvex.dev/ns/v0.2.0"] = Field(alias="@context")
    id: str = Field(alias="@id")
    author: str
    role: str | None = None
    timestamp: AwareDatetime
    last_updated: AwareDatetime | None = None
    version: int = Field(ge=1)
    tooling: str | None = None
    statements: list[_Statement] = Field(min_length=1)

    @model_validator(mode="after")
    def _texts(self) -> _Document:
        for value in (self.id, self.author, self.role, self.tooling):
            if value is not None:
                _check(_TEXT, value, "text (no line break, not blank)")
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


def load_vex(data: bytes) -> list[dict[str, Any]]:
    """The not_affected statements of a VEX document, normalized for the gate (EvaluationError if invalid)."""
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EvaluationError("VEX document is not UTF-8 JSON") from exc
    _no_null_or_bool(document)
    try:
        parsed = _Document.model_validate_json(json.dumps(document))
    except ValidationError as exc:
        raise EvaluationError(f"VEX document is not valid: {exc.errors()[0]['msg']}") from exc
    return [
        {
            "vulnerabilities": sorted({s.vulnerability.name, *(s.vulnerability.aliases or [])}),
            "products": [_product(p.id) for p in s.products],
            "justification": s.justification,
        }
        for s in parsed.statements
        if s.status == "not_affected"
    ]
