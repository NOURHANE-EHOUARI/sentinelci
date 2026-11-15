"""Read model of `schemas/explanation.v1.json`: the AI analyst's explanation of one finding (B5, SPEC 8).

Advisory: the release gate never reads it. The platform checks a worker's explanation with this model before
it keeps it (B5c). The contract fixtures pin the model to its schema: every valid fixture is accepted and
every invalid one refused (cli/tests/test_explanation_contract.py).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

# pydantic-core has no look-ahead: these are the schema's patterns without it, with the same meaning.
_BREAK = "\r\n\u2028\u2029"
_ONE_LINE = rf"^[^{_BREAK}]*\S[^{_BREAK}]*$"
_SHA256_HEX = r"^[a-f0-9]{64}$"
_REFERENCE = r"^(CWE-[0-9]{1,5}|CVE-[0-9]{4}-[0-9]{4,7}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|https://[^\s]+)$"
# RFC 3339 date-time (`format: date-time`): a date alone, or a time without its offset, is not one.
_DATE_TIME = re.compile(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})")


def _date_time(value: str) -> str:
    if not _DATE_TIME.fullmatch(value):
        raise ValueError("must be an RFC 3339 date-time")
    datetime.fromisoformat(value.replace("z", "Z").replace("t", "T"))  # a real date (no 31 February)
    return value


OneLine = Annotated[str, Field(min_length=1, pattern=_ONE_LINE)]
Sha256Hex = Annotated[str, Field(pattern=_SHA256_HEX)]
DateTime = Annotated[str, AfterValidator(_date_time)]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ModelRecord(_Contract):
    """What produced the output: provider, model (and digest when pinned), and the prompt and input hashes."""

    provider: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:/@-]+$")
    digest: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")
    prompt_sha256: Sha256Hex
    input_sha256: Sha256Hex


class Explanation(_Contract):
    schema_version: Literal["1.0"]
    finding_id: Sha256Hex
    summary: Annotated[OneLine, Field(max_length=300)]
    impact: Annotated[OneLine, Field(max_length=2000)]
    exploit_scenario: Annotated[OneLine, Field(max_length=2000)]
    fix_guidance: Annotated[OneLine, Field(max_length=2000)]
    references: list[Annotated[str, Field(max_length=500, pattern=_REFERENCE)]] = Field(max_length=10)
    confidence: float = Field(ge=0, le=1)
    model: ModelRecord
    created_at: DateTime

    @model_validator(mode="after")
    def _unique_references(self) -> Explanation:
        if len(set(self.references)) != len(self.references):
            raise ValueError("references holds each value once")
        return self
