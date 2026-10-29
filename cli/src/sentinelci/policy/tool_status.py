"""Load a tool status document (schemas/tool-status.v1.json): what happened to every scanner of a run.

The model mirrors the schema so `sentinel evaluate` needs no JSON Schema library at run time; tests check
both against the same fixtures. A document that does not validate means no decision (fail closed). A valid one
goes to the policy unchanged, where any tool that is not `ok` becomes SC-010.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from sentinelci.policy.errors import EvaluationError

_SHA256_HEX = r"^[a-f0-9]{64}$"
ToolStatusValue = Literal["ok", "failed", "timeout", "integrity_mismatch", "not_run"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ToolEntry(_Strict):
    version: str = Field(min_length=1)
    artifact_sha256: str | None = Field(default=None, pattern=_SHA256_HEX)
    binary_sha256: str | None = Field(default=None, pattern=_SHA256_HEX)
    status: ToolStatusValue
    detail: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def _status_needs_evidence(self) -> ToolEntry:
        if self.status == "ok" and self.binary_sha256 is None:
            raise ValueError("an ok tool must name its verified binary_sha256")
        if self.status != "ok" and self.detail is None:
            raise ValueError("a tool that is not ok must explain why in detail")
        return self


class ToolStatus(_Strict):
    schema_version: Literal[1]
    platform: str | None = Field(default=None, pattern=r"^(linux|darwin)-(amd64|arm64)$")
    lock_sha256: str = Field(pattern=_SHA256_HEX)
    tools: dict[str, ToolEntry] = Field(min_length=1)

    @model_validator(mode="after")
    def _tool_names(self) -> ToolStatus:
        for name in self.tools:
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", name):
                raise ValueError(f"invalid tool name {name!r}")
        return self


def load_tool_status(data: bytes) -> dict[str, Any]:
    """Return the validated document as parsed JSON (what the policy sees)."""
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvaluationError("tool status is not UTF-8 JSON") from exc
    try:
        ToolStatus.model_validate(document)
    except ValidationError as exc:
        raise EvaluationError(
            f"tool status is not a tool-status v1 document ({exc.error_count()} error(s))"
        ) from exc
    result: dict[str, Any] = document
    return result
