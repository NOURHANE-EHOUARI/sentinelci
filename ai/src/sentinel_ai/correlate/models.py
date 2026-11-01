"""`RootCauseGroup` (schemas/root-cause-group.v1.json) as the correlator writes it (task A7)."""

import hashlib
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Stage = Literal["dedup", "structural", "embedding", "llm"]
Fingerprint = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
OneLine = Annotated[str, StringConstraints(pattern=r"^[^\r\n\u2028\u2029]*\S[^\r\n\u2028\u2029]*$")]


class ModelRef(BaseModel):
    """For stage `llm`: what produced the labels (model, prompt and input hashes, SPEC section 8)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str
    name: str
    prompt_sha256: Fingerprint
    input_sha256: Fingerprint


class RootCauseGroup(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    group_id: Fingerprint
    finding_ids: list[Fingerprint] = Field(min_length=1)
    stage: Stage
    key: str | None = None
    title: Annotated[OneLine, Field(max_length=200)]
    root_cause: Annotated[OneLine, Field(max_length=2000)]
    single_fix: Annotated[OneLine, Field(max_length=1000)] | None
    model: ModelRef | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.finding_ids)) != len(self.finding_ids):
            raise ValueError("a finding is listed twice")
        if (self.stage == "llm") != (self.model is not None):
            raise ValueError("`model` is set for stage llm, and only for it")
        return self

    def document(self) -> dict[str, object]:
        """The contract's JSON object: `single_fix` is always there (null when none), `key` and `model` only
        when set."""
        return self.model_dump(mode="json", exclude_none=True) | {"single_fix": self.single_fix}


def group_id(finding_ids: list[str]) -> str:
    """sha256 of the sorted ids joined by '|': the same members always give the same group id."""
    return hashlib.sha256("|".join(sorted(finding_ids)).encode("utf-8")).hexdigest()
