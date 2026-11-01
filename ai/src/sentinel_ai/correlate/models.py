"""The correlator's contracts as it writes them (task A7): `RootCauseGroup` (schemas/root-cause-group.v1.json)
and the run document that carries a run's groups, `Correlation` (schemas/correlation.v1.json).

The models refuse whatever the schemas refuse, and also what a schema cannot express: finding ids out of
order, a `group_id` that is not the sha256 of the members, and a run whose groups do not hold each finding
exactly once.
"""

import hashlib
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Stage = Literal["dedup", "structural", "embedding"]
LabelledBy = Literal["template", "llm"]
Fingerprint = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
OneLine = Annotated[str, StringConstraints(pattern=r"^[^\r\n\u2028\u2029]*\S[^\r\n\u2028\u2029]*$")]
MAX_KEY = 2048
_Similarity = Annotated[float, Field(ge=-1, le=1)]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ModelRef(_Contract):
    """For `labelled_by: llm`: what produced the labels (model, prompt and input hashes, SPEC section 8)."""

    provider: Annotated[str, StringConstraints(pattern=r"^[a-z0-9._-]+$", max_length=64)]
    name: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:/@-]+$", max_length=128)]
    prompt_sha256: Fingerprint
    input_sha256: Fingerprint


class RootCauseGroup(_Contract):
    schema_version: Literal["1.0"] = "1.0"
    group_id: Fingerprint
    finding_ids: list[Fingerprint] = Field(min_length=1)
    stage: Stage  # what formed the group
    labelled_by: LabelledBy = "template"  # who wrote its labels
    similarity: _Similarity | None = None  # for stage embedding: the linkage of its last merge
    key: Annotated[OneLine, Field(max_length=MAX_KEY)] | None = None
    title: Annotated[OneLine, Field(max_length=200)]
    root_cause: Annotated[OneLine, Field(max_length=2000)]
    single_fix: Annotated[OneLine, Field(max_length=1000)] | None
    model: ModelRef | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.finding_ids)) != len(self.finding_ids):
            raise ValueError("a finding is listed twice")
        if self.finding_ids != sorted(self.finding_ids) or self.group_id != group_id(self.finding_ids):
            raise ValueError("finding_ids must be sorted and group_id the sha256 of them")
        if (self.labelled_by == "llm") != (self.model is not None):
            raise ValueError("`model` is set when a model wrote the labels, and only then")
        if (self.stage == "embedding") != (self.similarity is not None):
            raise ValueError("`similarity` is set for stage embedding, and only for it")
        return self

    def document(self) -> dict[str, object]:
        """The contract's JSON object: `single_fix` is always there (null when none); `key`, `similarity` and
        `model` only when set."""
        return self.model_dump(mode="json", exclude_none=True) | {"single_fix": self.single_fix}


class EmbeddingModel(_Contract):
    provider: Annotated[str, StringConstraints(pattern=r"^[a-z0-9._-]+$", max_length=64)]
    name: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._:/@-]+$", max_length=128)]
    digest: Annotated[str, StringConstraints(pattern=r"^sha256:[a-f0-9]{64}$")]


class Correlator(_Contract):
    version: Annotated[str, StringConstraints(pattern=r"^[0-9A-Za-z.+-]+$", max_length=64)]
    stages: list[Stage] = Field(min_length=1)
    threshold: _Similarity | None = None
    embedding_model: EmbeddingModel | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if "dedup" not in self.stages or len(set(self.stages)) != len(self.stages):
            raise ValueError("stages: each once, dedup always")
        embedded = "embedding" in self.stages
        if embedded != (self.threshold is not None) or embedded != (self.embedding_model is not None):
            raise ValueError("threshold and embedding_model are set when stage embedding ran, and only then")
        return self


class Correlation(_Contract):
    """One correlator run: the groups, the findings they were computed from, and how."""

    schema_version: Literal["1.0"] = "1.0"
    findings_sha256: Fingerprint
    correlator: Correlator
    groups: list[RootCauseGroup]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if [g.group_id for g in self.groups] != sorted(g.group_id for g in self.groups):
            raise ValueError("groups must be sorted by group_id")
        ids = [finding_id for group in self.groups for finding_id in group.finding_ids]
        if len(set(ids)) != len(ids):
            raise ValueError("a finding is in two groups")
        formed = {group.stage for group in self.groups} - {"dedup"}
        if not formed <= set(self.correlator.stages):
            raise ValueError("a group was formed by a stage that did not run")
        return self

    def document(self) -> dict[str, object]:
        """The contract's JSON object."""
        return {
            "schema_version": self.schema_version,
            "findings_sha256": self.findings_sha256,
            "correlator": self.correlator.model_dump(mode="json", exclude_none=True),
            "groups": [group.document() for group in self.groups],
        }


def group_id(finding_ids: list[str]) -> str:
    """sha256 of the sorted ids joined by '|': the same members always give the same group id."""
    return hashlib.sha256("|".join(sorted(finding_ids)).encode("utf-8")).hexdigest()
