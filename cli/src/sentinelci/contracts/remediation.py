"""Read models of the remediation contracts: `schemas/patch-proposal.v1.json` and
`schemas/verification-result.v1.json` (SPEC §9). The contract fixtures pin each model to its schema: every
valid fixture is accepted and every invalid one refused. Strict, like the decision's and the release's models:
a value of another JSON type (`1` for `true`, `"81"` for `81`, a Unix time for a date) is refused, as the
schema refuses it, never coerced."""

import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict, Field, model_validator

_ONE_LINE = re.compile("[^\r\n\u2028\u2029]*")
# RFC 3339, as the schema's `format: date-time`: pydantic alone also reads "1893456000" as a Unix time, and
# takes a space for the "T" or a time without seconds (#88 review).
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})")
_UUID = r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"

Strategy = Literal[
    "deterministic:dependency-bump", "deterministic:dockerfile", "deterministic:kubernetes", "llm:code"
]
Outcome = Literal["VERIFIED", "REJECTED", "FAILED"]
MAX_ATTEMPTS = 3  # the first try and up to two retries with CI feedback (SPEC §9)


def _relative_path(value: str) -> str:
    parts = value.split("/")
    if not _ONE_LINE.fullmatch(value) or value.startswith("/") or ".." in parts:
        raise ValueError("must be a repository-relative path on one line, without `..`")
    return value


def _rfc3339(value: Any) -> Any:
    """An RFC 3339 string, parsed here: strict mode then sees the datetime. Anything else is left to strict
    mode (a datetime built in Python passes, any other type is refused)."""
    if not isinstance(value, str):
        return value
    if not _RFC3339.fullmatch(value):
        raise ValueError("must be an RFC 3339 date-time")
    return datetime.fromisoformat(value.upper())


def _utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("must carry a time zone")
    return value


Fingerprint = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
RelativePath = Annotated[str, Field(min_length=1), AfterValidator(_relative_path)]
Timestamp = Annotated[datetime, BeforeValidator(_rfc3339), AfterValidator(_utc_timestamp)]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Model(_Contract):
    name: str = Field(min_length=1)
    version: str | None = None
    prompt_version: str = Field(min_length=1)


class PatchProposal(_Contract):
    schema_version: Literal["1.0"]
    proposal_id: str = Field(pattern=_UUID)
    finding_ids: list[Fingerprint] = Field(min_length=1)
    strategy: Strategy
    diff: str = Field(min_length=1)
    files: list[RelativePath] = Field(min_length=1)
    rationale: str = Field(min_length=1)
    attempt: int = Field(ge=1, le=MAX_ATTEMPTS)
    model: Model | None = None
    created_at: Timestamp

    @model_validator(mode="after")
    def _rules(self) -> "PatchProposal":
        if len(set(self.finding_ids)) != len(self.finding_ids) or len(set(self.files)) != len(self.files):
            raise ValueError("finding_ids and files hold each value once")
        if self.strategy == "llm:code" and self.model is None:
            raise ValueError("an llm:code proposal names its model")
        return self


class VerificationResult(_Contract):
    schema_version: Literal["1.0"]
    proposal_id: str = Field(pattern=_UUID)
    attempt: int = Field(ge=1, le=MAX_ATTEMPTS)
    build_ok: bool
    tests_ok: bool
    target_resolved: bool
    new_findings: list[Fingerprint]
    verdict: Literal["PASS", "WARN", "BLOCK"]
    outcome: Outcome
    pull_request: int | None = Field(default=None, ge=1)
    verified_at: Timestamp

    @model_validator(mode="after")
    def _gate(self) -> "VerificationResult":
        if len(set(self.new_findings)) != len(self.new_findings):
            raise ValueError("new_findings holds each fingerprint once")
        verified = (
            self.build_ok and self.tests_ok and self.target_resolved and not self.new_findings
            and self.verdict != "BLOCK"
        )  # fmt: skip
        if self.outcome == "VERIFIED" and not verified:
            raise ValueError(
                "VERIFIED needs a build, passing tests, the target gone, no new finding and no BLOCK"
            )
        return self


class RemediationAttempt(_Contract):
    """`schemas/remediation-attempt.v1.json`: one attempt of the loop, its proposal and its result, for the
    platform (`sentinel upload-remediation`, `POST /api/v1/remediations`, A8). `problem()` adds the rules JSON
    Schema cannot express."""

    schema_version: Literal["1.0"]
    repo: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    proposal: PatchProposal
    result: VerificationResult

    def problem(self) -> str | None:
        """Why the result is not this proposal's, or None."""
        if self.result.proposal_id != self.proposal.proposal_id:
            return f"the result is about proposal {self.result.proposal_id}, not {self.proposal.proposal_id}"
        if self.result.attempt != self.proposal.attempt:
            return f"the result is about attempt {self.result.attempt}, not {self.proposal.attempt}"
        if self.result.verified_at < self.proposal.created_at:
            return "the result was verified before the proposal was made"
        return None
