"""Trust report v1 and release evidence v1 (schemas/trust-report.v1.json, schemas/release-evidence.v1.json) as
immutable, read-only Pydantic models: what `sentinel verify --report-json` writes, and what `make release`
sends to the platform (`sentinel upload-release`, `POST /api/v1/releases`, task A8).

The contract fixtures pin each model to its schema: every valid fixture is accepted and every invalid one
refused. `problem()` adds the rules JSON Schema cannot express; a document with a problem is refused by its
producer and by the platform, so the Releases page never shows a report that contradicts itself.
"""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from sentinelci.contracts.decision import Decision

_BREAKS = "\r\n" + chr(0x2028) + chr(0x2029)  # a line ends at any of them (schemas/README.md)
_ONE_LINE = f"^[^{_BREAKS}]*$"
TrustMode = Literal["registry", "evidence"]


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ImageRef(_Contract):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9._/:-]{0,254}$")
    digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")


class CheckResult(_Contract):
    name: Annotated[str, StringConstraints(min_length=1, max_length=120, pattern=_ONE_LINE)]
    ok: bool
    detail: Annotated[str, StringConstraints(max_length=300, pattern=_ONE_LINE)]


class TrustReport(_Contract):
    schema_version: Literal["1.0"]
    image: ImageRef
    mode: TrustMode
    repo: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    builder_id: str = Field(max_length=512, pattern=f"^https://[^\\s{_BREAKS}]+$")
    key_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    verified_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
    trusted: bool
    checks: tuple[CheckResult, ...] = Field(min_length=1, max_length=32)

    def problem(self) -> str | None:
        """Why the report contradicts itself, or None."""
        try:
            datetime.fromisoformat(self.verified_at)
        except ValueError:
            return f"verified_at {self.verified_at} is not a date and time"
        failed = [check.name for check in self.checks if not check.ok]
        if self.trusted == bool(failed):
            return f"trusted is {self.trusted}, but {len(failed)} of {len(self.checks)} checks failed"
        return None


class ReleaseEvidence(_Contract):
    schema_version: Literal["1.0"]
    decision: Decision
    trust_reports: tuple[TrustReport, ...] = Field(max_length=2)

    @property
    def image_digest(self) -> str:
        return str(self.decision.subject.image_digest)

    @property
    def trusted(self) -> bool | None:
        """True when every report trusts the image, False when one does not, None with no report."""
        if not self.trust_reports:
            return None
        return all(report.trusted for report in self.trust_reports)

    def problem(self) -> str | None:
        """Why this evidence is not one release's, or None (the rules JSON Schema cannot express)."""
        subject = self.decision.subject
        if subject.context != "release":
            return f"the decision is a {subject.context} decision, not a release decision"
        if subject.image_digest is None:
            return "the release decision names no image digest"
        modes = [report.mode for report in self.trust_reports]
        if len(set(modes)) != len(modes):
            return f"two trust reports of the same mode ({', '.join(modes)})"
        for report in self.trust_reports:
            if (problem := report.problem()) is not None:
                return f"the {report.mode} trust report: {problem}"
            if report.image.digest != subject.image_digest:
                about = report.image.digest
                return f"the {report.mode} trust report is about {about}, not {subject.image_digest}"
            if report.repo != subject.repo:
                return f"the {report.mode} trust report required {report.repo}, not {subject.repo}"
            if report.trusted and self.decision.verdict == "BLOCK":
                return f"the {report.mode} trust report trusts an image the gate blocked"
        return None
