"""Store a run's correlation on the platform, next to its findings (task A7, SPEC §8; platform API, B1).

The correlator reads a run's findings exactly as the platform recorded them (`GET /api/v1/runs/{id}/findings`,
checked against the run's `findings_sha256`), correlates them, and posts the Correlation v1 document to
`POST /api/v1/runs/{id}/correlations`. The platform keeps the bytes as they were sent; their sha256 is the
version.

- A version is never overwritten. The same bytes a second time are answered 409 with the version the platform
  has, which counts as stored. Other bytes are another version: the platform's GET gives the latest one by
  order of writing, or one by its sha256.
- The document is canonical JSON (keys sorted, no white space, UTF-8, one final line feed), so the same
  correlation is always the same bytes. Stages 1 and 2 are deterministic: the same findings and correlator
  give the same version again. With embeddings, only while the embeddings are stable; stage 3's labels are
  a model's text, so a rerun is a new version even with the same model and prompt.
- The latest version can be a degraded one: an embedder that failed is recorded in `correlator.skipped`, never
  hidden, and the groups are then those of stages 1 and 2.
- Advice only: the release gate never reads a correlation, and the decision path cannot import this package.
- The transport is the CLI's platform client (`sentinelci.report.upload`): the token comes only from
  SENTINEL_API_TOKEN, plain http only on the loopback and never through a proxy, no redirect followed, an
  overall deadline, and the token is never printed.
"""

import hashlib
import json
import re
from dataclasses import dataclass

from sentinel_ai.correlate.models import Correlation, EmbeddingModel
from sentinel_ai.correlate.stages import DEFAULT_THRESHOLD, Embedder, correlate_run
from sentinelci.report.upload import Platform, UploadError, answer_summary

MAX_FINDINGS_BYTES = 32 * 1024 * 1024  # the platform's default upload limit (SENTINEL_API_MAX_UPLOAD_BYTES)
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_SHA256 = re.compile(r"[a-f0-9]{64}")


class StoreError(Exception):
    """The correlation was not stored: nothing on the platform changed because of this run of the command."""


@dataclass(frozen=True)
class Stored:
    run_id: str
    sha256: str  # the version: sha256 of the document's bytes
    groups: int
    stages: tuple[str, ...]
    skipped: tuple[str, ...]  # stages asked for that could not run (a degraded version)
    already_recorded: bool


def document_bytes(correlation: Correlation) -> bytes:
    """The canonical bytes of the Correlation v1 document: what is sent, and what its version hashes."""
    text = json.dumps(correlation.document(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8") + b"\n"


def read_findings(platform: Platform, run_id: str) -> bytes:
    """The run's findings, byte for byte as recorded, or StoreError."""
    if not _UUID.fullmatch(run_id):
        raise StoreError(f"{run_id!r} is not a run id")
    try:
        run = platform.run(run_id)
        recorded = run.get("findings_sha256")
        if not isinstance(recorded, str) or not _SHA256.fullmatch(recorded):
            raise StoreError(f"run {run_id} has no findings recorded yet: there is nothing to correlate")
        data = platform.get_bytes(f"/api/v1/runs/{run_id}/findings", limit=MAX_FINDINGS_BYTES)
    except UploadError as exc:
        raise StoreError(str(exc)) from exc
    if hashlib.sha256(data).hexdigest() != recorded:
        raise StoreError(f"the platform served other findings for run {run_id} than the ones it recorded")
    return data


def store(platform: Platform, run_id: str, correlation: Correlation, *, findings: bytes) -> Stored:
    """Post the correlation of `findings` (the run's recorded bytes) as a new version, or confirm the one the
    platform already has with the same bytes."""
    if correlation.findings_sha256 != hashlib.sha256(findings).hexdigest():
        raise StoreError("the correlation was not computed from this run's findings")
    data = document_bytes(correlation)
    version = hashlib.sha256(data).hexdigest()
    try:
        status, body = platform.post_json(f"/api/v1/runs/{run_id}/correlations", data)
    except UploadError as exc:
        raise StoreError(f"{exc} (the same command again stores it, or finds it stored)") from exc
    answered = body.get("sha256") if isinstance(body, dict) else None
    existing = body.get("correlation") if status == 409 and isinstance(body, dict) else None
    if status == 409 and not isinstance(existing, dict):  # a refusal (no findings recorded), not a version
        raise StoreError(f"storing the correlation failed: {answer_summary(status, body)}")
    if status == 409 and isinstance(existing, dict):
        answered = existing.get("sha256")
    if status in (201, 409) and answered == version:
        return Stored(
            run_id=run_id,
            sha256=version,
            groups=len(correlation.groups),
            stages=tuple(correlation.correlator.stages),
            skipped=tuple(item.stage for item in correlation.correlator.skipped or []),
            already_recorded=status == 409,
        )
    if status in (201, 409):
        raise StoreError(
            f"the platform recorded version {answered!r}, not the sha256 of the bytes sent ({version}): "
            "nothing is confirmed"
        )
    raise StoreError(f"storing the correlation failed: {answer_summary(status, body)}")


def correlate_and_store(
    platform: Platform,
    run_id: str,
    *,
    structural: bool = True,
    embed: Embedder | None = None,
    embedding_model: EmbeddingModel | None = None,
    threshold: float = DEFAULT_THRESHOLD,
) -> Stored:
    """Read the run's recorded findings, correlate them (stages 1 and 2, and 2b with an embedder), store the
    document. Stage 3 (labels) runs between `correlate_run` and `store` when a provider is configured (B5)."""
    findings = read_findings(platform, run_id)
    correlation = correlate_run(
        findings, structural=structural, embed=embed, embedding_model=embedding_model, threshold=threshold
    )
    return store(platform, run_id, correlation, findings=findings)
