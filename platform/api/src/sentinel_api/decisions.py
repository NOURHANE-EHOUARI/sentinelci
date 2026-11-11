"""A run's gate decision (Decision v1, task B4, SPEC section 6.5): record it, then serve it byte for byte.

The platform records what the gate decided; it never decides, and nothing here changes a verdict.

- `POST /api/v1/runs/{run_id}/decision`: the Decision v1 document `sentinel evaluate` wrote, as JSON. It is
  checked before it is kept: the contract (`sentinelci.contracts.decision`, which mirrors every rule of the
  schema, verdict consistency included), and that it is this run's decision: made on exactly the findings the
  run recorded (`inputs.findings_digest` is `sha256:` and the run's `findings_sha256`), about the run's
  subject (repo, commit, context, and the ref when the decision names one), and naming only findings the run
  recorded. A run has one decision: the same bytes again are answered 409 with it (a re-run of the upload
  step), and a different decision is refused with 409, as is a `decision_id` another run recorded.
- `GET /api/v1/runs/{run_id}/decision`: the decision byte for byte (what to hash, or to compare with the
  evidence bundle), its sha256 as the ETag. The run lists its `verdict` (`GET /runs`, `GET /runs/{id}`).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from sentinel_api.api import ErrorOut, SessionDep, _read_body
from sentinel_api.auth import require_writer
from sentinel_api.correlations import _invalid, _no_duplicate_keys, _refuse_constant
from sentinel_api.models import Run, RunDecision, RunFinding
from sentinelci.contracts.decision import Decision as DecisionDocument
from sentinelci.contracts.decision import Verdict

JSON_TYPE = "application/json"

router = APIRouter(prefix="/api/v1")


class DecisionOut(BaseModel):
    run_id: uuid.UUID
    sha256: str
    decision_id: uuid.UUID
    verdict: Verdict
    evaluated_at: datetime
    engine_version: str
    created_at: datetime


class DecisionExists(BaseModel):
    """409: this run's decision (`decision`) is recorded already, or the `decision_id` is another run's."""

    detail: str
    decision: DecisionOut


_REASONS = {
    401: "No valid ingestion token (`Authorization: Bearer <token>`).",
    404: "No such run, or no decision recorded for it.",
    413: "The document is larger than the upload limit.",
    415: f"The decision is not `{JSON_TYPE}`.",
    503: "No database is configured.",
}


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {code: {"model": ErrorOut, "description": _REASONS[code]} for code in codes}


_EXISTS: dict[int | str, dict[str, Any]] = {
    409: {
        # Two shapes, so a generated client never assumes `decision` is there.
        "model": DecisionExists | ErrorOut,
        "description": "The run's decision is recorded already, these bytes or others (`decision`); the "
        "`decision_id` is another run's (`decision`: that run's); or the run's findings are not recorded "
        "yet (`detail` only).",
    }
}


def _out(row: RunDecision) -> DecisionOut:
    return DecisionOut(
        run_id=row.run_id, sha256=row.sha256, decision_id=row.decision_id,
        verdict=row.verdict, evaluated_at=row.evaluated_at,  # type: ignore[arg-type]
        engine_version=row.engine_version, created_at=row.created_at,
    )  # fmt: skip


def _exists(detail: str, row: RunDecision) -> JSONResponse:
    content = DecisionExists(detail=detail, decision=_out(row))
    return JSONResponse(content.model_dump(mode="json"), status_code=status.HTTP_409_CONFLICT)


def _recorded(session: Session, run_id: uuid.UUID, digest: str) -> JSONResponse:
    """The 409 for a run whose decision is recorded: the same bytes, or another decision."""
    row = session.get(RunDecision, run_id)
    if row is None:
        raise RuntimeError(f"run {run_id}: no decision after a conflict on it")
    if row.sha256 == digest:
        return _exists(f"decision {row.sha256} is recorded already", row)
    return _exists(f"this run's decision is recorded already ({row.sha256}): a run has one decision", row)


def _document(body: bytes) -> DecisionDocument:
    """The Decision v1 document of these bytes, or 422. The bytes must mean one thing to every reader:
    UTF-8, one JSON object, no repeated key, no NaN or Infinity."""
    try:
        json.loads(
            body.decode("utf-8"), object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant
        )
        return DecisionDocument.model_validate_json(body)
    except (UnicodeDecodeError, ValueError) as exc:  # json and pydantic errors are ValueErrors
        if isinstance(exc, ValidationError):
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"]) or "document"
            raise _invalid(f"not a Decision v1 document: {where}: {first['msg']}") from exc
        raise _invalid(f"not a Decision v1 document: {exc}") from exc


def _check_is_the_runs(session: Session, run: Run, document: DecisionDocument) -> None:
    """422 unless the decision was made on the run's findings, about the run's subject."""
    if document.inputs.findings_digest != f"sha256:{run.findings_sha256}":
        raise _invalid(
            f"made on other findings: inputs.findings_digest is {document.inputs.findings_digest}, the run "
            f"recorded sha256:{run.findings_sha256}"
        )
    subject = document.subject
    for field, said, recorded in (
        ("repo", subject.repo, run.repo),
        ("commit", subject.commit, run.commit),
        ("context", subject.context, run.context),
        ("ref", subject.ref, run.ref),
    ):
        if said != recorded and not (field == "ref" and said is None):
            raise _invalid(f"about another subject: {field} is {said!r}, the run's is {recorded!r}")
    named = {i for violation in document.violations for i in violation.finding_ids}
    named |= set(document.vex_applied or ())
    unknown = named - set(session.scalars(select(RunFinding.finding_id).where(RunFinding.run_id == run.id)))
    if unknown:
        raise _invalid(f"names {len(unknown)} finding id(s) the run did not record")


def _store(session: Session, run_id: uuid.UUID, body: bytes) -> DecisionOut | JSONResponse:
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    if run.findings_sha256 is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "no findings recorded for this run yet: the decision follows the upload"
        )
    digest = hashlib.sha256(body).hexdigest()
    if run.decision is not None:
        return _recorded(session, run_id, digest)
    document = _document(body)
    _check_is_the_runs(session, run, document)
    decision_id = uuid.UUID(document.decision_id)
    elsewhere = session.scalars(select(RunDecision).where(RunDecision.decision_id == decision_id)).first()
    if elsewhere is not None:
        return _exists(f"decision {decision_id} is recorded for another run", elsewhere)
    row = RunDecision(
        run_id=run_id,
        sha256=digest,
        decision_id=decision_id,
        verdict=document.verdict,
        evaluated_at=datetime.fromisoformat(document.evaluated_at.replace("Z", "+00:00")),
        engine_version=document.engine_version,
        document=body,
    )
    session.add(row)
    try:
        session.commit()
    except IntegrityError:  # a decision recorded meanwhile by a concurrent request, for this run or another
        session.rollback()
        if session.get(RunDecision, run_id) is not None:
            return _recorded(session, run_id, digest)
        elsewhere = session.scalars(select(RunDecision).where(RunDecision.decision_id == decision_id)).first()
        if elsewhere is None:
            raise
        return _exists(f"decision {decision_id} is recorded for another run", elsewhere)
    session.refresh(row)
    return _out(row)


@router.post(
    "/runs/{run_id}/decision",
    status_code=status.HTTP_201_CREATED,
    response_model=DecisionOut,
    dependencies=[Depends(require_writer)],
    tags=["decisions"],
    responses={**_errors(401, 404, 413, 415, 503), **_EXISTS},
    openapi_extra={
        "requestBody": {
            "required": True,
            "description": "The Decision v1 document (schemas/decision.v1.json) the gate made on the run's "
            "findings, as `sentinel evaluate` wrote it.",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        }
    },
)
async def record_decision(
    run_id: uuid.UUID, request: Request, session: SessionDep
) -> DecisionOut | JSONResponse:
    """Record the run's gate decision (one per run), kept byte for byte. The platform never decides."""
    media_type = request.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if media_type != JSON_TYPE:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"a decision is posted as {JSON_TYPE}")
    body = await _read_body(request, request.app.state.settings.max_upload_bytes)
    return await run_in_threadpool(_store, session, run_id, body)


@router.get(
    "/runs/{run_id}/decision",
    tags=["decisions"],
    response_class=Response,
    responses={
        200: {
            "description": "The decision byte for byte: its sha256 is the ETag.",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        },
        **_errors(404, 413, 503),
    },
)
def get_decision(run_id: uuid.UUID, session: SessionDep) -> Response:
    """The run's gate decision, exactly as it was posted."""
    if session.get(Run, run_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    row = session.scalars(select(RunDecision).where(RunDecision.run_id == run_id)).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no decision recorded for this run")
    data = row.document
    if hashlib.sha256(data).hexdigest() != row.sha256:  # the database refuses this (decisions_bytes_match)
        raise RuntimeError(f"run {run_id}: decision {row.sha256} does not match its bytes")
    return Response(data, media_type=JSON_TYPE, headers={"ETag": f'"{row.sha256}"'})
