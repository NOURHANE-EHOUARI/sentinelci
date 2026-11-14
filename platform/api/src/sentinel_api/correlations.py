"""A run's correlations (Correlation v1, task A7, SPEC section 8): record them, then serve them byte for byte.

Advisory only: the gate never reads them, and nothing here changes a run, a finding or a decision.

- `POST /api/v1/runs/{run_id}/correlations`: one Correlation v1 document, as JSON. It is checked before it is
  kept: the contract (the correlator's own model, which also checks what the schema cannot: sorted ids, each
  `group_id` the sha256 of its members, no finding in two groups), `findings_sha256` equal to the run's (the
  groups were computed from exactly the findings the run recorded), and the groups holding each of the run's
  findings exactly once. The version is named by the sha256 of the bytes sent; the same bytes again are
  answered 409 with that version. A different document is a new version: the correlator may run again
  (another model, another threshold) and every version is kept.
- `GET /api/v1/runs/{run_id}/correlations`: the latest version, byte for byte (what to hash, or to compare
  with `findings_sha256`); `?sha256=` serves a given version. `GET .../correlations/versions` lists them.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from sentinel_ai.correlate.models import Correlation as CorrelationDocument
from sentinel_api.api import _SHA256, ErrorOut, SessionDep, _read_body
from sentinel_api.auth import require_writer
from sentinel_api.models import Correlation, Run, RunFinding

JSON_TYPE = "application/json"
MAX_REASON = 300

router = APIRouter(prefix="/api/v1")


class CorrelationOut(BaseModel):
    run_id: uuid.UUID
    sha256: str
    correlator_version: str
    group_count: int
    created_at: datetime


class CorrelationExists(BaseModel):
    """409: these exact bytes are this run's correlation already (`correlation`)."""

    detail: str
    correlation: CorrelationOut


class CorrelationVersions(BaseModel):
    items: list[CorrelationOut]  # newest first


_REASONS = {
    401: "No valid ingestion token (`Authorization: Bearer <token>`).",
    404: "No such run, or no correlation (version) recorded for it.",
    413: "The document is larger than the upload limit.",
    415: f"The correlation is not `{JSON_TYPE}`.",
    503: "No database is configured.",
}


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {code: {"model": ErrorOut, "description": _REASONS[code]} for code in codes}


_EXISTS: dict[int | str, dict[str, Any]] = {
    409: {
        # Two shapes, so a generated client never assumes `correlation` is there.
        "model": CorrelationExists | ErrorOut,
        "description": "These exact bytes are recorded already (`correlation`), or the run's findings are "
        "not recorded yet (`detail` only).",
    }
}


def _out(row: Correlation) -> CorrelationOut:
    return CorrelationOut(
        run_id=row.run_id, sha256=row.sha256, correlator_version=row.correlator_version,
        group_count=row.group_count, created_at=row.created_at,
    )  # fmt: skip


def _exists(row: Correlation) -> JSONResponse:
    content = CorrelationExists(detail=f"correlation {row.sha256} is recorded already", correlation=_out(row))
    return JSONResponse(content.model_dump(mode="json"), status_code=status.HTTP_409_CONFLICT)


def _invalid(message: str, kind: str = "correlation_invalid") -> RequestValidationError:
    """A 422 with the API's usual body (FastAPI's list of validation errors), of type `kind`."""
    return RequestValidationError(
        [{"type": kind, "loc": ("body",), "msg": message[:MAX_REASON], "input": None}]
    )


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("a JSON object repeats a key")
    return dict(pairs)


def _refuse_constant(name: str) -> None:
    raise ValueError(f"{name} is not JSON")


def _document(body: bytes) -> CorrelationDocument:
    """The Correlation v1 document of these bytes, or 422. The bytes must mean one thing to every reader:
    UTF-8, one JSON object, no repeated key, no NaN or Infinity."""
    try:
        json.loads(
            body.decode("utf-8"), object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant
        )
        return CorrelationDocument.model_validate_json(body)
    except (UnicodeDecodeError, ValueError) as exc:  # json and pydantic errors are ValueErrors
        if isinstance(exc, ValidationError):
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"]) or "document"
            raise _invalid(f"not a Correlation v1 document: {where}: {first['msg']}") from exc
        raise _invalid(f"not a Correlation v1 document: {exc}") from exc


def _store(session: Session, run_id: uuid.UUID, body: bytes) -> CorrelationOut | JSONResponse:
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    if run.findings_sha256 is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "no findings recorded for this run yet: a correlation follows the upload",
        )
    document = _document(body)
    if document.findings_sha256 != run.findings_sha256:
        raise _invalid(
            f"computed from other findings: findings_sha256 is {document.findings_sha256}, the run recorded "
            f"{run.findings_sha256}"
        )
    grouped = {finding_id for group in document.groups for finding_id in group.finding_ids}
    recorded = set(session.scalars(select(RunFinding.finding_id).where(RunFinding.run_id == run_id)))
    if grouped != recorded:
        missing, unknown = len(recorded - grouped), len(grouped - recorded)
        raise _invalid(
            f"the groups must hold each of the run's {len(recorded)} findings exactly once: {missing} "
            f"missing, {unknown} not the run's"
        )
    digest = hashlib.sha256(body).hexdigest()
    existing = session.get(Correlation, (run_id, digest))
    if existing is not None:
        return _exists(existing)
    row = Correlation(
        run_id=run_id,
        sha256=digest,
        correlator_version=document.correlator.version,
        group_count=len(document.groups),
        document=body,
    )
    session.add(row)
    try:
        session.commit()
    except IntegrityError:  # the same bytes, recorded meanwhile by a concurrent request
        session.rollback()
        existing = session.get(Correlation, (run_id, digest))
        if existing is None:
            raise
        return _exists(existing)
    session.refresh(row)
    return _out(row)


@router.post(
    "/runs/{run_id}/correlations",
    status_code=status.HTTP_201_CREATED,
    response_model=CorrelationOut,
    dependencies=[Depends(require_writer)],
    tags=["correlations"],
    responses={**_errors(401, 404, 413, 415, 503), **_EXISTS},
    openapi_extra={
        "requestBody": {
            "required": True,
            "description": "One Correlation v1 document (schemas/correlation.v1.json) of the run's findings.",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        }
    },
)
async def record_correlation(
    run_id: uuid.UUID, request: Request, session: SessionDep
) -> CorrelationOut | JSONResponse:
    """Record a correlation of the run's findings (advisory: the gate never reads it), kept byte for byte."""
    media_type = request.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if media_type != JSON_TYPE:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"a correlation is posted as {JSON_TYPE}")
    body = await _read_body(request, request.app.state.settings.max_upload_bytes)
    return await run_in_threadpool(_store, session, run_id, body)


@router.get(
    "/runs/{run_id}/correlations",
    tags=["correlations"],
    response_class=Response,
    responses={
        200: {
            "description": "The version byte for byte: its sha256 is the version's name, the ETag.",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        },
        **_errors(404, 413, 503),
    },
)
def get_correlation(
    run_id: uuid.UUID,
    session: SessionDep,
    sha256: Annotated[
        str | None, Query(pattern=_SHA256, description="A version; the latest without it.")
    ] = None,
) -> Response:
    """The run's latest correlation, or the version `sha256`, exactly as it was posted."""
    if session.get(Run, run_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    query = select(Correlation).where(Correlation.run_id == run_id)
    query = query.where(Correlation.sha256 == sha256) if sha256 else query.order_by(Correlation.seq.desc())
    row = session.scalars(query.limit(1)).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no correlation recorded for this run (this version)")
    data = row.document
    if hashlib.sha256(data).hexdigest() != row.sha256:  # the database refuses this (correlations_bytes_match)
        raise RuntimeError(f"run {run_id}: correlation {row.sha256} does not match its bytes")
    return Response(data, media_type=JSON_TYPE, headers={"ETag": f'"{row.sha256}"'})


@router.get("/runs/{run_id}/correlations/versions", tags=["correlations"], responses=_errors(404, 413, 503))
def list_correlations(run_id: uuid.UUID, session: SessionDep) -> CorrelationVersions:
    """Every version recorded for the run, newest first (without their documents)."""
    if session.get(Run, run_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    rows = session.scalars(
        select(Correlation).where(Correlation.run_id == run_id).order_by(Correlation.seq.desc())
    )
    return CorrelationVersions(items=[_out(row) for row in rows])
