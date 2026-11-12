"""Remediation attempts (Remediation attempt v1, tasks A6 and A8, SPEC sections 9, 10 and 13.3): record them,
list them, serve them byte for byte.

A record of what the remediation loop did: the proposal it made and what its verification gate found. Nothing
here merges, approves or re-verifies anything: a VERIFIED attempt is a pull request a person still reviews.

- `POST /api/v1/remediations`: one Remediation attempt v1 document, as JSON. It is checked before it is
  kept: the contract (the CLI's models, `sentinelci.contracts.remediation`, which hold the verification gate:
  VERIFIED only when every condition holds) and the rules JSON Schema cannot express (the result is the
  proposal's, and not verified before it was made). An attempt is recorded once: the same bytes again are
  answered 409 with the attempt, and other bytes for a recorded proposal are refused (409, an attempt never
  changes).
- `GET /api/v1/remediations`: the attempts, newest first, with what the Remediation page lists.
- `GET /api/v1/remediations/{proposal_id}`: one attempt, byte for byte (its sha256 is the ETag).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from sentinel_api.api import _REPO, MAX_OFFSET, ErrorOut, SessionDep, _read_body
from sentinel_api.auth import require_writer
from sentinel_api.correlations import _no_duplicate_keys, _refuse_constant
from sentinel_api.models import Remediation
from sentinelci.contracts.remediation import Outcome, RemediationAttempt, Strategy

JSON_TYPE = "application/json"
MAX_REASON = 300

router = APIRouter(prefix="/api/v1")


class RemediationOut(BaseModel):
    proposal_id: uuid.UUID
    repo: str
    strategy: Strategy
    attempt: int
    finding_count: int
    outcome: Outcome
    verdict: Literal["PASS", "WARN", "BLOCK"]
    build_ok: bool
    tests_ok: bool
    target_resolved: bool
    new_finding_count: int
    pull_request: int | None
    proposed_at: datetime
    verified_at: datetime
    created_at: datetime
    sha256: str


class RemediationExists(BaseModel):
    """409: this proposal's attempt is recorded already (`remediation`); with the same bytes when
    `remediation.sha256` is theirs."""

    detail: str
    remediation: RemediationOut


class RemediationPage(BaseModel):
    items: list[RemediationOut]  # newest first
    total: int
    limit: int
    offset: int


_REASONS = {
    401: "No valid ingestion token (`Authorization: Bearer <token>`).",
    404: "No attempt recorded for this proposal.",
    413: "The document is larger than the upload limit.",
    415: f"The attempt is not `{JSON_TYPE}`.",
    503: "No database is configured.",
}


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {code: {"model": ErrorOut, "description": _REASONS[code]} for code in codes}


_EXISTS: dict[int | str, dict[str, Any]] = {
    409: {
        "model": RemediationExists,
        "description": "The proposal's attempt is recorded already (`remediation`): with these bytes, or "
        "with another document, which never changes.",
    }
}


def _out(row: Remediation) -> RemediationOut:
    return RemediationOut(
        proposal_id=row.proposal_id, repo=row.repo, strategy=row.strategy,  # type: ignore[arg-type]
        attempt=row.attempt, finding_count=row.finding_count, outcome=row.outcome,  # type: ignore[arg-type]
        verdict=row.verdict, build_ok=row.build_ok, tests_ok=row.tests_ok,  # type: ignore[arg-type]
        target_resolved=row.target_resolved, new_finding_count=row.new_finding_count,
        pull_request=row.pull_request, proposed_at=row.proposed_at, verified_at=row.verified_at,
        created_at=row.created_at, sha256=row.sha256,
    )  # fmt: skip


def _exists(row: Remediation, digest: str) -> JSONResponse:
    detail = f"remediation attempt {row.proposal_id} is recorded already"
    if row.sha256 != digest:
        detail += f" with another document ({row.sha256}): it never changes"
    content = RemediationExists(detail=detail, remediation=_out(row))
    return JSONResponse(content.model_dump(mode="json"), status_code=status.HTTP_409_CONFLICT)


def _invalid(message: str) -> RequestValidationError:
    """A 422 with the API's usual body (FastAPI's list of validation errors)."""
    return RequestValidationError(
        [{"type": "remediation_invalid", "loc": ("body",), "msg": message[:MAX_REASON], "input": None}]
    )


def _attempt(body: bytes) -> RemediationAttempt:
    """The Remediation attempt v1 document of these bytes, consistent with itself, or 422. The bytes must mean
    one thing to every reader: UTF-8, one JSON object, no repeated key, no NaN or Infinity."""
    try:
        json.loads(
            body.decode("utf-8"), object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant
        )
        attempt = RemediationAttempt.model_validate_json(body)
    except (UnicodeDecodeError, ValueError) as exc:  # json and pydantic errors are ValueErrors
        if isinstance(exc, ValidationError):
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"]) or "document"
            raise _invalid(f"not a Remediation attempt v1 document: {where}: {first['msg']}") from exc
        raise _invalid(f"not a Remediation attempt v1 document: {exc}") from exc
    if (problem := attempt.problem()) is not None:
        raise _invalid(f"inconsistent remediation attempt: {problem}")
    return attempt


def _store(session: Session, body: bytes) -> RemediationOut | JSONResponse:
    attempt = _attempt(body)
    proposal, result = attempt.proposal, attempt.result
    digest = hashlib.sha256(body).hexdigest()
    proposal_id = uuid.UUID(proposal.proposal_id)
    existing = session.get(Remediation, proposal_id)
    if existing is not None:
        return _exists(existing, digest)
    row = Remediation(
        proposal_id=proposal_id, repo=attempt.repo, strategy=proposal.strategy, attempt=proposal.attempt,
        finding_count=len(proposal.finding_ids), outcome=result.outcome, verdict=result.verdict,
        build_ok=result.build_ok, tests_ok=result.tests_ok, target_resolved=result.target_resolved,
        new_finding_count=len(result.new_findings), pull_request=result.pull_request,
        proposed_at=proposal.created_at, verified_at=result.verified_at, sha256=digest, document=body,
    )  # fmt: skip
    session.add(row)
    try:
        session.commit()
    except IntegrityError:  # the same proposal, recorded meanwhile by a concurrent request
        session.rollback()
        existing = session.get(Remediation, proposal_id)
        if existing is None:
            raise
        return _exists(existing, digest)
    session.refresh(row)
    return _out(row)


_INVALID: dict[int | str, dict[str, Any]] = {
    422: {
        "description": "Not a Remediation attempt v1 document (values of another JSON type included), or one "
        "that contradicts itself: a VERIFIED the gate refuses, a result about another proposal or attempt, "
        "verified before it was proposed (the reason is in `msg`).",
        "content": {JSON_TYPE: {"schema": {"$ref": "#/components/schemas/HTTPValidationError"}}},
    }
}


@router.post(
    "/remediations",
    status_code=status.HTTP_201_CREATED,
    response_model=RemediationOut,
    dependencies=[Depends(require_writer)],
    tags=["remediations"],
    responses={**_errors(401, 413, 415, 503), **_EXISTS, **_INVALID},
    openapi_extra={
        "requestBody": {
            "required": True,
            "description": "One Remediation attempt v1 document (schemas/remediation-attempt.v1.json).",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        }
    },
)
async def record_remediation(request: Request, session: SessionDep) -> RemediationOut | JSONResponse:
    """Record one attempt of the remediation loop (its proposal and result), byte for byte, once."""
    media_type = request.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if media_type != JSON_TYPE:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"an attempt is posted as {JSON_TYPE}")
    body = await _read_body(request, request.app.state.settings.max_upload_bytes)
    return await run_in_threadpool(_store, session, body)


@router.get("/remediations", tags=["remediations"], responses=_errors(413, 503))
def list_remediations(
    session: SessionDep,
    repo: Annotated[str | None, Query(pattern=_REPO, max_length=200)] = None,
    strategy: Strategy | None = None,
    outcome: Outcome | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
) -> RemediationPage:
    """The attempts, newest first (as recorded), without their documents."""
    query = select(Remediation)
    if repo is not None:
        query = query.where(Remediation.repo == repo)
    if strategy is not None:
        query = query.where(Remediation.strategy == strategy)
    if outcome is not None:
        query = query.where(Remediation.outcome == outcome)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(Remediation.seq.desc()).limit(limit).offset(offset))
    return RemediationPage(items=[_out(row) for row in rows], total=total, limit=limit, offset=offset)


@router.get(
    "/remediations/{proposal_id}",
    tags=["remediations"],
    response_class=Response,
    responses={
        200: {
            "description": "The Remediation attempt v1 document byte for byte: its sha256 is the ETag.",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        },
        **_errors(404, 413, 503),
    },
)
def get_remediation(proposal_id: uuid.UUID, session: SessionDep) -> Response:
    """One attempt, exactly as it was posted."""
    row = session.get(Remediation, proposal_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no attempt recorded for this proposal")
    data = row.document
    if hashlib.sha256(data).hexdigest() != row.sha256:  # the database refuses this (remediations_bytes_match)
        raise RuntimeError(f"remediation {row.proposal_id}: the kept document does not match its sha256")
    return Response(data, media_type=JSON_TYPE, headers={"ETag": f'"{row.sha256}"'})
