"""Releases and their evidence (Release evidence v1, tasks A4 and A8, SPEC sections 7, 10 and 13.3): record
them, list them, serve them byte for byte.

What the platform holds is a record of what happened on the release laptop: the release decision, and what
`sentinel verify` found about the image there. It verifies nothing itself (it holds no key and reaches no
registry), and nothing here can change a decision or admit an image: Kyverno verifies again at admission.

- `POST /api/v1/releases`: one Release evidence v1 document, as JSON. It is checked before it is kept: the
  contract (the CLI's own models, `sentinelci.contracts.release`) and the rules JSON Schema cannot express (a
  release decision about an image; each report about that image and repository, one per mode, consistent with
  its checks; no trusted report for a BLOCK). A decision is recorded once: the same bytes again are answered
  409 with the release, and other bytes for a recorded decision are refused (409, its evidence never changes).
- `GET /api/v1/releases`: the releases, newest first, with what the Releases page lists.
- `GET /api/v1/releases/{image_digest}/evidence`: the latest release of an image, byte for byte (its sha256 is
  the ETag); `?decision_id=` names one.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
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
from sentinel_api.models import Release
from sentinelci.contracts.release import ReleaseEvidence

JSON_TYPE = "application/json"
DIGEST = r"^sha256:[a-f0-9]{64}$"
MAX_REASON = 300
Verdict = Literal["PASS", "WARN", "BLOCK"]

router = APIRouter(prefix="/api/v1")


class ReleaseOut(BaseModel):
    decision_id: uuid.UUID
    repo: str
    commit: str
    ref: str | None
    image_digest: str
    verdict: Verdict
    trusted: bool | None  # every trust report trusts the image, one does not, or none was sent (a BLOCK)
    evaluated_at: datetime
    created_at: datetime
    sha256: str


class ReleaseExists(BaseModel):
    """409: this decision is recorded already (`release`); with the same bytes when `release.sha256` is
    theirs."""

    detail: str
    release: ReleaseOut


class ReleasePage(BaseModel):
    items: list[ReleaseOut]  # newest first
    total: int
    limit: int
    offset: int


_REASONS = {
    401: "No valid ingestion token (`Authorization: Bearer <token>`).",
    404: "No release recorded for this image (or this decision).",
    413: "The document is larger than the upload limit.",
    415: f"The evidence is not `{JSON_TYPE}`.",
    503: "No database is configured.",
}


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {code: {"model": ErrorOut, "description": _REASONS[code]} for code in codes}


_INVALID: dict[int | str, dict[str, Any]] = {
    422: {
        "description": "Not a Release evidence v1 document, or one that contradicts itself: a BLOCK with "
        "a trust report, a report about another image, repository or decision (the reason is in `msg`).",
        "content": {JSON_TYPE: {"schema": {"$ref": "#/components/schemas/HTTPValidationError"}}},
    }
}

_EXISTS: dict[int | str, dict[str, Any]] = {
    409: {
        "model": ReleaseExists,
        "description": "The decision is recorded already (`release`): with these bytes, or with other "
        "evidence, which never changes.",
    }
}


def _out(row: Release) -> ReleaseOut:
    return ReleaseOut(
        decision_id=row.decision_id, repo=row.repo, commit=row.commit, ref=row.ref,
        image_digest=row.image_digest, verdict=row.verdict,  # type: ignore[arg-type]
        trusted=row.trusted, evaluated_at=row.evaluated_at, created_at=row.created_at, sha256=row.sha256,
    )  # fmt: skip


def _exists(row: Release, digest: str) -> JSONResponse:
    detail = f"release {row.decision_id} is recorded already"
    if row.sha256 != digest:
        detail += f" with other evidence ({row.sha256}): it never changes"
    content = ReleaseExists(detail=detail, release=_out(row))
    return JSONResponse(content.model_dump(mode="json"), status_code=status.HTTP_409_CONFLICT)


def _invalid(message: str) -> RequestValidationError:
    """A 422 with the API's usual body (FastAPI's list of validation errors)."""
    return RequestValidationError(
        [{"type": "release_invalid", "loc": ("body",), "msg": message[:MAX_REASON], "input": None}]
    )


def _evidence(body: bytes) -> ReleaseEvidence:
    """The Release evidence v1 document of these bytes, consistent with itself, or 422. The bytes must mean
    one thing to every reader: UTF-8, one JSON object, no repeated key, no NaN or Infinity."""
    try:
        json.loads(
            body.decode("utf-8"), object_pairs_hook=_no_duplicate_keys, parse_constant=_refuse_constant
        )
        evidence = ReleaseEvidence.model_validate_json(body)
    except (UnicodeDecodeError, ValueError) as exc:  # json and pydantic errors are ValueErrors
        if isinstance(exc, ValidationError):
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"]) or "document"
            raise _invalid(f"not a Release evidence v1 document: {where}: {first['msg']}") from exc
        raise _invalid(f"not a Release evidence v1 document: {exc}") from exc
    if (problem := evidence.problem()) is not None:
        raise _invalid(f"inconsistent release evidence: {problem}")
    return evidence


def _store(session: Session, body: bytes) -> ReleaseOut | JSONResponse:
    evidence = _evidence(body)
    decision = evidence.decision
    digest = hashlib.sha256(body).hexdigest()
    existing = session.get(Release, decision.decision_id)
    if existing is not None:
        return _exists(existing, digest)
    row = Release(
        decision_id=decision.decision_id,
        repo=decision.subject.repo,
        commit=decision.subject.commit,
        ref=decision.subject.ref,
        image_digest=evidence.image_digest,
        verdict=decision.verdict,
        trusted=evidence.trusted,
        evaluated_at=decision.evaluated_at,
        sha256=digest,
        document=body,
    )
    session.add(row)
    try:
        session.commit()
    except IntegrityError:  # the same decision, recorded meanwhile by a concurrent request
        session.rollback()
        existing = session.get(Release, decision.decision_id)
        if existing is None:
            raise
        return _exists(existing, digest)
    session.refresh(row)
    return _out(row)


@router.post(
    "/releases",
    status_code=status.HTTP_201_CREATED,
    response_model=ReleaseOut,
    dependencies=[Depends(require_writer)],
    tags=["releases"],
    responses={**_errors(401, 413, 415, 503), **_EXISTS, **_INVALID},
    openapi_extra={
        "requestBody": {
            "required": True,
            "description": "One Release evidence v1 document (schemas/release-evidence.v1.json).",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        }
    },
)
async def record_release(request: Request, session: SessionDep) -> ReleaseOut | JSONResponse:
    """Record a release decision and the trust reports of its image, kept byte for byte, once."""
    media_type = request.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if media_type != JSON_TYPE:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"release evidence is posted as {JSON_TYPE}"
        )
    body = await _read_body(request, request.app.state.settings.max_upload_bytes)
    return await run_in_threadpool(_store, session, body)


@router.get("/releases", tags=["releases"], responses=_errors(413, 503))
def list_releases(
    session: SessionDep,
    repo: Annotated[str | None, Query(pattern=_REPO, max_length=200)] = None,
    verdict: Verdict | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
) -> ReleasePage:
    """The releases, newest first (as recorded), without their documents."""
    query = select(Release)
    if repo is not None:
        query = query.where(Release.repo == repo)
    if verdict is not None:
        query = query.where(Release.verdict == verdict)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(query.order_by(Release.seq.desc()).limit(limit).offset(offset))
    return ReleasePage(items=[_out(row) for row in rows], total=total, limit=limit, offset=offset)


@router.get(
    "/releases/{image_digest}/evidence",
    tags=["releases"],
    response_class=Response,
    responses={
        200: {
            "description": "The Release evidence v1 document byte for byte: its sha256 is the ETag.",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        },
        **_errors(404, 413, 503),
    },
)
def get_release_evidence(
    image_digest: Annotated[str, Path(pattern=DIGEST)],
    session: SessionDep,
    decision_id: Annotated[
        uuid.UUID | None,
        Query(description="One release of the image; without it, the one recorded last."),
    ] = None,
) -> Response:
    """The image's release recorded last (or the release `decision_id`), exactly as it was posted. "Last"
    is the order of recording, not of the decisions: a late upload of an older decision becomes the one
    served without `decision_id`."""
    query = select(Release).where(Release.image_digest == image_digest)
    query = (
        query.where(Release.decision_id == decision_id) if decision_id else query.order_by(Release.seq.desc())
    )
    row = session.scalars(query.limit(1)).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no release recorded for this image (this decision)")
    data = row.document
    if hashlib.sha256(data).hexdigest() != row.sha256:  # the database refuses this (releases_bytes_match)
        raise RuntimeError(f"release {row.decision_id}: the kept evidence does not match its sha256")
    return Response(data, media_type=JSON_TYPE, headers={"ETag": f'"{row.sha256}"'})
