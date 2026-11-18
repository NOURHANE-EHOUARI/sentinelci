"""Explanations of findings (task B5c, SPEC sections 8 and 13.3): ask for one, follow it, read it.

Advisory: an explanation never changes a verdict, and the gate never reads it. The model never runs in the
API: a request is queued (Celery over Redis, task `sentinel.explain`), and the worker
(`sentinel_worker.tasks`) claims it, asks the model through `sentinel_ai.explain`, and records the outcome
with `finish`, which keeps only a valid Explanation v1 document about the request's own finding.

- `POST /api/v1/findings/{id}/explain` (the ingestion token): explain the finding as a run recorded it
  (`run_id`, by default the latest run that recorded it). A secret's finding is never sent to a model (422).
  While a request for the same finding and run is open, it is answered (200) and no second job is queued. A
  request no worker finished within an hour is failed, and a new one replaces it. Without a queue
  (`SENTINEL_REDIS_URL`) nothing is recorded (503); a queue that refuses the job fails the request (503, with
  the request).
- `GET /api/v1/explain-requests/{id}`: a request: queued, running, explained (with its explanation's sha256),
  unavailable (the model gave no valid answer, or the provider failed), not_sent, or failed.
- `GET /api/v1/findings/{id}/explanation`: the finding's latest explanation, byte for byte, its sha256 as the
  ETag.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from sentinel_api.api import _SHA256, ErrorOut, SessionDep
from sentinel_api.auth import require_writer
from sentinel_api.models import ExplainRequest, Explanation, Run, RunFinding
from sentinelci.contracts.explanation import Explanation as ExplanationDocument
from sentinelci.contracts.finding import Finding

JSON_TYPE = "application/json"
TASK = "sentinel.explain"
# A job that runs longer than this is taken as lost (two model calls of at most 15 minutes each, ADR-0009).
STALE_AFTER = timedelta(hours=1)
OPEN = ("queued", "running")
MAX_REASON = 500

Status = Literal["queued", "running", "explained", "unavailable", "not_sent", "failed"]
Finished = Literal["explained", "unavailable", "not_sent", "failed"]
# Sends one job to the queue: (task name, arguments). Raises when the queue does not take it.
Enqueue = Callable[[str, list[str]], None]

router = APIRouter(prefix="/api/v1")

_REASONS = {
    401: "No valid ingestion token (`Authorization: Bearer <token>`).",
    404: "No such finding (in that run), request or explanation.",
    500: "The finding's latest explanation is not a valid Explanation v1 document about it: it did not come "
    "through the worker's checks, so it is not served (T33).",
    503: "No database or no job queue is configured, or the queue did not take the job.",
}


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {code: {"model": ErrorOut, "description": _REASONS[code]} for code in codes}


class ExplainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: uuid.UUID | None = None


class ExplainRequestOut(BaseModel):
    id: uuid.UUID
    finding_id: str
    run_id: uuid.UUID
    status: Status
    reason: str | None
    explanation_sha256: str | None
    created_at: datetime
    updated_at: datetime


class ExplainRequestFailed(BaseModel):
    """503: the queue did not take the job; the request is recorded as failed."""

    detail: str
    request: ExplainRequestOut


def celery_enqueue(redis_url: str) -> Enqueue:
    """Send jobs by name to the worker's Celery queue: JSON only, and no retry, so a broker that is down fails
    the request at once instead of holding it."""
    from celery import Celery  # type: ignore[import-untyped]

    app = Celery("sentinel-api", broker=redis_url, set_as_current=False)
    app.conf.update(task_serializer="json", accept_content=["json"], broker_connection_timeout=5)

    def enqueue(name: str, args: list[str]) -> None:
        app.send_task(name, args=args, retry=False)

    return enqueue


def _out(row: ExplainRequest) -> ExplainRequestOut:
    return ExplainRequestOut(
        id=row.id, finding_id=row.finding_id, run_id=row.run_id, status=row.status,  # type: ignore[arg-type]
        reason=row.reason, explanation_sha256=row.explanation_sha256, created_at=row.created_at,
        updated_at=row.updated_at,
    )  # fmt: skip


def _finding(session: Session, finding_id: str, run_id: uuid.UUID | None) -> RunFinding:
    query = select(RunFinding).where(RunFinding.finding_id == finding_id)
    if run_id is not None:
        query = query.where(RunFinding.run_id == run_id)
    else:
        query = query.join(Run, Run.id == RunFinding.run_id).order_by(
            Run.findings_uploaded_at.desc(), Run.id.desc()
        )
    row = session.scalars(query.limit(1)).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such finding in a recorded run")
    return row


def _open(
    session: Session, finding_id: str, run_id: uuid.UUID, *, lock: bool = False
) -> ExplainRequest | None:
    """The open request of a finding in a run. With `lock`, its row is held until the commit, and a worker
    that finished it meanwhile is waited for: the row is then no longer open, and None is returned."""
    query = select(ExplainRequest).where(
        ExplainRequest.finding_id == finding_id,
        ExplainRequest.run_id == run_id,
        ExplainRequest.status.in_(OPEN),
    )
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    return session.scalars(query).first()


def _set(session: Session, row: ExplainRequest, state: Status, reason: str | None) -> None:
    row.status, row.reason = state, reason[:MAX_REASON] if reason else reason
    row.updated_at = func.now()
    session.commit()
    session.refresh(row)


def _request(
    session: Session, enqueue: Enqueue | None, finding_id: str, run_id: uuid.UUID | None
) -> ExplainRequestOut | JSONResponse:
    if enqueue is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "no job queue is configured (SENTINEL_REDIS_URL): nothing recorded",
        )
    recorded = _finding(session, finding_id, run_id)
    if recorded.category == "SECRET":
        raise RequestValidationError(
            [{"type": "secret", "loc": ("path", "finding_id"), "input": None,
              "msg": "a secret's finding is never sent to a model: rotate the secret"}]
        )  # fmt: skip
    current = _open(session, finding_id, recorded.run_id, lock=True)  # never fail one a worker is finishing
    if current is not None:
        stale = session.scalar(select(func.now() - current.updated_at > STALE_AFTER))
        if not stale:
            body = _out(current).model_dump(mode="json")
            session.rollback()  # releases the row
            return JSONResponse(body, status_code=status.HTTP_200_OK)
        _set(session, current, "failed", "no worker finished it within an hour")
    row = ExplainRequest(finding_id=finding_id, run_id=recorded.run_id, status="queued")
    session.add(row)
    try:
        session.commit()
    except IntegrityError:  # a request for this finding and run opened meanwhile
        session.rollback()
        current = _open(session, finding_id, recorded.run_id)
        if current is None:
            raise
        return JSONResponse(_out(current).model_dump(mode="json"), status_code=status.HTTP_200_OK)
    session.refresh(row)
    try:
        enqueue(TASK, [str(row.id)])
    except Exception:
        _set(session, row, "failed", "the job queue did not take the job")
        content = ExplainRequestFailed(detail="the job queue did not take the job", request=_out(row))
        return JSONResponse(content.model_dump(mode="json"), status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    return _out(row)


_FINDING_ID = Annotated[str, Path(pattern=_SHA256, description="The finding's id (fingerprint).")]


@router.post(
    "/findings/{finding_id}/explain",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ExplainRequestOut,
    dependencies=[Depends(require_writer)],
    tags=["explanations"],
    responses={
        200: {"model": ExplainRequestOut, "description": "A request for this finding and run is open: it."},
        **_errors(401, 404),
        503: {
            "model": ExplainRequestFailed | ErrorOut,
            "description": "No database or no job queue is configured (`detail` only), or the queue did "
            "not take the job (`request`: the request, failed).",
        },
    },
)
def request_explanation(
    finding_id: _FINDING_ID, request: Request, session: SessionDep, body: ExplainIn | None = None
) -> ExplainRequestOut | JSONResponse:
    """Queue an explanation of the finding as a run recorded it. Advisory: it never changes a verdict."""
    return _request(session, request.app.state.enqueue, finding_id, body.run_id if body else None)


@router.get(
    "/explain-requests/{request_id}",
    response_model=ExplainRequestOut,
    tags=["explanations"],
    responses=_errors(404, 503),
)
def get_explain_request(request_id: uuid.UUID, session: SessionDep) -> ExplainRequestOut:
    """Where a request for an explanation stands."""
    row = session.get(ExplainRequest, request_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such request")
    return _out(row)


@router.get(
    "/findings/{finding_id}/explanation",
    tags=["explanations"],
    response_class=Response,
    responses={
        200: {
            "description": "The finding's latest explanation (Explanation v1) byte for byte: its sha256 is "
            "the ETag. Advisory: never read by the gate.",
            "content": {JSON_TYPE: {"schema": {"type": "object"}}},
        },
        **_errors(404, 500, 503),
    },
)
def get_explanation(finding_id: _FINDING_ID, session: SessionDep) -> Response:
    """The finding's latest explanation, exactly as the worker recorded it, once checked again."""
    # Checked again before it is served: `finish` checks it in the worker's own process, and the database
    # only binds it to its request's finding and run, so a compromised worker could record any JSON naming
    # the finding (T33). A latest explanation that is not a valid Explanation v1 about this finding is
    # refused, and nothing is served in its place, an older explanation included.
    row = session.scalars(
        select(Explanation)
        .where(Explanation.finding_id == finding_id)
        .order_by(Explanation.seq.desc())
        .limit(1)
    ).first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no explanation recorded for this finding")
    data = row.document
    if hashlib.sha256(data).hexdigest() != row.sha256:  # the database refuses this (explanations_bytes_match)
        raise RuntimeError(f"explanation {row.sha256} does not match its bytes")
    if _not_served(data, finding_id):
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"the latest explanation of this finding is not a valid Explanation v1 document about it "
            f"({row.sha256}): it is not served",
        )
    return Response(data, media_type=JSON_TYPE, headers={"ETag": f'"{row.sha256}"'})


def _not_served(data: bytes, finding_id: str) -> bool:
    """`finish`'s own check, again: a valid Explanation v1 document about this finding, or nothing."""
    try:
        return ExplanationDocument.model_validate_json(data).finding_id != finding_id
    except (ValidationError, ValueError):
        return True


# ---------------------------------------------------------------- the worker's side


@dataclass(frozen=True)
class Claimed:
    """A request the worker now runs: the finding as its run recorded it, and that run's findings."""

    request_id: uuid.UUID
    finding: Finding
    findings: Sequence[Finding]


def claim(session: Session, request_id: uuid.UUID) -> Claimed | None:
    """Take a queued request (queued → running), or None if it is not queued: a job delivered twice runs
    once."""
    taken = session.execute(
        update(ExplainRequest)
        .where(ExplainRequest.id == request_id, ExplainRequest.status == "queued")
        .values(status="running", updated_at=func.now())
        .returning(ExplainRequest.finding_id, ExplainRequest.run_id)
    ).first()
    session.commit()
    if taken is None:
        return None
    finding_id, run_id = taken
    documents = session.scalars(select(RunFinding).where(RunFinding.run_id == run_id)).all()
    findings = [Finding.model_validate(row.document) for row in documents]
    (finding,) = [f for f in findings if f.id == finding_id]
    return Claimed(request_id, finding, findings)


class NotRunning(RuntimeError):
    """The request is no longer running: a later ask failed it as stale while its worker ran."""


def finish(
    session: Session,
    request_id: uuid.UUID,
    outcome: Finished,
    *,
    reason: str | None = None,
    document: bytes | None = None,
) -> Status:
    """Record a running request's outcome. An explanation is kept only if it is a valid Explanation v1
    document about the request's own finding; otherwise the request fails, saying why, and nothing is kept."""
    # Locked until the outcome is committed: a stale ask in between either waits and sees it finished, or
    # failed it first, and then this one is NotRunning.
    row = session.get(ExplainRequest, request_id, with_for_update=True, populate_existing=True)
    if row is None or row.status != "running":
        raise NotRunning(f"request {request_id} is not running")
    if outcome != "explained":
        _set(session, row, outcome, reason)
        return outcome
    try:
        explanation = ExplanationDocument.model_validate_json(document or b"")
    except (ValidationError, ValueError) as exc:
        first = exc.errors()[0]["msg"] if isinstance(exc, ValidationError) else str(exc)
        _set(session, row, "failed", f"not a valid Explanation v1 document: {first}")
        return "failed"
    if explanation.finding_id != row.finding_id:
        _set(session, row, "failed", f"an explanation about another finding ({explanation.finding_id})")
        return "failed"
    if document is None:  # model_validate_json refused b"" above
        raise RuntimeError("no document")
    digest = hashlib.sha256(document).hexdigest()
    session.add(
        Explanation(
            sha256=digest, finding_id=row.finding_id, run_id=row.run_id, request_id=row.id, document=document
        )
    )
    session.flush()
    row.explanation_sha256 = digest
    _set(session, row, "explained", None)
    return "explained"


def as_bytes(document: dict[str, Any]) -> bytes:
    """An Explanation v1 document as the worker records it."""
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
