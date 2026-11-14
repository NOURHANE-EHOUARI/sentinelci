"""Platform API v1, first cut (SPEC section 13.3): record runs and their findings, then query them."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Annotated, Any

import psycopg.errors
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from sentinel_api.auth import require_writer
from sentinel_api.models import Run, RunFinding
from sentinelci.contracts.decision import Verdict
from sentinelci.contracts.finding import Category, RunContext, Severity
from sentinelci.policy.decision import load_findings
from sentinelci.policy.errors import EvaluationError

router = APIRouter(prefix="/api/v1")

# The same shapes as Finding v1 `run` (schemas/finding.v1.json): one line, no surrounding space.
_REPO = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
_COMMIT = r"^[a-f0-9]{40}$"
_SHA256 = r"^[a-f0-9]{64}$"
_LINE = r"^[^\r\n\u2028\u2029]*$"
NDJSON_TYPE = "application/x-ndjson"
MAX_OFFSET = 1_000_000

# U+0000 (B1, the #86 review). PostgreSQL stores it neither in a text column nor in jsonb, so a string
# that holds it is refused here with a 422, rather than reaching the database and failing as a 500.
# In a JSON document it is the escape `\u0000` after an even number of backslashes (after an odd
# number, the backslash itself is escaped and the text only spells it), or a raw NUL byte, which JSON
# never allows in a string. Linear: a match cannot start inside a run of backslashes.
_NUL_IN_JSON = re.compile(rb"(?<!\\)(?:\\\\)*\\u0000|\x00")
NUL_REFUSED = "U+0000 cannot be stored (PostgreSQL refuses it in text and jsonb)"


def _no_nul(value: str | None) -> str | None:
    if value is not None and "\x00" in value:
        raise ValueError(NUL_REFUSED)
    return value


NoNul = AfterValidator(_no_nul)  # for a free-text field or query parameter


class ErrorOut(BaseModel):
    """Every error except 422, which keeps FastAPI's list of validation errors (`HTTPValidationError`)."""

    detail: str


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    """The documented error responses of a route (schemas/openapi.yaml must list every status it returns)."""
    reasons = {
        401: "No valid ingestion token (`Authorization: Bearer <token>`).",
        404: "No such run or finding, or no findings recorded for the run (yet).",
        409: "This run's findings are already recorded; compare `findings_sha256` from `GET /runs/{run_id}`.",
        413: "The request body is larger than the limit (64 KiB, or the upload limit for findings).",
        415: f"The findings upload is not `{NDJSON_TYPE}`.",
        503: "No database is configured.",
    }
    return {code: {"model": ErrorOut, "description": reasons[code]} for code in codes}


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str = Field(pattern=_REPO, max_length=200)
    commit: str = Field(pattern=_COMMIT)
    context: RunContext
    ref: Annotated[str | None, NoNul] = Field(default=None, pattern=_LINE, min_length=1, max_length=255)
    run_id: Annotated[str | None, NoNul] = Field(default=None, pattern=_LINE, min_length=1, max_length=255)


class RunOut(BaseModel):
    id: uuid.UUID
    repo: str
    commit: str
    context: RunContext
    ref: str | None
    run_id: str | None
    created_at: datetime
    finding_count: int
    findings_sha256: str | None
    findings_uploaded_at: datetime | None
    verdict: Verdict | None = None  # the gate's, once its decision is recorded (API 1.6.0)


class RunExists(BaseModel):
    """409 on `POST /runs`: this CI run is already recorded. `run` is the existing run, so a re-run can resume
    it (upload its findings if `findings_sha256` is null) instead of recording the findings a second time."""

    detail: str
    run: RunOut


class UploadResult(BaseModel):
    run_id: uuid.UUID
    finding_count: int
    findings_sha256: str


class FindingItem(BaseModel):
    run_id: uuid.UUID
    finding: dict[str, Any]


class RunPage(BaseModel):
    items: list[RunOut]  # newest first
    total: int
    limit: int
    offset: int


class FindingPage(BaseModel):
    items: list[FindingItem]
    total: int
    limit: int
    offset: int


class Occurrence(BaseModel):
    run_id: uuid.UUID
    repo: str
    commit: str
    context: RunContext
    created_at: datetime


class FindingDetail(BaseModel):
    finding: dict[str, Any]
    occurrence_count: int
    occurrences: list[Occurrence]


def get_session(request: Request) -> Iterator[Session]:
    factory: sessionmaker[Session] | None = request.app.state.sessions
    if factory is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "no database is configured")
    with factory() as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def _run_out(run: Run) -> RunOut:
    return RunOut(
        id=run.id, repo=run.repo, commit=run.commit, context=run.context,  # type: ignore[arg-type]
        ref=run.ref, run_id=run.ci_run_id, created_at=run.created_at, finding_count=run.finding_count,
        findings_sha256=run.findings_sha256, findings_uploaded_at=run.findings_uploaded_at,
        verdict=run.decision.verdict if run.decision is not None else None,  # type: ignore[arg-type]
    )  # fmt: skip


_RUN_EXISTS: dict[int | str, dict[str, Any]] = {
    409: {
        "model": RunExists,
        "description": "This CI run (`repo`, `commit`, `context`, `run_id`) is recorded already: see `run`.",
    }
}


def _existing_run(session: Session, body: RunCreate) -> Run | None:
    """The run already recorded for this CI run. A run without `run_id` names no CI run: it matches none."""
    if body.run_id is None:
        return None
    return session.scalars(
        select(Run).where(
            Run.repo == body.repo, Run.commit == body.commit, Run.context == body.context,
            Run.ci_run_id == body.run_id,
        )
    ).one_or_none()  # fmt: skip


def _run_exists(run: Run) -> JSONResponse:
    content = RunExists(detail=f"CI run already recorded as run {run.id}", run=_run_out(run))
    return JSONResponse(content.model_dump(mode="json"), status_code=status.HTTP_409_CONFLICT)


@router.post(
    "/runs",
    status_code=status.HTTP_201_CREATED,
    response_model=RunOut,
    dependencies=[Depends(require_writer)],
    tags=["runs"],
    responses={**_errors(401, 413, 503), **_RUN_EXISTS},
)
def create_run(body: RunCreate, session: SessionDep) -> RunOut | JSONResponse:
    """Record a pipeline run. Its findings are uploaded next, once.

    A CI run is recorded once: the same `repo`, `commit`, `context` and `run_id` again (a re-run of the upload
    step) is answered 409 with the existing run, which the client resumes instead of recording the findings a
    second time. A run without `run_id` (a local run) is always a new run.
    """
    existing = _existing_run(session, body)
    if existing is not None:
        return _run_exists(existing)
    run = Run(repo=body.repo, commit=body.commit, context=body.context, ref=body.ref, ci_run_id=body.run_id)
    session.add(run)
    try:
        session.commit()
    except IntegrityError as exc:  # recorded meanwhile by a concurrent request: the unique index decided
        session.rollback()
        diag = getattr(exc.orig, "diag", None)
        existing = _existing_run(session, body)
        if getattr(diag, "constraint_name", None) != "runs_ci_run" or existing is None:
            raise
        return _run_exists(existing)
    session.refresh(run)
    return _run_out(run)


@router.get("/runs", tags=["runs"], responses=_errors(413, 503))
def list_runs(
    session: SessionDep,
    repo: Annotated[str | None, Query(pattern=_REPO, max_length=200)] = None,
    context: RunContext | None = None,
    ref: Annotated[str | None, Query(pattern=_LINE, min_length=1, max_length=255), NoNul] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
) -> RunPage:
    """Recorded runs, newest first (the run id breaks ties). For a fixed set of runs, walking the pages never
    repeats or skips one; while runs are being recorded, a new run at the top shifts later pages by one, and a
    run's `created_at` is the start of its transaction, so a run committed later can sort as older.

    `ref` is matched exactly (`refs/heads/main`), like `repo`. A run whose findings are not uploaded yet is
    listed too: its `findings_sha256` is null.
    """
    query = select(Run)
    if repo is not None:
        query = query.where(Run.repo == repo)
    if context is not None:
        query = query.where(Run.context == context)
    if ref is not None:
        query = query.where(Run.ref == ref)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    runs = session.scalars(query.order_by(Run.created_at.desc(), Run.id).limit(limit).offset(offset))
    return RunPage(items=[_run_out(run) for run in runs], total=total, limit=limit, offset=offset)


@router.get("/runs/{run_id}", tags=["runs"], responses=_errors(404, 413, 503))
def get_run(run_id: uuid.UUID, session: SessionDep) -> RunOut:
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    return _run_out(run)


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("Content-Length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"the upload is larger than {limit} bytes")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, f"the upload is larger than {limit} bytes")
        chunks.append(chunk)
    body = b"".join(chunks)
    if _NUL_IN_JSON.search(body):
        raise RequestValidationError(
            [{"type": "nul_character", "loc": ("body",), "msg": NUL_REFUSED, "input": None}]
        )
    return body


def _invalid(message: str, lineno: int | None = None) -> RequestValidationError:
    """A 422 with the same body as every other one in the API (FastAPI's list of validation errors)."""
    loc: tuple[str | int, ...] = ("body",) if lineno is None else ("body", lineno)
    return RequestValidationError([{"type": "finding_invalid", "loc": loc, "msg": message, "input": None}])


def _parse(body: bytes, run: Run) -> list[dict[str, Any]]:
    """Finding v1 documents of exactly this run, or 422 with the first problem (nothing is stored)."""
    try:
        findings = load_findings(body)
    except EvaluationError as exc:
        raise _invalid(str(exc)) from exc
    # load_findings skips blank lines; recover each finding's line number the same way.
    lines = [n for n, line in enumerate(body.decode("utf-8").split("\n"), start=1) if line.strip()]
    expected = {"repo": run.repo, "commit": run.commit, "context": run.context}
    optional = {"ref": run.ref, "run_id": run.ci_run_id}
    seen: dict[str, int] = {}
    for lineno, finding in zip(lines, findings, strict=True):
        # JSON can spell a lone UTF-16 surrogate (`"\ud800"`) and json.loads reads it, but it is not text:
        # it cannot be encoded as UTF-8, and PostgreSQL's jsonb refuses it (a 500 before, #126 review).
        try:
            json.dumps(finding, ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError:
            raise _invalid(
                f"findings line {lineno}: a string holds a lone UTF-16 surrogate, which cannot be stored",
                lineno,
            ) from None
        if (first := seen.setdefault(finding["id"], lineno)) != lineno:
            raise _invalid(
                f"findings line {lineno}: finding {finding['id']} appears twice (first on line {first})",
                lineno,
            )
        reported = finding["run"]
        mismatch = any(reported.get(k) != v for k, v in expected.items()) or any(
            k in reported and reported[k] != v for k, v in optional.items()
        )
        if mismatch:
            raise _invalid(f"findings line {lineno}: the finding belongs to another run", lineno)
    return findings


def _store(session: Session, run_id: uuid.UUID, body: bytes) -> UploadResult:
    # The row lock makes a second upload wait, then see the first one's result (409 before any parsing).
    already_recorded = HTTPException(status.HTTP_409_CONFLICT, "this run's findings are already recorded")
    run = session.get(Run, run_id, with_for_update=True)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    if run.findings_sha256 is not None:
        raise already_recorded
    findings = _parse(body, run)
    try:
        session.add_all(
            RunFinding(
                run_id=run.id,
                finding_id=f["id"],
                category=f["category"],
                severity=f["severity"],
                tool=f["tool"]["name"],
                rule_id=f["rule_id"],
                document=f,
            )
            for f in findings
        )
        session.flush()
        # Recorded once, whatever the lock does: only the update that finds the run unrecorded may commit. The
        # database refuses any later change to a recorded run (migration 0002).
        digest = hashlib.sha256(body).hexdigest()
        recorded = session.execute(
            update(Run)
            .where(Run.id == run_id, Run.findings_sha256.is_(None))
            .values(
                findings_sha256=digest,
                findings_uploaded_at=datetime.now(UTC),
                finding_count=len(findings),
                findings_ndjson=body,
            )
            .execution_options(synchronize_session=False)
        )
        if recorded.rowcount != 1:  # type: ignore[attr-defined]
            session.rollback()
            raise already_recorded
    except DBAPIError as exc:
        # Without the lock (or if it is ever bypassed), the trigger of migration 0002 refuses findings for a
        # run another upload has just recorded: the same answer as the check above.
        session.rollback()
        if isinstance(exc.orig, psycopg.errors.RaiseException) and "is recorded" in str(exc.orig):
            raise already_recorded from exc
        raise
    session.commit()
    return UploadResult(run_id=run_id, finding_count=len(findings), findings_sha256=digest)


@router.post(
    "/runs/{run_id}/findings",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_writer)],
    tags=["runs"],
    responses=_errors(401, 404, 409, 413, 415, 503),
    openapi_extra={
        "requestBody": {"required": True, "content": {NDJSON_TYPE: {"schema": {"type": "string"}}}}
    },
)
async def upload_findings(run_id: uuid.UUID, request: Request, session: SessionDep) -> UploadResult:
    """Record the run's findings: Finding v1 NDJSON, all of them in one upload, all or nothing."""
    media_type = request.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if media_type != NDJSON_TYPE:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"findings are uploaded as {NDJSON_TYPE}")
    body = await _read_body(request, request.app.state.settings.max_upload_bytes)
    return await run_in_threadpool(_store, session, run_id, body)


@router.get(
    "/runs/{run_id}/findings",
    tags=["runs"],
    response_class=Response,
    responses={
        200: {
            "description": "The upload byte for byte: its sha256 is the run's `findings_sha256`, the ETag.",
            "content": {NDJSON_TYPE: {"schema": {"type": "string"}}},
        },
        **_errors(404, 413, 503),
    },
)
def get_run_findings(run_id: uuid.UUID, session: SessionDep) -> Response:
    """The run's findings exactly as uploaded: what to hash, correlate or replay against `findings_sha256`."""
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    if run.findings_sha256 is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no findings recorded for this run yet")
    data = run.findings_ndjson
    if data is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "the uploaded bytes were not kept (the run predates API 1.2.0)"
        )
    if hashlib.sha256(data).hexdigest() != run.findings_sha256:  # the database refuses this (migration 0004)
        raise RuntimeError(f"run {run.id}: the kept upload does not match its findings_sha256")
    return Response(data, media_type=NDJSON_TYPE, headers={"ETag": f'"{run.findings_sha256}"'})


@router.get("/findings", tags=["findings"], responses=_errors(413, 503))
def list_findings(
    session: SessionDep,
    repo: Annotated[str | None, Query(pattern=_REPO, max_length=200)] = None,
    run_id: uuid.UUID | None = None,
    category: Category | None = None,
    severity: Severity | None = None,
    tool: Annotated[str | None, Query(min_length=1, max_length=200), NoNul] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
) -> FindingPage:
    """Findings as each run reported them, newest run first."""
    query = select(RunFinding).join(Run)
    if repo is not None:
        query = query.where(Run.repo == repo)
    if run_id is not None:
        query = query.where(RunFinding.run_id == run_id)
    if category is not None:
        query = query.where(RunFinding.category == category)
    if severity is not None:
        query = query.where(RunFinding.severity == severity)
    if tool is not None:
        query = query.where(RunFinding.tool == tool)
    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(
        query.order_by(Run.created_at.desc(), Run.id, RunFinding.finding_id).limit(limit).offset(offset)
    )
    items = [FindingItem(run_id=row.run_id, finding=row.document) for row in rows]
    return FindingPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/findings/{finding_id}", tags=["findings"], responses=_errors(404, 413, 503))
def get_finding(
    finding_id: Annotated[str, Path(pattern=_SHA256)],
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> FindingDetail:
    """One finding (its fingerprint), as the latest run reported it, and the newest runs that reported it."""
    newest_first = (Run.created_at.desc(), Run.id)
    matching = select(RunFinding).join(Run).where(RunFinding.finding_id == finding_id)
    latest = session.scalars(matching.order_by(*newest_first).limit(1)).first()
    if latest is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such finding")
    total = session.scalar(select(func.count()).select_from(matching.subquery())) or 0
    runs = session.scalars(
        select(Run)
        .join(RunFinding)
        .where(RunFinding.finding_id == finding_id)
        .order_by(*newest_first)
        .limit(limit)
    )
    occurrences = [
        Occurrence(run_id=run.id, repo=run.repo, commit=run.commit, context=run.context,  # type: ignore[arg-type]
                   created_at=run.created_at)
        for run in runs
    ]  # fmt: skip
    return FindingDetail(finding=latest.document, occurrence_count=total, occurrences=occurrences)
