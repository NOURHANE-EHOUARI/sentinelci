"""Platform API v1, first cut (SPEC section 13.3): record runs and their findings, then query them."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from sentinel_api.auth import require_writer
from sentinel_api.models import Run, RunFinding
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


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str = Field(pattern=_REPO, max_length=200)
    commit: str = Field(pattern=_COMMIT)
    context: RunContext
    ref: str | None = Field(default=None, pattern=_LINE, min_length=1, max_length=255)
    run_id: str | None = Field(default=None, pattern=_LINE, min_length=1, max_length=255)


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


class UploadResult(BaseModel):
    run_id: uuid.UUID
    finding_count: int
    findings_sha256: str


class FindingItem(BaseModel):
    run_id: uuid.UUID
    finding: dict[str, Any]


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
    )  # fmt: skip


@router.post(
    "/runs", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_writer)], tags=["runs"]
)
def create_run(body: RunCreate, session: SessionDep) -> RunOut:
    """Record a pipeline run. Its findings are uploaded next, once."""
    run = Run(repo=body.repo, commit=body.commit, context=body.context, ref=body.ref, ci_run_id=body.run_id)
    session.add(run)
    session.commit()
    session.refresh(run)
    return _run_out(run)


@router.get("/runs/{run_id}", tags=["runs"])
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
    return b"".join(chunks)


def _parse(body: bytes, run: Run) -> list[dict[str, Any]]:
    """Finding v1 documents of exactly this run, or 422 with the first problem (nothing is stored)."""
    try:
        findings = load_findings(body)
    except EvaluationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    # load_findings skips blank lines; recover each finding's line number the same way.
    lines = [n for n, line in enumerate(body.decode("utf-8").split("\n"), start=1) if line.strip()]
    expected = {"repo": run.repo, "commit": run.commit, "context": run.context}
    optional = {"ref": run.ref, "run_id": run.ci_run_id}
    seen: dict[str, int] = {}
    for lineno, finding in zip(lines, findings, strict=True):
        if (first := seen.setdefault(finding["id"], lineno)) != lineno:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"findings line {lineno}: finding {finding['id']} appears twice (first on line {first})",
            )
        reported = finding["run"]
        mismatch = any(reported.get(k) != v for k, v in expected.items()) or any(
            k in reported and reported[k] != v for k, v in optional.items()
        )
        if mismatch:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                f"findings line {lineno}: the finding belongs to another run",
            )
    return findings


def _store(session: Session, run_id: uuid.UUID, body: bytes) -> UploadResult:
    # Lock the run row: two concurrent uploads must not both see "no findings yet".
    run = session.get(Run, run_id, with_for_update=True)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such run")
    if run.findings_sha256 is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "this run's findings are already recorded")
    findings = _parse(body, run)
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
    run.findings_sha256 = hashlib.sha256(body).hexdigest()
    run.findings_uploaded_at = datetime.now(UTC)
    run.finding_count = len(findings)
    session.commit()
    return UploadResult(run_id=run.id, finding_count=run.finding_count, findings_sha256=run.findings_sha256)


@router.post(
    "/runs/{run_id}/findings",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_writer)],
    tags=["runs"],
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


@router.get("/findings", tags=["findings"])
def list_findings(
    session: SessionDep,
    repo: Annotated[str | None, Query(pattern=_REPO, max_length=200)] = None,
    run_id: uuid.UUID | None = None,
    category: Category | None = None,
    severity: Severity | None = None,
    tool: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
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


@router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(finding_id: Annotated[str, Path(pattern=_SHA256)], session: SessionDep) -> FindingDetail:
    """One finding (its fingerprint), as the latest run reported it, with every run that reported it."""
    rows = session.execute(
        select(RunFinding, Run)
        .join(Run)
        .where(RunFinding.finding_id == finding_id)
        .order_by(Run.created_at.desc(), Run.id)
    ).all()
    if not rows:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such finding")
    occurrences = [
        Occurrence(run_id=run.id, repo=run.repo, commit=run.commit, context=run.context,  # type: ignore[arg-type]
                   created_at=run.created_at)
        for _, run in rows
    ]  # fmt: skip
    return FindingDetail(finding=rows[0][0].document, occurrences=occurrences)
