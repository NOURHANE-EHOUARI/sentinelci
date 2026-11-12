"""The waivers the gate read, and how often each rule fired (task B7, SPEC sections 6.4 and 10): for the
Policies & waivers page. Read-only aggregates of what was recorded; the platform never judges a waiver.

- `PUT /api/v1/waivers/{sha256}`: one waivers file (schemas/waivers.v1.json, `.sentinel/waivers.yaml`), as the
  gate read it. A decision records only its digest (`inputs.waivers_digest`); the file is kept, named by its
  sha256, only when a recorded decision (a run's or a release's) read it, so the page never shows a file no
  gate evaluated. It must be a file the gate could have read (`sentinelci.policy.waivers.load_waivers`). The
  same file again is answered 200 with the record (a re-run of the upload step).
- `GET /api/v1/waivers/{sha256}`: the file byte for byte, its sha256 as the ETag.
- `GET /api/v1/waivers`: the waivers in force: for each repository, its latest release decision of the default
  branch (`SENTINEL_DEFAULT_REF`), a run's or a release's, by `evaluated_at`, with the waivers of the file it
  read. Each waiver is shown as written (a field that is not text is absent, and `expires_at` is the
  reviewer's text, never a parsed date); whether it applied is the decision's `waivers_applied`, and why one
  is invalid is the decision's SC-005 message. A file not uploaded is `null` (unknown), never an empty list,
  except the empty file, whose digest says it holds no waiver.
- `GET /api/v1/rules`: how many recorded decisions each rule fired in, by effect and context (a decision
  recorded both as a run's and as a release's counts once).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from sentinel_api.api import _REPO, _SHA256, ErrorOut, SessionDep, _read_body
from sentinel_api.auth import require_writer
from sentinel_api.models import WaiversFile
from sentinelci.contracts.decision import DecisionContext, Verdict
from sentinelci.policy.errors import EvaluationError
from sentinelci.policy.waivers import load_waivers

YAML_TYPE = "application/yaml"
# The digest the gate records when there is no waivers file (`sha256` of empty content): no waiver, known.
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_TEXT_FIELDS = ("id", "finding_id", "vulnerability", "purl", "owner", "justification", "expires_at")

router = APIRouter(prefix="/api/v1")

_REASONS = {
    401: "No valid ingestion token (`Authorization: Bearer <token>`).",
    404: "No waivers file of this sha256 is recorded.",
    409: "No recorded decision read this file (`inputs.waivers_digest`): record the decision first.",
    413: "The file is larger than the upload limit.",
    415: f"The file is not sent as `{YAML_TYPE}`.",
    503: "No database is configured.",
}


def _errors(*codes: int) -> dict[int | str, dict[str, Any]]:
    return {code: {"model": ErrorOut, "description": _REASONS[code]} for code in codes}


class WaiversFileOut(BaseModel):
    sha256: str
    waiver_count: int
    created_at: datetime


class WaiverOut(BaseModel):
    """One entry of the file, as written. A field that is absent or not text is null: the platform shows
    what the reviewer wrote and never fills in or corrects a waiver."""

    index: int
    id: str | None
    finding_id: str | None
    vulnerability: str | None
    purl: str | None
    owner: str | None
    justification: str | None
    expires_at: str | None
    applied: bool


class WaiversInForce(BaseModel):
    """A repository's latest release decision of the default branch, and the waivers it read."""

    repo: str
    commit: str
    ref: str | None
    source: Literal["run", "release"]
    run_id: uuid.UUID | None
    image_digest: str | None
    decision_id: uuid.UUID
    verdict: Verdict
    evaluated_at: datetime
    engine_version: str
    policy_bundle_digest: str | None
    # null: a Decision 1.0, which does not record the file it read.
    waivers_digest: str | None
    # null: the file is not uploaded (or not recorded by the decision), so the waivers are unknown.
    waivers: list[WaiverOut] | None
    applied: list[str]
    invalid_waivers: list[str]


class WaiversPage(BaseModel):
    items: list[WaiversInForce]


class RuleCount(BaseModel):
    rule: str
    effect: str
    context: DecisionContext
    decisions: int
    last_evaluated_at: datetime


class RulesOut(BaseModel):
    decisions: int
    items: list[RuleCount]


def _invalid(message: str) -> RequestValidationError:
    return RequestValidationError(
        [{"type": "waivers_invalid", "loc": ("body",), "msg": message, "input": None}]
    )


def _out(row: WaiversFile, count: int) -> WaiversFileOut:
    return WaiversFileOut(sha256=row.sha256, waiver_count=count, created_at=row.created_at)


def _entries(data: bytes) -> list[Any]:
    try:
        return load_waivers(data)
    except EvaluationError as exc:
        raise _invalid(f"not a waivers file the gate could read: {exc}") from exc


_READ_BY_A_DECISION = text(
    """
    SELECT EXISTS (
        SELECT 1 FROM decisions
        WHERE convert_from(document, 'UTF8')::jsonb #>> '{inputs,waivers_digest}' = :digest
    ) OR EXISTS (
        SELECT 1 FROM releases
        WHERE convert_from(document, 'UTF8')::jsonb #>> '{decision,inputs,waivers_digest}' = :digest
    )
    """
)


def _store(session: Session, digest: str, body: bytes) -> WaiversFileOut | JSONResponse:
    if hashlib.sha256(body).hexdigest() != digest:
        raise _invalid(f"these bytes are not waivers file {digest}: their sha256 is another")
    entries = _entries(body)
    recorded = session.get(WaiversFile, digest)
    if recorded is not None:
        return JSONResponse(
            _out(recorded, len(entries)).model_dump(mode="json"), status_code=status.HTTP_200_OK
        )
    if not session.scalar(_READ_BY_A_DECISION, {"digest": f"sha256:{digest}"}):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"no recorded decision read waivers file {digest}: record the decision that read it first",
        )
    row = WaiversFile(sha256=digest, document=body)
    session.add(row)
    try:
        session.commit()
    except IntegrityError:  # the same file recorded meanwhile by a concurrent request
        session.rollback()
        recorded = session.get(WaiversFile, digest)
        if recorded is None:
            raise
        return JSONResponse(
            _out(recorded, len(entries)).model_dump(mode="json"), status_code=status.HTTP_200_OK
        )
    session.refresh(row)
    return _out(row, len(entries))


_DIGEST = Annotated[str, Path(pattern=_SHA256, description="The file's sha256, lowercase hex.")]


@router.put(
    "/waivers/{sha256}",
    status_code=status.HTTP_201_CREATED,
    response_model=WaiversFileOut,
    dependencies=[Depends(require_writer)],
    tags=["waivers"],
    responses={
        200: {"model": WaiversFileOut, "description": "This file is recorded already: its record."},
        **_errors(401, 409, 413, 415, 503),
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "description": "The waivers file (schemas/waivers.v1.json, `.sentinel/waivers.yaml`) as the gate "
            "read it; empty when there was none.",
            "content": {YAML_TYPE: {"schema": {"type": "string"}}},
        }
    },
)
async def record_waivers(
    sha256: _DIGEST, request: Request, session: SessionDep
) -> WaiversFileOut | JSONResponse:
    """Keep a waivers file a recorded decision read, byte for byte, by its sha256. Never judged here."""
    media_type = request.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if media_type != YAML_TYPE:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, f"a waivers file is sent as {YAML_TYPE}")
    body = await _read_body(request, request.app.state.settings.max_upload_bytes)
    return await run_in_threadpool(_store, session, sha256, body)


@router.get(
    "/waivers/{sha256}",
    tags=["waivers"],
    response_class=Response,
    responses={
        200: {
            "description": "The waivers file byte for byte: its sha256 is the ETag.",
            "content": {YAML_TYPE: {"schema": {"type": "string"}}},
        },
        **_errors(404, 503),
    },
)
def get_waivers_file(sha256: _DIGEST, session: SessionDep) -> Response:
    """A recorded waivers file, exactly as it was sent."""
    row = session.get(WaiversFile, sha256)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no waivers file of this sha256 is recorded")
    data = row.document
    if (
        hashlib.sha256(data).hexdigest() != row.sha256
    ):  # the database refuses this (waivers_files_bytes_match)
        raise RuntimeError(f"waivers file {row.sha256} does not match its bytes")
    return Response(data, media_type=YAML_TYPE, headers={"ETag": f'"{row.sha256}"'})


_LATEST = text(
    """
    WITH candidates AS (
        SELECT r.repo, r.commit, r.ref, 'run' AS source, r.id AS run_id, NULL::text AS image_digest,
               d.decision_id, d.evaluated_at, convert_from(d.document, 'UTF8')::jsonb AS decision
        FROM decisions d JOIN runs r ON r.id = d.run_id
        WHERE r.context = 'release' AND r.ref = :ref AND (CAST(:repo AS text) IS NULL OR r.repo = :repo)
        UNION ALL
        SELECT rel.repo, rel.commit, rel.ref, 'release', NULL::uuid, rel.image_digest,
               rel.decision_id, rel.evaluated_at, convert_from(rel.document, 'UTF8')::jsonb -> 'decision'
        FROM releases rel
        WHERE rel.ref = :ref AND (CAST(:repo AS text) IS NULL OR rel.repo = :repo)
    )
    SELECT DISTINCT ON (repo)
        repo, commit, ref, source, run_id, image_digest, decision_id, evaluated_at, decision
    FROM candidates
    ORDER BY repo, evaluated_at DESC, source DESC, decision_id
    """
)


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _waivers(entries: list[Any], applied: set[str]) -> list[WaiverOut]:
    shown = []
    for index, entry in enumerate(entries):
        fields = {name: _text(entry.get(name)) if isinstance(entry, dict) else None for name in _TEXT_FIELDS}
        shown.append(WaiverOut(index=index, **fields, applied=fields["id"] in applied))
    return shown


def _strings(values: Any) -> list[str]:
    return [value for value in values if isinstance(value, str)] if isinstance(values, list) else []


def _in_force(session: Session, default_ref: str, repo: str | None) -> WaiversPage:
    rows = session.execute(_LATEST, {"ref": default_ref, "repo": repo}).mappings().all()
    digests = {
        digest.removeprefix("sha256:")
        for row in rows
        if isinstance(digest := (row["decision"].get("inputs") or {}).get("waivers_digest"), str)
    }
    files = {
        file.sha256: file.document
        for file in session.scalars(select(WaiversFile).where(WaiversFile.sha256.in_(digests)))
    }
    items = []
    for row in rows:
        decision: dict[str, Any] = row["decision"]
        inputs = decision.get("inputs") or {}
        digest = _text(inputs.get("waivers_digest"))
        applied = _strings(decision.get("waivers_applied"))
        name = digest.removeprefix("sha256:") if digest else None
        waivers: list[WaiverOut] | None = None
        if name == EMPTY_SHA256:
            waivers = []
        elif name is not None and name in files:
            waivers = _waivers(load_waivers(files[name]), set(applied))
        items.append(
            WaiversInForce(
                repo=row["repo"], commit=row["commit"], ref=row["ref"], source=row["source"],
                run_id=row["run_id"], image_digest=row["image_digest"], decision_id=row["decision_id"],
                verdict=decision["verdict"], evaluated_at=row["evaluated_at"],
                engine_version=decision["engine_version"],
                policy_bundle_digest=_text(inputs.get("policy_bundle_digest")), waivers_digest=digest,
                waivers=waivers, applied=applied,
                invalid_waivers=[
                    violation["message"]
                    for violation in decision.get("violations") or []
                    if violation.get("rule") == "SC-005" and isinstance(violation.get("message"), str)
                ],
            )
        )  # fmt: skip
    return WaiversPage(items=items)


@router.get("/waivers", response_model=WaiversPage, tags=["waivers"], responses=_errors(503))
def list_waivers_in_force(
    request: Request,
    session: SessionDep,
    repo: Annotated[str | None, Query(pattern=_REPO, max_length=200)] = None,
) -> WaiversPage:
    """For each repository, its latest release decision of the default branch and the waivers it read."""
    return _in_force(session, request.app.state.settings.default_ref, repo)


_RULES = text(
    """
    WITH recorded AS (
        SELECT d.decision_id, r.context, d.evaluated_at,
               convert_from(d.document, 'UTF8')::jsonb -> 'violations' AS violations
        FROM decisions d JOIN runs r ON r.id = d.run_id
        UNION ALL
        SELECT decision_id, 'release', evaluated_at,
               convert_from(document, 'UTF8')::jsonb #> '{decision,violations}'
        FROM releases
    )
    -- A decision recorded both as a run's and as a release's is one decision: count it once.
    SELECT v ->> 'rule' AS rule, v ->> 'effect' AS effect, context,
           count(DISTINCT decision_id) AS decisions, max(evaluated_at) AS last_evaluated_at
    FROM recorded CROSS JOIN LATERAL jsonb_array_elements(violations) AS v
    GROUP BY 1, 2, 3
    ORDER BY 1, 2, 3
    """
)
_DECIDED = text(
    "SELECT count(*) FROM "
    "(SELECT decision_id FROM decisions UNION SELECT decision_id FROM releases) AS decided"
)


@router.get("/rules", response_model=RulesOut, tags=["waivers"], responses=_errors(503))
def count_rules(session: SessionDep) -> RulesOut:
    """How many recorded decisions each rule fired in, by effect and context."""
    rows = session.execute(_RULES).mappings().all()
    return RulesOut(
        decisions=session.scalar(_DECIDED) or 0,
        items=[
            RuleCount(
                rule=row["rule"], effect=row["effect"], context=row["context"], decisions=row["decisions"],
                last_evaluated_at=row["last_evaluated_at"],
            )
            for row in rows
        ],
    )  # fmt: skip
