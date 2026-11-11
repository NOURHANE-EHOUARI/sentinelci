"""Prometheus metrics of the platform (SPEC section 10, task A8): `GET /metrics`, read-only aggregates.

- Only the metric names of SPEC §10, with bounded labels (an enumerated value each): never a repository, a
  commit, an id or free text.
- Every value is counted by PostgreSQL (`GROUP BY` / `count`), in a read-only transaction; no row is loaded.
- A metric whose data the platform does not store yet is absent, not 0: Grafana shows "No data" rather than a
  false "0 BLOCK".
- The text exposition format (version 0.0.4) is written here, with no client library: a few lines, all of
  them tested.

Exposed now:
- `sentinel_findings_open{priority,category}` (gauge): the findings of each repository's latest release run
  of its default branch (`SENTINEL_DEFAULT_REF`, default `refs/heads/main`) whose findings are recorded, by
  priority (`P0` to `P4` from `risk`, or `unscored`) and category, summed over the repositories. Once such a
  run exists, every pair is present, at 0 when there is none, so a series never vanishes; with none, the
  metric is absent.

Absent until their data is stored: `sentinel_gate_decisions_total` (decisions, B1),
`sentinel_remediation_attempts_total` (remediation jobs, A6), `sentinel_attestation_verifications_total`,
`sentinel_pipeline_stage_duration_seconds` and `sentinel_ai_request_duration_seconds`.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal, get_args

from fastapi import APIRouter, Request
from fastapi.responses import Response
from sqlalchemy import case, func, literal, select, text
from sqlalchemy.orm import Session

from sentinel_api.api import SessionDep, _errors
from sentinel_api.models import Run, RunFinding
from sentinelci.contracts.finding import Category

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
UNSCORED = "unscored"
CATEGORIES: tuple[str, ...] = get_args(Category)
# SPEC §10: the only names this endpoint may expose, each with its labels (a test keeps them in step).
SPEC_METRICS: dict[str, tuple[str, ...]] = {
    "sentinel_gate_decisions_total": ("verdict", "context"),
    "sentinel_findings_open": ("priority", "category"),
    "sentinel_pipeline_stage_duration_seconds": ("stage",),
    "sentinel_remediation_attempts_total": ("strategy", "outcome"),
    "sentinel_ai_request_duration_seconds": ("task", "model"),
    "sentinel_attestation_verifications_total": ("result",),
}
SPEC_NAMES = frozenset(SPEC_METRICS)

router = APIRouter()


@dataclass(frozen=True)
class Family:
    """One metric and its samples (label values, value)."""

    name: str
    kind: Literal["counter", "gauge"]
    help: str
    samples: Sequence[tuple[dict[str, str], float]]


def _escape_help(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n")


def _escape(value: str) -> str:
    """A label value: a backslash, a line feed and a double quote are escaped."""
    return _escape_help(value).replace('"', '\\"')


def _number(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    return str(int(value)) if float(value).is_integer() else repr(float(value))


def render(families: Sequence[Family]) -> str:
    """The text exposition format: HELP and TYPE, then one line per sample, labels in their given order.
    A name or a label SPEC §10 does not list is a ValueError."""
    lines: list[str] = []
    for family in families:
        if family.name not in SPEC_NAMES:
            raise ValueError(f"{family.name} is not a metric of SPEC section 10")
        if any(set(labels) != set(SPEC_METRICS[family.name]) for labels, _ in family.samples):
            raise ValueError(f"{family.name} takes the labels {', '.join(SPEC_METRICS[family.name])} only")
        lines += [f"# HELP {family.name} {_escape_help(family.help)}", f"# TYPE {family.name} {family.kind}"]
        for labels, value in family.samples:
            pairs = ",".join(f'{key}="{_escape(label)}"' for key, label in labels.items())
            lines.append(f"{family.name}{{{pairs}}} {_number(value)}")
    return "".join(f"{line}\n" for line in lines)


def findings_open(session: Session, default_ref: str) -> Family | None:
    """Open findings by priority and category: those of each repository's latest release run of its default
    branch (`default_ref`). A release run of another ref (a manual run on a feature branch) is not counted."""
    newest_first = func.row_number().over(
        partition_by=Run.repo, order_by=(Run.findings_uploaded_at.desc(), Run.id.desc())
    )
    ranked = (
        select(Run.id, newest_first.label("rank"))
        .where(Run.context == "release", Run.ref == default_ref, Run.findings_sha256.is_not(None))
        .subquery()
    )
    latest = select(ranked.c.id).where(ranked.c.rank == 1).subquery()
    if not session.scalar(select(func.count()).select_from(latest)):
        return None  # no release run recorded: nothing is known, so nothing is said
    priority = RunFinding.document["risk"]["priority"].astext
    bucket = case((priority.in_(PRIORITIES), priority), else_=literal(UNSCORED)).label("priority")
    rows = session.execute(
        select(RunFinding.category, bucket, func.count())
        .join(latest, RunFinding.run_id == latest.c.id)
        .group_by(RunFinding.category, bucket)
    ).all()
    counts = {(category, level): count for category, level, count in rows}
    return Family(
        name="sentinel_findings_open",
        kind="gauge",
        help="Findings of each repository's latest release run, by priority and category.",
        samples=[
            ({"priority": level, "category": category}, counts.get((category, level), 0))
            for level in (*PRIORITIES, UNSCORED)
            for category in CATEGORIES
        ],
    )


# Each metric the platform can compute; one returns None while its data is not stored.
METRICS: tuple[Callable[[Session, str], Family | None], ...] = (findings_open,)


@router.get(
    "/metrics",
    tags=["ops"],
    response_class=Response,
    responses={
        200: {"content": {CONTENT_TYPE: {"schema": {"type": "string"}}}, "description": "Prometheus text."},
        **_errors(503),
    },
)
def metrics(request: Request, session: SessionDep) -> Response:
    """Prometheus metrics (SPEC section 10): read-only aggregates, bounded labels, absent until stored."""
    session.execute(text("SET TRANSACTION READ ONLY"))
    default_ref: str = request.app.state.settings.default_ref
    families = [family for metric in METRICS if (family := metric(session, default_ref)) is not None]
    return Response(content=render(families), media_type=CONTENT_TYPE)
