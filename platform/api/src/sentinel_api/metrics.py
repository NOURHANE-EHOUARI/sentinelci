"""Prometheus metrics of the platform (SPEC section 10, task A8): `GET /metrics`, read-only aggregates.

- Only the metric names of SPEC §10, with bounded labels (an enumerated value each): never a repository, a
  commit, an id or free text.
- Every value is counted by PostgreSQL (`GROUP BY` / `count`), in one read-only REPEATABLE READ transaction:
  every metric of a scrape comes from the same snapshot, so a ratio (MTTR, alert reduction) never pairs one
  set of rows with another. No row is loaded.
- A metric whose data the platform does not store yet is absent, not 0: Grafana shows "No data" rather than a
  false "0 BLOCK".
- The text exposition format (version 0.0.4) is written here, with no client library: a few lines, all of
  them tested.

Exposed now:
- `sentinel_gate_decisions_total{verdict,context}` (counter): the gate decisions recorded (API 1.6.0), by
  verdict (`PASS`, `WARN`, `BLOCK`) and the run's context (`pr`, `release`, `local`). Once one is recorded,
  every pair is present, at 0 when there is none; with none, the metric is absent.
- `sentinel_findings_open{priority,category}` (gauge): the findings of each repository's latest release run
  of its default branch (`SENTINEL_DEFAULT_REF`, default `refs/heads/main`) whose findings are recorded, by
  priority (`P0` to `P4` from `risk`, or `unscored`) and category, summed over the repositories. Once such a
  run exists, every pair is present, at 0 when there is none, so a series never vanishes; with none, the
  metric is absent.
- `sentinel_attestation_verifications_total{result}` (counter): the recorded releases whose image
  `sentinel verify` checked on the release laptop (`POST /api/v1/releases`), by `result`: `trusted` when every
  trust report trusted it, `not_trusted` otherwise. A BLOCK carries no report: nothing was signed, so nothing
  was verified. A release is never deleted, so the count only grows. Absent until one is recorded.

- `sentinel_remediation_attempts_total{strategy,outcome}` (counter): the recorded attempts of the remediation
  loop (`POST /api/v1/remediations`), by strategy and outcome (VERIFIED, REJECTED, FAILED). Once one is
  recorded, every pair is present, at 0 when there is none; an attempt is never deleted, so the counts only
  grow. Absent until one is recorded. Remediation success (SPEC §10) is VERIFIED ÷ all, per strategy.

- `sentinel_findings_fixed{priority}` and `sentinel_findings_fix_seconds{priority}` (gauges): MTTR (SPEC §10)
  is their ratio. Over each repository's release runs of its default branch whose findings and decision are
  recorded, a finding is fixed when a run reports it and the next such run does not; its time to fix runs from
  the first run of that streak to the run that no longer reports it (the runs' recording times). A run whose
  decision holds SC-010 is not evidence that anything is gone (a scanner failed), so it is skipped. Priority
  is the finding's in the last run that reported it. "Next" is the order the runs were recorded in, not the
  commits' order. Both cover every recorded fix since the first evidence run: when an older run's decision is
  recorded late, that run becomes evidence and a fix can move earlier, so the ratio can go down. Every
  priority is present once such a run exists, at 0 when none was fixed; absent before.
- `sentinel_correlated_findings{category}` and `sentinel_root_cause_groups{category}` (gauges): alert
  reduction (SPEC §10) is `1 - groups / findings`. For each repository's latest release run of its default
  branch that has a correlation (A7), its findings and the groups of its latest correlation version, by
  category (a group's findings share one), summed over the repositories. Absent until a correlation is
  recorded.

Absent until their data is stored: `sentinel_pipeline_stage_duration_seconds` and
`sentinel_ai_request_duration_seconds`.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast, get_args

from fastapi import APIRouter, Request
from fastapi.responses import Response
from sqlalchemy import case, func, literal, select, text
from sqlalchemy.orm import Session

from sentinel_api.api import SessionDep, _errors
from sentinel_api.models import Release, Remediation, Run, RunDecision, RunFinding
from sentinelci.contracts.decision import DecisionContext, Verdict
from sentinelci.contracts.finding import Category
from sentinelci.contracts.remediation import Outcome, Strategy

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
PRIORITIES = ("P0", "P1", "P2", "P3", "P4")
UNSCORED = "unscored"
CATEGORIES: tuple[str, ...] = get_args(Category)
VERDICTS: tuple[str, ...] = get_args(Verdict)
CONTEXTS: tuple[str, ...] = get_args(DecisionContext)
STRATEGIES: tuple[str, ...] = get_args(Strategy)
OUTCOMES: tuple[str, ...] = get_args(Outcome)
# SPEC §10: the only names this endpoint may expose, each with its labels (a test keeps them in step).
SPEC_METRICS: dict[str, tuple[str, ...]] = {
    "sentinel_gate_decisions_total": ("verdict", "context"),
    "sentinel_findings_open": ("priority", "category"),
    "sentinel_pipeline_stage_duration_seconds": ("stage",),
    "sentinel_remediation_attempts_total": ("strategy", "outcome"),
    "sentinel_ai_request_duration_seconds": ("task", "model"),
    "sentinel_attestation_verifications_total": ("result",),
    "sentinel_findings_fixed": ("priority",),
    "sentinel_findings_fix_seconds": ("priority",),
    "sentinel_correlated_findings": ("category",),
    "sentinel_root_cause_groups": ("category",),
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


def gate_decisions(session: Session, default_ref: str) -> Family | None:
    """Recorded gate decisions by verdict and the run's context (every repository and ref)."""
    rows = session.execute(
        select(RunDecision.verdict, Run.context, func.count())
        .join(Run, Run.id == RunDecision.run_id)
        .group_by(RunDecision.verdict, Run.context)
    ).all()
    if not rows:
        return None  # no decision recorded: nothing is known, so nothing is said
    counts = {(verdict, context): count for verdict, context, count in rows}
    return Family(
        name="sentinel_gate_decisions_total",
        kind="counter",
        help="Gate decisions recorded, by verdict and context.",
        samples=[
            ({"verdict": verdict, "context": context}, counts.get((verdict, context), 0))
            for verdict in VERDICTS
            for context in CONTEXTS
        ],
    )


def attestation_verifications(session: Session, _default_ref: str) -> Family | None:
    """The recorded releases `sentinel verify` checked, by result (a BLOCK, with no report, is not one)."""
    rows = session.execute(
        select(Release.trusted, func.count()).where(Release.trusted.is_not(None)).group_by(Release.trusted)
    ).all()
    if not rows:
        return None
    counts = {bool(trusted): count for trusted, count in rows}
    return Family(
        name="sentinel_attestation_verifications_total",
        kind="counter",
        help="Recorded releases whose image sentinel verify checked, by result.",
        samples=[
            ({"result": "trusted"}, counts.get(True, 0)),
            ({"result": "not_trusted"}, counts.get(False, 0)),
        ],
    )


def remediation_attempts(session: Session, _default_ref: str) -> Family | None:
    """The recorded attempts of the remediation loop, by strategy and outcome."""
    rows = session.execute(
        select(Remediation.strategy, Remediation.outcome, func.count()).group_by(
            Remediation.strategy, Remediation.outcome
        )
    ).all()
    if not rows:
        return None
    counts = {(strategy, outcome): count for strategy, outcome, count in rows}
    return Family(
        name="sentinel_remediation_attempts_total",
        kind="counter",
        help="Recorded attempts of the remediation loop, by strategy and outcome.",
        samples=[
            ({"strategy": strategy, "outcome": outcome}, counts.get((strategy, outcome), 0))
            for strategy in STRATEGIES
            for outcome in OUTCOMES
        ],
    )


# MTTR. The evidence runs are each repository's release runs of the default branch whose findings and decision
# are recorded and whose decision holds no SC-010 (a failed scanner is no evidence that a finding is gone),
# numbered in recording order. A streak of evidence runs reporting a finding (gaps and islands) is a fix when
# the next evidence run does not report it. The first row counts the evidence runs: none means nothing is
# known.
_FIXES = """
WITH evidence AS (
  SELECT r.id, r.repo, r.findings_uploaded_at AS at,
         row_number() OVER (PARTITION BY r.repo ORDER BY r.findings_uploaded_at, r.id) AS n
  FROM runs r JOIN decisions d ON d.run_id = r.id
  WHERE r.context = 'release' AND r.ref = :ref AND r.findings_sha256 IS NOT NULL
    AND NOT jsonb_path_exists(
      convert_from(d.document, 'UTF8')::jsonb, '$.violations[*] ? (@.rule == "SC-010")'
    )
),
seen AS (
  SELECT e.repo, f.finding_id, e.n, e.at, f.document -> 'risk' ->> 'priority' AS priority,
         e.n - row_number() OVER (PARTITION BY e.repo, f.finding_id ORDER BY e.n) AS streak
  FROM evidence e JOIN findings f ON f.run_id = e.id
),
streaks AS (
  SELECT repo, min(at) AS first_seen, max(n) AS last_n, (array_agg(priority ORDER BY n DESC))[1] AS priority
  FROM seen GROUP BY repo, finding_id, streak
)
SELECT '#evidence_runs' AS bucket, count(*) AS fixed, 0.0 AS seconds FROM evidence
UNION ALL
SELECT CASE WHEN s.priority IN ('P0', 'P1', 'P2', 'P3', 'P4') THEN s.priority ELSE 'unscored' END,
       count(*), sum(extract(epoch FROM gone.at - s.first_seen))
FROM streaks s JOIN evidence gone ON gone.repo = s.repo AND gone.n = s.last_n + 1
GROUP BY 1
"""


def _once[T](session: Session, key: str, compute: Callable[[], T]) -> T:
    """`compute()` once per scrape: the session is the request's, and its transaction one snapshot, so two
    metrics computed from one query (a ratio's two halves) read the same result."""
    cache: dict[str, Any] = session.info.setdefault("sentinel_metrics", {})
    if key not in cache:
        cache[key] = compute()
    return cast(T, cache[key])


def _fixes(session: Session, default_ref: str) -> dict[str, tuple[int, float]] | None:
    """priority -> (findings fixed, seconds to fix them), or None before any evidence run."""

    def compute() -> dict[str, tuple[int, float]] | None:
        rows = {bucket: (int(fixed), float(seconds)) for bucket, fixed, seconds in session.execute(
            text(_FIXES), {"ref": default_ref}
        )}  # fmt: skip
        if not rows.pop("#evidence_runs")[0]:
            return None
        return rows

    return _once(session, f"fixes {default_ref}", compute)


def findings_fixed(session: Session, default_ref: str) -> Family | None:
    """How many findings were fixed on the default branch, by priority (MTTR's denominator)."""
    fixes = _fixes(session, default_ref)
    if fixes is None:
        return None
    return Family(
        name="sentinel_findings_fixed",
        kind="gauge",
        help="Findings fixed on each repository's default branch, by priority.",
        samples=[({"priority": level}, fixes.get(level, (0, 0.0))[0]) for level in (*PRIORITIES, UNSCORED)],
    )


def findings_fix_seconds(session: Session, default_ref: str) -> Family | None:
    """The time those fixes took, in seconds, by priority (MTTR's numerator)."""
    fixes = _fixes(session, default_ref)
    if fixes is None:
        return None
    return Family(
        name="sentinel_findings_fix_seconds",
        kind="gauge",
        help="Seconds from first report to fix of the findings fixed on the default branch, by priority.",
        samples=[({"priority": level}, fixes.get(level, (0, 0.0))[1]) for level in (*PRIORITIES, UNSCORED)],
    )


# Alert reduction. Each repository's latest release run of the default branch that has a correlation, and its
# latest correlation version; a group's category is its first finding's: since API 1.10.2 (#138) the API
# refuses a group across two categories (a correlation stored before is not re-checked), and the correlator
# never forms one. The first row counts those runs: none means nothing is known.
_CORRELATED = """
WITH ranked AS (
  SELECT r.id, row_number() OVER (PARTITION BY r.repo ORDER BY r.findings_uploaded_at DESC, r.id DESC) AS rank
  FROM runs r
  WHERE r.context = 'release' AND r.ref = :ref AND r.findings_sha256 IS NOT NULL
    AND EXISTS (SELECT 1 FROM correlations c WHERE c.run_id = r.id)
),
correlated AS (
  SELECT ranked.id AS run_id, latest.document
  FROM ranked
  JOIN LATERAL (
    SELECT c.document FROM correlations c WHERE c.run_id = ranked.id ORDER BY c.seq DESC LIMIT 1
  ) latest ON true
  WHERE ranked.rank = 1
)
SELECT '#runs' AS category, 'runs' AS kind, count(*) AS n FROM correlated
UNION ALL
SELECT f.category, 'findings', count(*) FROM correlated JOIN findings f ON f.run_id = correlated.run_id
GROUP BY f.category
UNION ALL
SELECT f.category, 'groups', count(*)
FROM correlated
CROSS JOIN LATERAL jsonb_array_elements(convert_from(correlated.document, 'UTF8')::jsonb -> 'groups') g
JOIN findings f ON f.run_id = correlated.run_id AND f.finding_id = g -> 'finding_ids' ->> 0
GROUP BY f.category
"""


def _correlated(session: Session, default_ref: str, kind: str) -> dict[str, int] | None:
    """category -> findings or groups, or None before any correlation of a release run."""

    def compute() -> dict[tuple[str, str], int]:
        return {(category, what): int(n) for category, what, n in session.execute(
            text(_CORRELATED), {"ref": default_ref}
        )}  # fmt: skip

    rows = _once(session, f"correlated {default_ref}", compute)
    if not rows[("#runs", "runs")]:
        return None
    return {category: n for (category, what), n in rows.items() if what == kind}


def correlated_findings(session: Session, default_ref: str) -> Family | None:
    """The findings of each repository's latest correlated release run, by category."""
    counts = _correlated(session, default_ref, "findings")
    if counts is None:
        return None
    return Family(
        name="sentinel_correlated_findings",
        kind="gauge",
        help="Findings of each repository's latest correlated release run, by category.",
        samples=[({"category": category}, counts.get(category, 0)) for category in CATEGORIES],
    )


def root_cause_groups(session: Session, default_ref: str) -> Family | None:
    """The root-cause groups the correlator made of them, by category."""
    counts = _correlated(session, default_ref, "groups")
    if counts is None:
        return None
    return Family(
        name="sentinel_root_cause_groups",
        kind="gauge",
        help="Root-cause groups of each repository's latest correlated release run, by category.",
        samples=[({"category": category}, counts.get(category, 0)) for category in CATEGORIES],
    )


# Each metric the platform can compute; one returns None while its data is not stored.
METRICS: tuple[Callable[[Session, str], Family | None], ...] = (
    gate_decisions,
    findings_open,
    attestation_verifications,
    remediation_attempts,
    findings_fixed,
    findings_fix_seconds,
    correlated_findings,
    root_cause_groups,
)


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
    session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
    default_ref: str = request.app.state.settings.default_ref
    families = [family for metric in METRICS if (family := metric(session, default_ref)) is not None]
    return Response(content=render(families), media_type=CONTENT_TYPE)
