"""Keep each run's findings upload byte for byte (`runs.findings_ndjson`).

The findings are stored as JSONB rows, which keep neither key order nor bytes, so nothing could give back the
bytes `findings_sha256` was taken of. A consumer that must match that digest (the correlator's run document,
a replay) now reads them from `GET /api/v1/runs/{id}/findings`.

The database keeps only bytes that hash to the run's recorded digest (`runs_findings_bytes_match`), and the
trigger of 0002 already refuses any change to a recorded run, these bytes included. Runs recorded before this
migration have no bytes (null), and the API says so.

Going back below 0004 would drop the only copy of those bytes, so the downgrade stops, changing nothing, while
any run keeps them (like 0003 on a CI run recorded twice).

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("findings_ndjson", sa.LargeBinary(), nullable=True))
    op.create_check_constraint(
        "runs_findings_bytes_match",
        "runs",
        "findings_ndjson IS NULL OR "
        "(findings_sha256 IS NOT NULL AND encode(sha256(findings_ndjson), 'hex') = findings_sha256)",
    )


KEPT = "SELECT count(*) FROM runs WHERE findings_ndjson IS NOT NULL"


def downgrade() -> None:
    kept = op.get_bind().execute(sa.text(KEPT)).scalar_one()
    if kept:
        raise RuntimeError(
            f"{kept} run(s) keep their uploaded findings bytes (runs.findings_ndjson), the only copy that "
            "findings_sha256 was taken of, so going below 0004 would lose them. Stay at 0004 or later, or "
            "export them first (GET /api/v1/runs/{id}/findings) and go down on a new, empty database; a "
            "recorded run cannot be cleared (trigger runs_keep_recorded_evidence). Nothing was changed."
        )
    op.drop_constraint("runs_findings_bytes_match", "runs", type_="check")
    op.drop_column("runs", "findings_ndjson")
