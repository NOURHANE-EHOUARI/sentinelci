"""Keep each run's findings upload byte for byte (`runs.findings_ndjson`).

The findings are stored as JSONB rows, which keep neither key order nor bytes, so nothing could give back the
bytes `findings_sha256` was taken of. A consumer that must match that digest (the correlator's run document,
a replay) now reads them from `GET /api/v1/runs/{id}/findings`.

The database keeps only bytes that hash to the run's recorded digest (`runs_findings_bytes_match`), and the
trigger of 0002 already refuses any change to a recorded run, these bytes included. Runs recorded before this
migration have no bytes (null), and the API says so.

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


def downgrade() -> None:
    op.drop_constraint("runs_findings_bytes_match", "runs", type_="check")
    op.drop_column("runs", "findings_ndjson")
