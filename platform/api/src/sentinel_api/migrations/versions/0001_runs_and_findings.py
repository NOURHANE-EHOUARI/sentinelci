"""Runs and the findings each run reported (B1a).

Revision ID: 0001
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("repo", sa.String(length=200), nullable=False),
        sa.Column("commit", sa.String(length=40), nullable=False),
        sa.Column("context", sa.String(length=16), nullable=False),
        sa.Column("ref", sa.String(length=255), nullable=True),
        sa.Column("ci_run_id", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("findings_sha256", sa.String(length=64), nullable=True),
        sa.Column("findings_uploaded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finding_count", sa.Integer(), server_default="0", nullable=False),
        sa.CheckConstraint("context IN ('pr', 'release', 'local')", name="runs_context"),
        sa.CheckConstraint("commit ~ '^[a-f0-9]{40}$'", name="runs_commit"),
        sa.CheckConstraint(
            "(findings_sha256 IS NULL) = (findings_uploaded_at IS NULL)", name="runs_findings_recorded_once"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_runs_repo", "runs", ["repo"])
    op.create_table(
        "findings",
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("tool", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["run_id"], ["runs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("run_id", "finding_id"),
    )
    op.create_index("findings_finding_id", "findings", ["finding_id"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_tool", "findings", ["tool"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("runs")
