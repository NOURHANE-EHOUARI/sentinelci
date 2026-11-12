"""Keep each run's correlations (Correlation v1, task A7), version by version, byte for byte.

A correlator run posts one Correlation v1 document per run (`POST /api/v1/runs/{id}/correlations`). Each
version is kept as the bytes that were sent, named by their sha256, and served back unchanged. The groups are
advisory: the gate never reads them.

The database is the backstop for what the API checks:
- a version's bytes hash to its name (`correlations_bytes_match`);
- a version is only added to a run whose findings are recorded, and only if the document names that run's
  `findings_sha256` (the groups were computed from exactly those findings);
- a version never changes and is never deleted (a recorded run cannot be deleted either, migration 0002).

Going back below 0005 would drop the only copy of those documents, so the downgrade stops, changing nothing,
while any version is kept (like 0004 with the uploaded findings).

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "correlations",
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("runs.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), nullable=False, unique=True),
        sa.Column("correlator_version", sa.String(64), nullable=False),
        sa.Column("group_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("document", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'", name="correlations_sha256"),
        sa.CheckConstraint("encode(sha256(document), 'hex') = sha256", name="correlations_bytes_match"),
    )
    op.execute(
        """
        CREATE FUNCTION correlations_are_kept() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NOT EXISTS (
                    SELECT 1 FROM runs
                    WHERE id = NEW.run_id
                      AND findings_sha256 IS NOT NULL
                      AND findings_sha256 = convert_from(NEW.document, 'UTF8')::jsonb ->> 'findings_sha256'
                ) THEN
                    RAISE EXCEPTION 'run %: a correlation is kept only for the findings the run recorded',
                        NEW.run_id;
                END IF;
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'correlation % of run % is kept as recorded: it cannot change or be deleted',
                OLD.sha256, OLD.run_id;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER correlations_are_kept BEFORE INSERT OR UPDATE OR DELETE ON correlations "
        "FOR EACH ROW EXECUTE FUNCTION correlations_are_kept()"
    )


KEPT = "SELECT count(*) FROM correlations"


def downgrade() -> None:
    kept = op.get_bind().execute(sa.text(KEPT)).scalar_one()
    if kept:
        raise RuntimeError(
            f"{kept} correlation version(s) are kept (table correlations), the only copy of what the "
            "correlator posted, so going below 0005 would lose them. Stay at 0005 or later, or export them "
            "first (GET /api/v1/runs/{id}/correlations?sha256=...) and go down on a new, empty database; a "
            "kept version cannot be deleted (trigger correlations_are_kept). Nothing was changed."
        )
    op.execute("DROP TRIGGER correlations_are_kept ON correlations")
    op.execute("DROP FUNCTION correlations_are_kept()")
    op.drop_table("correlations")
