"""A recorded run's evidence cannot change (#38 review).

Once `runs.findings_sha256` is set, the database refuses any change to the run (its evidence and what the
upload was checked against: repo, commit, context, ref, CI run id) and refuses to delete it, and refuses to
add, change or remove that run's findings. A run whose findings never arrived carries no evidence and can
still be deleted. The API's single conditional update already allows
one recording only; this is the backstop for anything that bypasses it.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION runs_keep_recorded_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.findings_sha256 IS NOT NULL THEN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'run % is recorded: it cannot be deleted', OLD.id;
                ELSIF NEW IS DISTINCT FROM OLD THEN
                    RAISE EXCEPTION 'run % is recorded: its evidence cannot change', OLD.id;
                END IF;
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER runs_keep_recorded_evidence BEFORE UPDATE OR DELETE ON runs "
        "FOR EACH ROW EXECUTE FUNCTION runs_keep_recorded_evidence()"
    )
    op.execute(
        """
        CREATE FUNCTION findings_of_recorded_runs_are_fixed() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            target uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.run_id ELSE NEW.run_id END;
        BEGIN
            IF EXISTS (SELECT 1 FROM runs WHERE id = target AND findings_sha256 IS NOT NULL)
               OR (TG_OP = 'UPDATE' AND EXISTS (
                   SELECT 1 FROM runs WHERE id = OLD.run_id AND findings_sha256 IS NOT NULL)) THEN
                RAISE EXCEPTION 'run % is recorded: its findings cannot change', target;
            END IF;
            RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER findings_of_recorded_runs_are_fixed BEFORE INSERT OR UPDATE OR DELETE ON findings "
        "FOR EACH ROW EXECUTE FUNCTION findings_of_recorded_runs_are_fixed()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER findings_of_recorded_runs_are_fixed ON findings")
    op.execute("DROP FUNCTION findings_of_recorded_runs_are_fixed()")
    op.execute("DROP TRIGGER runs_keep_recorded_evidence ON runs")
    op.execute("DROP FUNCTION runs_keep_recorded_evidence()")
