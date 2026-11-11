"""Keep each run's gate decision (Decision v1, task B4), byte for byte: one per run.

`sentinel upload` posts the decision `sentinel evaluate` wrote (`POST /api/v1/runs/{id}/decision`). It is kept
as the bytes that were sent, named by their sha256, and served back unchanged.

The database is the backstop for what the API checks:
- the bytes hash to the decision's name (`decisions_bytes_match`);
- a run has one decision (the primary key), and a decision belongs to one run (`decision_id` is unique);
- a decision is only added to a run whose findings are recorded, if it was made on exactly those findings
  (`inputs.findings_digest` is `sha256:` and the run's `findings_sha256`) and is about the run's subject
  (repo, commit, context, and the ref when the decision names one);
- the copied columns that are listed and counted are the document's (`decision_id`, `verdict`);
  `evaluated_at` and `engine_version` are copied by the API only, for display (the document is the reference);
- a decision never changes and is never deleted (a recorded run cannot be deleted either, migration 0002).

Going back below 0006 would drop the only copy of those documents, so the downgrade stops, changing nothing,
while any decision is kept (like 0004 and 0005).

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "decisions",
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("runs.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("decision_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("verdict", sa.String(8), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("engine_version", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("document", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'", name="decisions_sha256"),
        sa.CheckConstraint("encode(sha256(document), 'hex') = sha256", name="decisions_bytes_match"),
        sa.CheckConstraint("verdict IN ('PASS', 'WARN', 'BLOCK')", name="decisions_verdict"),
    )
    op.execute(
        """
        CREATE FUNCTION decisions_are_kept() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            doc jsonb;
            run runs%ROWTYPE;
        BEGIN
            IF TG_OP <> 'INSERT' THEN
                RAISE EXCEPTION 'the decision of run % is kept as recorded: it cannot change or be deleted',
                    OLD.run_id;
            END IF;
            doc := convert_from(NEW.document, 'UTF8')::jsonb;
            SELECT * INTO run FROM runs WHERE id = NEW.run_id;
            IF run.findings_sha256 IS NULL
               OR doc #>> '{inputs,findings_digest}' IS DISTINCT FROM 'sha256:' || run.findings_sha256 THEN
                RAISE EXCEPTION 'run %: a decision is kept only if it was made on the findings it recorded',
                    NEW.run_id;
            END IF;
            IF doc #>> '{subject,repo}' IS DISTINCT FROM run.repo
               OR doc #>> '{subject,commit}' IS DISTINCT FROM run.commit
               OR doc #>> '{subject,context}' IS DISTINCT FROM run.context
               OR (doc -> 'subject' ? 'ref' AND doc #>> '{subject,ref}' IS DISTINCT FROM run.ref) THEN
                RAISE EXCEPTION 'run %: a decision is kept only about the run''s subject', NEW.run_id;
            END IF;
            IF (doc ->> 'decision_id')::uuid IS DISTINCT FROM NEW.decision_id
               OR doc ->> 'verdict' IS DISTINCT FROM NEW.verdict THEN
                RAISE EXCEPTION 'run %: the columns are the document''s (decision_id, verdict)', NEW.run_id;
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER decisions_are_kept BEFORE INSERT OR UPDATE OR DELETE ON decisions "
        "FOR EACH ROW EXECUTE FUNCTION decisions_are_kept()"
    )


KEPT = "SELECT count(*) FROM decisions"


def downgrade() -> None:
    kept = op.get_bind().execute(sa.text(KEPT)).scalar_one()
    if kept:
        raise RuntimeError(
            f"{kept} decision(s) are kept (table decisions), the only copy of what the gate decided for "
            "those runs, so going below 0006 would lose them. Stay at 0006 or later, or export them first "
            "(GET /api/v1/runs/{id}/decision) and go down on a new, empty database; a kept decision cannot "
            "be deleted (trigger decisions_are_kept). Nothing was changed."
        )
    op.execute("DROP TRIGGER decisions_are_kept ON decisions")
    op.execute("DROP FUNCTION decisions_are_kept()")
    op.drop_table("decisions")
