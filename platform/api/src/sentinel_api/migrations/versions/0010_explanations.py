"""Explanations of findings (Explanation v1, task B5c) and the requests that ask for them.

`POST /api/v1/findings/{id}/explain` records a request and queues a job; the worker claims it (queued →
running), asks the model, and records the outcome. An explanation is advisory (the gate never reads it), kept
as the bytes the worker produced, named by their sha256.

The database is the backstop for what the API checks:
- a request is about a finding its run recorded (a foreign key to `findings`);
- a request has one of the known statuses, and only an explained one names an explanation
  (`explain_requests_explained`);
- one open request (queued or running) per finding and run (`explain_requests_one_open`);
- an explanation's bytes hash to its name (`explanations_bytes_match`), it is about its own finding and its
  request's (trigger `explanations_are_kept`), and it never changes and is never deleted (the same trigger).

Going back below 0010 would drop the only copy of those explanations, so the downgrade stops, changing
nothing, while any is kept. Requests are only a queue's state: they go.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

STATUSES = "('queued', 'running', 'explained', 'unavailable', 'not_sent', 'failed')"


def upgrade() -> None:
    op.create_table(
        "explain_requests",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("finding_id", sa.String(64), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("explanation_sha256", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id", "finding_id"], ["findings.run_id", "findings.finding_id"], ondelete="CASCADE"
        ),
        sa.CheckConstraint(f"status IN {STATUSES}", name="explain_requests_status"),
        sa.CheckConstraint(
            "(status = 'explained') = (explanation_sha256 IS NOT NULL)", name="explain_requests_explained"
        ),
    )
    op.create_index(
        "explain_requests_one_open",
        "explain_requests",
        ["finding_id", "run_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.create_table(
        "explanations",
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), nullable=False, unique=True),
        sa.Column("finding_id", sa.String(64), nullable=False, index=True),
        sa.Column("run_id", sa.Uuid(), sa.ForeignKey("runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column(
            "request_id", sa.Uuid(), sa.ForeignKey("explain_requests.id", ondelete="CASCADE"), nullable=False,
            unique=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("document", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'", name="explanations_sha256"),
        sa.CheckConstraint("encode(sha256(document), 'hex') = sha256", name="explanations_bytes_match"),
    )  # fmt: skip
    op.create_foreign_key(
        "explain_requests_explanation", "explain_requests", "explanations", ["explanation_sha256"], ["sha256"]
    )
    op.execute(
        """
        CREATE FUNCTION explanations_are_kept() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
            request explain_requests%ROWTYPE;
        BEGIN
            IF TG_OP <> 'INSERT' THEN
                RAISE EXCEPTION 'explanation % is kept as recorded: it cannot change or be deleted',
                    OLD.sha256;
            END IF;
            SELECT * INTO request FROM explain_requests WHERE id = NEW.request_id;
            IF convert_from(NEW.document, 'UTF8')::jsonb ->> 'finding_id' IS DISTINCT FROM NEW.finding_id
               OR request.finding_id IS DISTINCT FROM NEW.finding_id
               OR request.run_id IS DISTINCT FROM NEW.run_id THEN
                RAISE EXCEPTION
                    'explanation %: an explanation is kept only about its own finding and its request''s',
                    NEW.sha256;
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER explanations_are_kept BEFORE INSERT OR UPDATE OR DELETE ON explanations "
        "FOR EACH ROW EXECUTE FUNCTION explanations_are_kept()"
    )


KEPT = "SELECT count(*) FROM explanations"


def downgrade() -> None:
    kept = op.get_bind().execute(sa.text(KEPT)).scalar_one()
    if kept:
        raise RuntimeError(
            f"{kept} explanation(s) are kept (table explanations), the only copy of what the analyst wrote, "
            "so going below 0010 would lose them. Stay at 0010 or later, or export them first (GET "
            "/api/v1/findings/{id}/explanation) and go down on a new, empty database; a kept explanation "
            "cannot be deleted (trigger explanations_are_kept). Nothing was changed."
        )
    op.drop_constraint("explain_requests_explanation", "explain_requests", type_="foreignkey")
    op.execute("DROP TRIGGER explanations_are_kept ON explanations")
    op.execute("DROP FUNCTION explanations_are_kept()")
    op.drop_table("explanations")
    op.drop_index("explain_requests_one_open", table_name="explain_requests")
    op.drop_table("explain_requests")
