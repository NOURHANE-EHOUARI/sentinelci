"""Keep the waivers files the gate read (schemas/waivers.v1.json, SPEC section 6.4), byte for byte.

A decision records the digest of the waivers file it read (`inputs.waivers_digest`, Decision 1.1), not the
file. `PUT /api/v1/waivers/{sha256}` keeps that file, named by its sha256, for the Policies & waivers page:
who owns each waiver, why, and when it expires.

The database is the backstop for what the API checks:
- the bytes hash to their name (`waivers_files_bytes_match`);
- a file is kept only when a recorded decision read it: a run's decision or a release's names
  `sha256:<name>` as `inputs.waivers_digest` (trigger `waivers_files_are_kept`), so the page never shows a
  file no gate evaluated;
- a file never changes and is never deleted (the same trigger).

`entries` is the API's parse of the bytes, and the database cannot check it against them: PL/pgSQL reads no
YAML. A row written straight into the table could list other waivers than its file holds, the same trust as
any other column the API derives for display.

Going back below 0009 would drop the only copy of those files, so the downgrade stops, changing nothing, while
any file is kept.

Revision ID: 0009
Revises: 0008
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "waivers_files",
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("document", sa.LargeBinary(), nullable=False),
        # What the gate's loader read from the bytes (`load_waivers`), parsed once when the file is recorded,
        # so listing the waivers in force never parses a file again. The bytes stay the record.
        sa.Column("entries", JSONB(), nullable=False),
        sa.CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'", name="waivers_files_sha256"),
        sa.CheckConstraint("jsonb_typeof(entries) = 'array'", name="waivers_files_entries"),
        sa.CheckConstraint("encode(sha256(document), 'hex') = sha256", name="waivers_files_bytes_match"),
    )
    op.execute(
        """
        CREATE FUNCTION waivers_files_are_kept() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP <> 'INSERT' THEN
                RAISE EXCEPTION 'waivers file % is kept as recorded: it cannot change or be deleted',
                    OLD.sha256;
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM decisions
                WHERE convert_from(document, 'UTF8')::jsonb #>> '{inputs,waivers_digest}'
                    = 'sha256:' || NEW.sha256
            ) AND NOT EXISTS (
                SELECT 1 FROM releases
                WHERE convert_from(document, 'UTF8')::jsonb #>> '{decision,inputs,waivers_digest}'
                    = 'sha256:' || NEW.sha256
            ) THEN
                RAISE EXCEPTION 'waivers file %: no recorded decision read it', NEW.sha256;
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER waivers_files_are_kept BEFORE INSERT OR UPDATE OR DELETE ON waivers_files "
        "FOR EACH ROW EXECUTE FUNCTION waivers_files_are_kept()"
    )


KEPT = "SELECT count(*) FROM waivers_files"


def downgrade() -> None:
    kept = op.get_bind().execute(sa.text(KEPT)).scalar_one()
    if kept:
        raise RuntimeError(
            f"{kept} waivers file(s) are kept (table waivers_files), the only copy the platform has of the "
            "waivers the gate read, so going below 0009 would lose them. Stay at 0009 or later, or export "
            "them first (GET /api/v1/waivers/{sha256}) and go down on a new, empty database; a kept file "
            "cannot be deleted (trigger waivers_files_are_kept). Nothing was changed."
        )
    op.execute("DROP TRIGGER waivers_files_are_kept ON waivers_files")
    op.execute("DROP FUNCTION waivers_files_are_kept()")
    op.drop_table("waivers_files")
