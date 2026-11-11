"""Keep each release's evidence (Release evidence v1, tasks A4 and A8), byte for byte.

`make release` posts one document per release decision (`POST /api/v1/releases`): the decision record and
what `sentinel verify` found about the image (none for a BLOCK, which nothing signed). It is kept as the bytes
that were sent, named by their sha256, and served back unchanged for the Releases & evidence page.

The database is the backstop for what the API checks:
- the bytes hash to their name (`releases_bytes_match`);
- a BLOCK release is never recorded as trusted (`releases_block_never_trusted`);
- a release never changes and is never deleted (trigger `releases_are_kept`).

Going back below 0006 would drop the only copy of those documents, so the downgrade stops, changing nothing,
while any release is kept (like 0005 with the correlations).

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
        "releases",
        sa.Column("decision_id", sa.Uuid(), primary_key=True),
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), nullable=False, unique=True),
        sa.Column("repo", sa.String(200), nullable=False),
        sa.Column("commit", sa.String(40), nullable=False),
        sa.Column("ref", sa.String(255), nullable=True),
        sa.Column("image_digest", sa.String(71), nullable=False),
        sa.Column("verdict", sa.String(5), nullable=False),
        sa.Column("trusted", sa.Boolean(), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("document", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'", name="releases_sha256"),
        sa.CheckConstraint("encode(sha256(document), 'hex') = sha256", name="releases_bytes_match"),
        sa.CheckConstraint("commit ~ '^[a-f0-9]{40}$'", name="releases_commit"),
        sa.CheckConstraint("image_digest ~ '^sha256:[a-f0-9]{64}$'", name="releases_image_digest"),
        sa.CheckConstraint("verdict IN ('PASS', 'WARN', 'BLOCK')", name="releases_verdict"),
        sa.CheckConstraint("verdict <> 'BLOCK' OR trusted IS NOT TRUE", name="releases_block_never_trusted"),
    )
    op.create_index("ix_releases_repo", "releases", ["repo"])
    op.create_index("ix_releases_image_digest", "releases", ["image_digest"])
    op.execute(
        """
        CREATE FUNCTION releases_are_kept() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'release % is kept as recorded: it cannot change or be deleted', OLD.decision_id;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER releases_are_kept BEFORE UPDATE OR DELETE ON releases "
        "FOR EACH ROW EXECUTE FUNCTION releases_are_kept()"
    )


KEPT = "SELECT count(*) FROM releases"


def downgrade() -> None:
    kept = op.get_bind().execute(sa.text(KEPT)).scalar_one()
    if kept:
        raise RuntimeError(
            f"{kept} release(s) are kept (table releases), the only copy of their evidence on the platform, "
            "so going below 0006 would lose them. Stay at 0006 or later, or export them first (GET "
            "/api/v1/releases/{digest}/evidence) and go down on a new, empty database; a kept release cannot "
            "be deleted (trigger releases_are_kept). Nothing was changed."
        )
    op.execute("DROP TRIGGER releases_are_kept ON releases")
    op.execute("DROP FUNCTION releases_are_kept()")
    op.drop_index("ix_releases_image_digest", table_name="releases")
    op.drop_index("ix_releases_repo", table_name="releases")
    op.drop_table("releases")
