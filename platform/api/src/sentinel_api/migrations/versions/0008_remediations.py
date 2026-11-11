"""Keep each remediation attempt (Remediation attempt v1, tasks A6 and A8), byte for byte.

The remediation loop's report posts one document per attempt (`POST /api/v1/remediations`): the patch
proposal and its verification result. It is kept as the bytes that were sent, named by their sha256, for the
Remediation page and `sentinel_remediation_attempts_total`.

The database is the backstop for what the API checks:
- the bytes hash to their name (`remediations_bytes_match`);
- VERIFIED only when every condition of the verification gate holds (`remediations_verified_gate`, SPEC 9.2);
- an attempt never changes and is never deleted (trigger `remediations_are_kept`).

Going back below 0008 would drop the only copy of those documents, so the downgrade stops, changing nothing,
while any attempt is kept.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "remediations",
        sa.Column("proposal_id", sa.Uuid(), primary_key=True),
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), nullable=False, unique=True),
        sa.Column("repo", sa.String(200), nullable=False),
        sa.Column("strategy", sa.String(40), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(8), nullable=False),
        sa.Column("verdict", sa.String(5), nullable=False),
        sa.Column("build_ok", sa.Boolean(), nullable=False),
        sa.Column("tests_ok", sa.Boolean(), nullable=False),
        sa.Column("target_resolved", sa.Boolean(), nullable=False),
        sa.Column("new_finding_count", sa.Integer(), nullable=False),
        sa.Column("pull_request", sa.Integer(), nullable=True),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("document", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint("sha256 ~ '^[a-f0-9]{64}$'", name="remediations_sha256"),
        sa.CheckConstraint("encode(sha256(document), 'hex') = sha256", name="remediations_bytes_match"),
        sa.CheckConstraint(
            "strategy IN ('deterministic:dependency-bump', 'deterministic:dockerfile', "
            "'deterministic:kubernetes', 'llm:code')",
            name="remediations_strategy",
        ),
        sa.CheckConstraint("outcome IN ('VERIFIED', 'REJECTED', 'FAILED')", name="remediations_outcome"),
        sa.CheckConstraint("verdict IN ('PASS', 'WARN', 'BLOCK')", name="remediations_verdict"),
        sa.CheckConstraint("attempt BETWEEN 1 AND 3", name="remediations_attempt"),
        sa.CheckConstraint(
            "outcome <> 'VERIFIED' OR (build_ok AND tests_ok AND target_resolved AND new_finding_count = 0 "
            "AND verdict <> 'BLOCK')",
            name="remediations_verified_gate",
        ),
    )
    op.create_index("ix_remediations_repo", "remediations", ["repo"])
    op.execute(
        """
        CREATE FUNCTION remediations_are_kept() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'remediation attempt % is kept as recorded: it cannot change or be deleted',
                OLD.proposal_id;
        END
        $$
        """
    )
    op.execute(
        "CREATE TRIGGER remediations_are_kept BEFORE UPDATE OR DELETE ON remediations "
        "FOR EACH ROW EXECUTE FUNCTION remediations_are_kept()"
    )


KEPT = "SELECT count(*) FROM remediations"


def downgrade() -> None:
    kept = op.get_bind().execute(sa.text(KEPT)).scalar_one()
    if kept:
        raise RuntimeError(
            f"{kept} remediation attempt(s) are kept (table remediations), the only copy of what the loop "
            "reported, so going below 0008 would lose them. Stay at 0008 or later, or export them first (GET "
            "/api/v1/remediations/{proposal_id}) and go down on a new, empty database; a kept attempt cannot "
            "be deleted (trigger remediations_are_kept). Nothing was changed."
        )
    op.execute("DROP TRIGGER remediations_are_kept ON remediations")
    op.execute("DROP FUNCTION remediations_are_kept()")
    op.drop_index("ix_remediations_repo", table_name="remediations")
    op.drop_table("remediations")
