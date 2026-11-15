"""The worker's own role (`sentinel_worker`, task B5c, #111 review): only what its jobs need.

The worker feeds the model a finding that a scanner wrote, so it gets the least it needs:
- `SELECT` on `runs` and `findings` (the finding, and the run's other findings, for context);
- `SELECT` on `explain_requests`, and `UPDATE` on its state only (`status`, `reason`, `explanation_sha256`,
  `updated_at`): claim a queued request and record its outcome, never move it to another finding or run;
- `INSERT` on `explanations` (record one), and `SELECT` on its `seq` and `created_at` only: the insert reads
  back these two generated columns. It cannot read an explanation's document.
Nothing else: no decision, waiver, release, remediation or correlation, no delete, no schema change.

The role is created without a login and without a password: a migration holds no secret.
`sentinel-api migrate` gives it a login with `SENTINEL_WORKER_DATABASE_PASSWORD` (`migrate.py`). A role
belongs to the server, not to one database, so it is created only if it is not there yet; going below 0011
takes this database's rights back and leaves the role, which another database may use.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

ROLE = "sentinel_worker"
GRANTS = (
    ("SELECT", "runs"),
    ("SELECT", "findings"),
    # Claim and finish change a request's state only. Its finding and run stay the API's: the trigger
    # `explanations_are_kept` binds an explanation to its request's finding and run, so the worker must not
    # be able to point a request at another finding before it records an explanation (#140 review).
    ("SELECT, UPDATE (status, reason, explanation_sha256, updated_at)", "explain_requests"),
    ("SELECT (seq, created_at), INSERT", "explanations"),
)


def upgrade() -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{ROLE}') THEN
                CREATE ROLE {ROLE} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
        END
        $$
        """
    )
    op.execute(f"REVOKE ALL ON SCHEMA public FROM {ROLE}")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {ROLE}")
    for privileges, table in GRANTS:
        op.execute(f"GRANT {privileges} ON {table} TO {ROLE}")


def downgrade() -> None:
    for _, table in GRANTS:
        op.execute(f"REVOKE ALL ON {table} FROM {ROLE}")
    op.execute(f"REVOKE ALL ON SCHEMA public FROM {ROLE}")
