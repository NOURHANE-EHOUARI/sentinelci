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

# Each statement is written out: the role and the grants are constants, and SentinelCI's own SAST refuses SQL
# built from strings (`python-sql-built-from-strings`, the self-gate of 16 November), whatever the values.
UPGRADE = (
    """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sentinel_worker') THEN
                CREATE ROLE sentinel_worker NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
            END IF;
        END
        $$
        """,
    "REVOKE ALL ON SCHEMA public FROM sentinel_worker",
    "GRANT USAGE ON SCHEMA public TO sentinel_worker",
    "GRANT SELECT ON runs TO sentinel_worker",
    "GRANT SELECT ON findings TO sentinel_worker",
    # Claim and finish change a request's state only. Its finding and run stay the API's: the trigger
    # `explanations_are_kept` binds an explanation to its request's finding and run, so the worker must not
    # be able to point a request at another finding before it records an explanation (#140 review).
    "GRANT SELECT, UPDATE (status, reason, explanation_sha256, updated_at) ON explain_requests"
    " TO sentinel_worker",
    "GRANT SELECT (seq, created_at), INSERT ON explanations TO sentinel_worker",
)
DOWNGRADE = (
    "REVOKE ALL ON runs FROM sentinel_worker",
    "REVOKE ALL ON findings FROM sentinel_worker",
    "REVOKE ALL ON explain_requests FROM sentinel_worker",
    "REVOKE ALL ON explanations FROM sentinel_worker",
    "REVOKE ALL ON SCHEMA public FROM sentinel_worker",
)


def upgrade() -> None:
    for statement in UPGRADE:
        op.execute(statement)


def downgrade() -> None:
    for statement in DOWNGRADE:
        op.execute(statement)
