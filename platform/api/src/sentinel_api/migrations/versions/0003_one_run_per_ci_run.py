"""One run per CI run (#50 review): `repo`, `commit`, `context` and `ci_run_id` are unique when it is set.

A re-run of the upload step names the same CI run, and `POST /runs` answers it 409 with the existing run, so
the findings are never recorded twice. The unique index is what decides between two concurrent requests.

A database that already holds a CI run twice cannot take the index. The migration then stops and says so,
without touching anything: which copy to keep is a decision about evidence, so it is left to a person.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

DUPLICATES = """
    SELECT count(*) FROM (
        SELECT 1 FROM runs WHERE ci_run_id IS NOT NULL
        GROUP BY repo, commit, context, ci_run_id HAVING count(*) > 1
    ) AS twice
"""


def upgrade() -> None:
    twice = op.get_bind().execute(sa.text(DUPLICATES)).scalar_one()
    if twice:
        raise RuntimeError(
            f"{twice} CI run(s) are recorded more than once (same repo, commit, context and ci_run_id), so "
            "the unique index runs_ci_run cannot be created. Keep one run of each and delete the others "
            "(a run whose findings are recorded is protected by the trigger runs_keep_recorded_evidence), "
            "or start from an empty database. Nothing was changed."
        )
    op.create_index(
        "runs_ci_run",
        "runs",
        ["repo", "commit", "context", "ci_run_id"],
        unique=True,
        postgresql_where=sa.text("ci_run_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("runs_ci_run", table_name="runs")
