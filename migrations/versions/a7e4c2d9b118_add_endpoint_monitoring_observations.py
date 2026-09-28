"""add endpoint monitoring observations

Revision ID: a7e4c2d9b118
Revises: f8d2c1b0a774
Create Date: 2026-09-28 10:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a7e4c2d9b118"
down_revision: str | None = "f8d2c1b0a774"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "endpoint_monitoring_observations",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("baseline_id", sa.String(length=128), nullable=False),
        sa.Column("observation_type", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("subject", sa.String(length=1024), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("chain_hash", sa.String(length=64), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_endpoint_monitoring_job", "endpoint_monitoring_observations", ["job_id"])


def downgrade() -> None:
    op.drop_index("ix_endpoint_monitoring_job", table_name="endpoint_monitoring_observations")
    op.drop_table("endpoint_monitoring_observations")
