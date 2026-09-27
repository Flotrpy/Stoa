"""add firewall simulation observations

Revision ID: f8d2c1b0a774
Revises: c0f4e7a9d2b1
Create Date: 2026-09-27 16:10:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "f8d2c1b0a774"
down_revision: str | None = "c0f4e7a9d2b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "firewall_simulation_observations",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("packet", sa.JSON(), nullable=False),
        sa.Column("action", sa.String(length=24), nullable=False),
        sa.Column("matched_rule", sa.String(length=160), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_firewall_simulation_job", "firewall_simulation_observations", ["job_id"])


def downgrade() -> None:
    op.drop_index("ix_firewall_simulation_job", table_name="firewall_simulation_observations")
    op.drop_table("firewall_simulation_observations")
