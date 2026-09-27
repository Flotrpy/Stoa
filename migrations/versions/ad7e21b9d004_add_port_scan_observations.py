"""add port scan observations

Revision ID: ad7e21b9d004
Revises: 696006213af0
Create Date: 2026-09-27 14:40:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "ad7e21b9d004"
down_revision: str | None = "696006213af0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "port_scan_observations",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("service", sa.String(length=80), nullable=True),
        sa.Column("banner", sa.String(length=256), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_port_scan_job_port", "port_scan_observations", ["job_id", "port"], unique=True
    )


def downgrade() -> None:
    op.drop_index("uq_port_scan_job_port", table_name="port_scan_observations")
    op.drop_table("port_scan_observations")
