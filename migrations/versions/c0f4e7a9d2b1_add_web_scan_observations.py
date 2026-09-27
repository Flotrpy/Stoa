"""add web scan observations

Revision ID: c0f4e7a9d2b1
Revises: ad7e21b9d004
Create Date: 2026-09-27 15:45:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c0f4e7a9d2b1"
down_revision: str | None = "ad7e21b9d004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "web_scan_observations",
        sa.Column("team_id", sa.Uuid(), nullable=False),
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=80), nullable=False),
        sa.Column("title", sa.String(length=240), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("url", sa.String(length=512), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_web_scan_job", "web_scan_observations", ["job_id"])


def downgrade() -> None:
    op.drop_index("ix_web_scan_job", table_name="web_scan_observations")
    op.drop_table("web_scan_observations")
