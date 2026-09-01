"""Add cross-instance service heartbeats."""

import sqlalchemy as sa
from alembic import op

revision = "20260821_0006"
down_revision = "20260821_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_heartbeats",
        sa.Column("instance_id", sa.String(64), primary_key=True),
        sa.Column("service", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
    )
    op.create_index("ix_service_heartbeats_service", "service_heartbeats", ["service"])
    op.create_index("ix_service_heartbeats_status", "service_heartbeats", ["status"])
    op.create_index(
        "ix_service_heartbeats_last_heartbeat_at",
        "service_heartbeats",
        ["last_heartbeat_at"],
    )


def downgrade() -> None:
    op.drop_table("service_heartbeats")
