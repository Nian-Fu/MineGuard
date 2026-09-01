"""Add durable cross-instance realtime signals."""

import sqlalchemy as sa
from alembic import op

revision = "20260821_0003"
down_revision = "20260821_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "realtime_signals",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("topic", sa.String(40), nullable=False),
        sa.Column("resource_id", sa.String(64)),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_realtime_signals_topic", "realtime_signals", ["topic"])
    op.create_index("ix_realtime_signals_created_at", "realtime_signals", ["created_at"])


def downgrade() -> None:
    op.drop_table("realtime_signals")
