"""Add area labels to realtime signals."""

import sqlalchemy as sa
from alembic import op

revision = "20260821_0005"
down_revision = "20260821_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("realtime_signals") as batch_op:
        batch_op.add_column(sa.Column("area", sa.String(100), nullable=True))
        batch_op.create_index("ix_realtime_signals_area", ["area"])


def downgrade() -> None:
    with op.batch_alter_table("realtime_signals") as batch_op:
        batch_op.drop_index("ix_realtime_signals_area")
        batch_op.drop_column("area")
