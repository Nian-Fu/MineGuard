import sqlalchemy as sa
from alembic import op

revision = "20260822_0010"
down_revision = "20260821_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "snapshot_legal_hold_jobs",
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("desired_enabled", sa.Boolean(), nullable=False),
        sa.Column("requested_by", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["requested_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index(
        "ix_snapshot_legal_hold_jobs_next_attempt_at",
        "snapshot_legal_hold_jobs",
        ["next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_snapshot_legal_hold_jobs_next_attempt_at",
        table_name="snapshot_legal_hold_jobs",
    )
    op.drop_table("snapshot_legal_hold_jobs")
