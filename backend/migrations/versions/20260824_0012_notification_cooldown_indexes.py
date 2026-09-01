from alembic import op

revision = "20260824_0012"
down_revision = "20260822_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_events_notification_cooldown_scope",
        "events",
        ["camera_id", "event_type", "occurred_at"],
    )
    op.create_index(
        "ix_notification_deliveries_cooldown_scope",
        "notification_deliveries",
        ["rule_id", "channel", "event_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_notification_deliveries_cooldown_scope",
        table_name="notification_deliveries",
    )
    op.drop_index(
        "ix_events_notification_cooldown_scope",
        table_name="events",
    )
