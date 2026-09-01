import sqlalchemy as sa
from alembic import op

revision = "20260821_0007"
down_revision = "20260821_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "events",
        sa.Column(
            "legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.create_index("ix_events_legal_hold", "events", ["legal_hold"])
    op.add_column(
        "face_templates",
        sa.Column(
            "legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.create_index(
        "ix_face_templates_legal_hold", "face_templates", ["legal_hold"]
    )
    op.add_column(
        "audit_logs",
        sa.Column(
            "legal_hold", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.create_index("ix_audit_logs_legal_hold", "audit_logs", ["legal_hold"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_legal_hold", table_name="audit_logs")
    op.drop_column("audit_logs", "legal_hold")
    op.drop_index("ix_face_templates_legal_hold", table_name="face_templates")
    op.drop_column("face_templates", "legal_hold")
    op.drop_index("ix_events_legal_hold", table_name="events")
    op.drop_column("events", "legal_hold")
