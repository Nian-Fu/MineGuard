from alembic import op
import sqlalchemy as sa

revision = "20260902_0013"
down_revision = "20260824_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_configurations",
        sa.Column("key", sa.String(length=80), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("system_configurations")
