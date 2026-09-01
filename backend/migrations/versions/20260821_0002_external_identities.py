"""Add external identity bindings."""

import sqlalchemy as sa
from alembic import op

revision = "20260821_0002"
down_revision = "20260821_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column(
                "identity_provider",
                sa.String(64),
                nullable=False,
                server_default="local",
            )
        )
        batch_op.add_column(
            sa.Column("external_subject", sa.String(255), nullable=True)
        )
        batch_op.create_index("ix_users_identity_provider", ["identity_provider"])
        batch_op.create_unique_constraint(
            "uq_user_external_identity",
            ["identity_provider", "external_subject"],
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("uq_user_external_identity", type_="unique")
        batch_op.drop_index("ix_users_identity_provider")
        batch_op.drop_column("external_subject")
        batch_op.drop_column("identity_provider")
