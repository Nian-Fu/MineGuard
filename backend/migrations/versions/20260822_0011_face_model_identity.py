import sqlalchemy as sa
from alembic import op

revision = "20260822_0011"
down_revision = "20260822_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "face_templates",
        sa.Column("model_sha256", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_face_templates_model_identity",
        "face_templates",
        ["model_version", "model_sha256"],
    )
    # Existing ciphertext did not bind an artifact digest. Keep it for audit,
    # but fail closed until the person is re-enrolled with an approved model.
    op.execute("UPDATE face_templates SET active = false")
    op.execute("UPDATE persons SET face_enrolled = false")


def downgrade() -> None:
    # Templates created after this revision bind the artifact digest into
    # AES-GCM AAD. Older application code cannot verify that identity after
    # the column is removed, so fail closed until every person is re-enrolled.
    op.execute("UPDATE face_templates SET active = false")
    op.execute("UPDATE persons SET face_enrolled = false")
    op.drop_index(
        "ix_face_templates_model_identity",
        table_name="face_templates",
    )
    op.drop_column("face_templates", "model_sha256")
