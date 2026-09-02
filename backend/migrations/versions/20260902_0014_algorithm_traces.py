from alembic import op
import sqlalchemy as sa

revision = "20260902_0014"
down_revision = "20260902_0013"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table("algorithm_traces", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("node_id", sa.Integer(), nullable=False), sa.Column("camera_id", sa.Integer(), nullable=False), sa.Column("algorithm_type", sa.String(length=50), nullable=False), sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("frames", sa.JSON(), nullable=False))
    op.create_index("ix_algorithm_traces_camera_id", "algorithm_traces", ["camera_id"])
    op.create_index("ix_algorithm_traces_occurred_at", "algorithm_traces", ["occurred_at"])

def downgrade() -> None:
    op.drop_index("ix_algorithm_traces_occurred_at", table_name="algorithm_traces")
    op.drop_index("ix_algorithm_traces_camera_id", table_name="algorithm_traces")
    op.drop_table("algorithm_traces")
