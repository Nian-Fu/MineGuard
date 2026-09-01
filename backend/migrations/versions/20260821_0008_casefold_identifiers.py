import sqlalchemy as sa
from alembic import op

revision = "20260821_0008"
down_revision = "20260821_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table_name, column_name, index_name in (
        ("users", "username", "uq_users_username_lower"),
        ("persons", "employee_no", "uq_persons_employee_no_lower"),
        ("edge_nodes", "code", "uq_edge_nodes_code_lower"),
        ("alert_rules", "name", "uq_alert_rules_name_lower"),
    ):
        op.create_index(
            index_name,
            table_name,
            [sa.text(f"lower({column_name})")],
            unique=True,
        )


def downgrade() -> None:
    for table_name, index_name in (
        ("alert_rules", "uq_alert_rules_name_lower"),
        ("edge_nodes", "uq_edge_nodes_code_lower"),
        ("persons", "uq_persons_employee_no_lower"),
        ("users", "uq_users_username_lower"),
    ):
        op.drop_index(index_name, table_name=table_name)
