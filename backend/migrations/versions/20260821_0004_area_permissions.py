"""Add user and person area permissions."""

import sqlalchemy as sa
from alembic import op

revision = "20260821_0004"
down_revision = "20260821_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("permitted_areas", sa.JSON(), nullable=True))
    op.create_table(
        "person_area_grants",
        sa.Column(
            "person_id",
            sa.Integer(),
            sa.ForeignKey("persons.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("area", sa.String(100), primary_key=True),
    )
    op.create_index("ix_person_area_grants_area", "person_area_grants", ["area"])

    persons = sa.table(
        "persons",
        sa.column("id", sa.Integer()),
        sa.column("authorized_areas", sa.JSON()),
    )
    grants = sa.table(
        "person_area_grants",
        sa.column("person_id", sa.Integer()),
        sa.column("area", sa.String(100)),
    )
    connection = op.get_bind()
    for row in connection.execute(sa.select(persons.c.id, persons.c.authorized_areas)):
        raw_areas = row.authorized_areas or []
        if not isinstance(raw_areas, list) or any(
            not isinstance(area, str)
            or not area.strip()
            or len(area.strip()) > 100
            for area in raw_areas
        ):
            raise RuntimeError(
                f"person {row.id} contains an invalid authorized_areas value"
            )
        normalized_areas = sorted({area.strip() for area in raw_areas})
        connection.execute(
            persons.update()
            .where(persons.c.id == row.id)
            .values(authorized_areas=normalized_areas)
        )
        for area in normalized_areas:
            connection.execute(grants.insert().values(person_id=row.id, area=area))


def downgrade() -> None:
    op.drop_table("person_area_grants")
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("permitted_areas")
