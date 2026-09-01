import sqlalchemy as sa
from alembic import context, op

from app.core.config import get_settings
from app.services.camera_urls import camera_url_cipher_from_settings

revision = "20260821_0009"
down_revision = "20260821_0008"
branch_labels = None
depends_on = None


camera_table = sa.table(
    "cameras",
    sa.column("id", sa.Integer),
    sa.column("code", sa.String),
    sa.column("stream_url", sa.String),
    sa.column("stream_url_ciphertext", sa.LargeBinary),
    sa.column("stream_url_nonce", sa.LargeBinary),
    sa.column("stream_url_key_version", sa.String),
)


def _associated_data(code: str) -> bytes:
    return f"mineguard:camera-url:{code}".encode("utf-8")


def upgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("camera URL encryption migration requires online mode")
    op.add_column(
        "cameras", sa.Column("stream_url_ciphertext", sa.LargeBinary(), nullable=True)
    )
    op.add_column(
        "cameras", sa.Column("stream_url_nonce", sa.LargeBinary(12), nullable=True)
    )
    op.add_column(
        "cameras", sa.Column("stream_url_key_version", sa.String(50), nullable=True)
    )
    with op.batch_alter_table("cameras") as batch_op:
        batch_op.alter_column(
            "stream_url", existing_type=sa.String(500), nullable=True
        )

    cipher = camera_url_cipher_from_settings(get_settings())
    if cipher is not None:
        connection = op.get_bind()
        rows = list(
            connection.execute(
                sa.select(
                    camera_table.c.id,
                    camera_table.c.code,
                    camera_table.c.stream_url,
                ).where(camera_table.c.stream_url.is_not(None))
            ).mappings()
        )
        for row in rows:
            encrypted = cipher.encrypt(
                row["stream_url"], _associated_data(row["code"])
            )
            connection.execute(
                camera_table.update()
                .where(camera_table.c.id == row["id"])
                .values(
                    stream_url=None,
                    stream_url_ciphertext=encrypted.ciphertext,
                    stream_url_nonce=encrypted.nonce,
                    stream_url_key_version=encrypted.key_version,
                )
            )
    with op.batch_alter_table("cameras") as batch_op:
        batch_op.create_check_constraint(
            "ck_cameras_stream_url_storage",
            "(stream_url IS NOT NULL AND stream_url_ciphertext IS NULL "
            "AND stream_url_nonce IS NULL AND stream_url_key_version IS NULL) OR "
            "(stream_url IS NULL AND stream_url_ciphertext IS NOT NULL "
            "AND stream_url_nonce IS NOT NULL AND stream_url_key_version IS NOT NULL)",
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("camera URL decryption migration requires online mode")
    connection = op.get_bind()
    encrypted_rows = list(
        connection.execute(
            sa.select(
                camera_table.c.id,
                camera_table.c.code,
                camera_table.c.stream_url_ciphertext,
                camera_table.c.stream_url_nonce,
                camera_table.c.stream_url_key_version,
            ).where(camera_table.c.stream_url_ciphertext.is_not(None))
        ).mappings()
    )
    if encrypted_rows:
        cipher = camera_url_cipher_from_settings(get_settings())
        if cipher is None:
            raise RuntimeError("camera URL key is required to downgrade encrypted rows")
        for row in encrypted_rows:
            plaintext = cipher.decrypt(
                row["stream_url_ciphertext"],
                row["stream_url_nonce"],
                row["stream_url_key_version"],
                _associated_data(row["code"]),
            )
            connection.execute(
                camera_table.update()
                .where(camera_table.c.id == row["id"])
                .values(
                    stream_url=plaintext,
                    stream_url_ciphertext=None,
                    stream_url_nonce=None,
                    stream_url_key_version=None,
                )
            )
    with op.batch_alter_table("cameras") as batch_op:
        batch_op.drop_constraint(
            "ck_cameras_stream_url_storage", type_="check"
        )
        batch_op.drop_column("stream_url_key_version")
        batch_op.drop_column("stream_url_nonce")
        batch_op.drop_column("stream_url_ciphertext")
        batch_op.alter_column(
            "stream_url", existing_type=sa.String(500), nullable=False
        )
