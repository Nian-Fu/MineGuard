from alembic import command
from alembic.config import Config
from sqlalchemy import text

from app.core.database import SessionLocal, engine
from app.seed import seed_database

MIGRATION_LOCK_ID = 1_296_648_001


def main() -> None:
    config = Config("alembic.ini")
    with engine.connect() as connection:
        is_postgresql = connection.dialect.name == "postgresql"
        if is_postgresql:
            connection.execute(
                text("SELECT pg_advisory_lock(:lock_id)"),
                {"lock_id": MIGRATION_LOCK_ID},
            )
            connection.commit()
        try:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
            with SessionLocal() as db:
                seed_database(db)
        finally:
            if is_postgresql:
                connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": MIGRATION_LOCK_ID},
                )
                connection.commit()


if __name__ == "__main__":
    main()
