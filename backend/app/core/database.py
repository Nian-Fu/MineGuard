from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()


def database_engine_options(config) -> dict:
    if config.database_url.startswith("sqlite"):
        return {
            "pool_pre_ping": True,
            "connect_args": {"check_same_thread": False},
        }
    return {
        "pool_pre_ping": True,
        "pool_timeout": config.database_pool_timeout_seconds,
        "pool_recycle": config.database_pool_recycle_seconds,
        "connect_args": {
            "connect_timeout": config.database_connect_timeout_seconds,
        },
    }


engine = create_engine(settings.database_url, **database_engine_options(settings))
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
