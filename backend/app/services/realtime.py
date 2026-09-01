from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models import RealtimeSignal, User

REALTIME_TOPICS = {"events", "cameras", "deliveries", "system"}


def realtime_session_active(user_id: int, auth_version: int) -> bool:
    with SessionLocal() as db:
        return (
            db.scalar(
                select(User.id).where(
                    User.id == user_id,
                    User.active.is_(True),
                    User.auth_version == auth_version,
                )
            )
            is not None
        )


def signal_visible_to_scope(
    signal: dict[str, str | int | None], scope: set[str] | None
) -> bool:
    return scope is None or signal.get("area") in scope


def publish_realtime_signal(
    db: Session,
    topic: str,
    resource_id: int | str | None,
    action: str,
    area: str | None = None,
) -> None:
    if topic not in REALTIME_TOPICS:
        raise ValueError("unsupported realtime topic")
    if not action or len(action) > 40 or not action.replace("_", "").isalnum():
        raise ValueError("invalid realtime action")
    db.add(
        RealtimeSignal(
            topic=topic,
            area=area,
            resource_id=str(resource_id) if resource_id is not None else None,
            action=action,
        )
    )


def latest_realtime_signal_id() -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.max(RealtimeSignal.id))) or 0


def load_realtime_signals(after_id: int, limit: int = 100) -> list[dict[str, str | int | None]]:
    with SessionLocal() as db:
        rows = db.scalars(
            select(RealtimeSignal)
            .where(RealtimeSignal.id > after_id)
            .order_by(RealtimeSignal.id)
            .limit(limit)
        ).all()
        return [
            {
                "id": row.id,
                "topic": row.topic,
                "area": row.area,
                "resource_id": row.resource_id,
                "action": row.action,
                "created_at": row.created_at.isoformat(),
            }
            for row in rows
        ]


def prune_realtime_signals(db: Session, retention_hours: int = 24) -> int:
    cutoff = datetime.now(UTC) - timedelta(hours=retention_hours)
    result = db.execute(delete(RealtimeSignal).where(RealtimeSignal.created_at < cutoff))
    return result.rowcount or 0
