from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.models import Camera, Event, Person
from app.schemas import EventCreate
from app.services.notifications import create_notification_deliveries
from app.services.realtime import publish_realtime_signal


def event_query():
    return select(Event).options(joinedload(Event.camera), joinedload(Event.person))


def ingest_event_record(
    db: Session,
    payload: EventCreate,
    idempotency_key: str | None,
    *,
    idempotency_ignored_metadata_keys: set[str] | None = None,
    idempotency_conflict_status: int = 409,
) -> tuple[Event, bool]:
    camera = db.get(Camera, payload.camera_id)
    if not camera:
        raise HTTPException(status_code=404, detail="摄像头不存在")
    if payload.person_id is not None and not db.get(Person, payload.person_id):
        raise HTTPException(status_code=404, detail="人员档案不存在")
    if idempotency_key:
        existing = db.scalar(event_query().where(Event.idempotency_key == idempotency_key))
        if existing:
            return validate_idempotent_event(
                existing,
                payload,
                idempotency_ignored_metadata_keys,
                idempotency_conflict_status,
            ), False
    values = payload.model_dump()
    values["event_type"] = payload.event_type.value
    values["severity"] = payload.severity.value
    values["occurred_at"] = payload.occurred_at or datetime.now(UTC)
    event = Event(**values, idempotency_key=idempotency_key)
    if idempotency_key:
        try:
            with db.begin_nested():
                db.add(event)
                db.flush()
        except IntegrityError:
            existing = db.scalar(event_query().where(Event.idempotency_key == idempotency_key))
            if existing:
                return validate_idempotent_event(
                    existing,
                    payload,
                    idempotency_ignored_metadata_keys,
                    idempotency_conflict_status,
                ), False
            raise
    else:
        db.add(event)
        db.flush()
    create_notification_deliveries(db, event, camera.area)
    publish_realtime_signal(db, "events", event.id, "created", area=camera.area)
    return event, True


def validate_idempotent_event(
    existing: Event,
    payload: EventCreate,
    ignored_metadata_keys: set[str] | None = None,
    conflict_status: int = 409,
) -> Event:
    ignored = ignored_metadata_keys or set()
    existing_metadata = {
        key: value
        for key, value in (existing.metadata_json or {}).items()
        if key not in ignored
    }
    payload_metadata = {
        key: value
        for key, value in payload.metadata_json.items()
        if key not in ignored
    }
    occurred_at_matches = True
    if payload.occurred_at is not None:
        existing_occurred_at = existing.occurred_at
        if existing_occurred_at.tzinfo is None:
            existing_occurred_at = existing_occurred_at.replace(tzinfo=UTC)
        payload_occurred_at = payload.occurred_at
        if payload_occurred_at.tzinfo is None:
            payload_occurred_at = payload_occurred_at.replace(tzinfo=UTC)
        occurred_at_matches = (
            existing_occurred_at.astimezone(UTC)
            == payload_occurred_at.astimezone(UTC)
        )
    if not (
        existing.camera_id == payload.camera_id
        and existing.event_type == payload.event_type.value
        and existing.severity == payload.severity.value
        and existing.person_id == payload.person_id
        and existing.title == payload.title
        and existing.description == payload.description
        and existing.confidence == payload.confidence
        and existing.snapshot_url == payload.snapshot_url
        and existing_metadata == payload_metadata
        and occurred_at_matches
    ):
        raise HTTPException(
            status_code=conflict_status,
            detail="幂等键载荷与原始事件不一致",
        )
    return existing
