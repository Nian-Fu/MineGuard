from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies import get_current_user, require_roles
from app.models import AuditLog, Camera, Event, EventStatus, Role, User
from app.schemas import (
    EventCreate,
    EventRead,
    EventStatusUpdate,
    LegalHoldUpdate,
    Page,
    SnapshotAccessGrant,
)
from app.services.audit import write_audit
from app.services.concurrency import enforce_if_match
from app.services.events import event_query, ingest_event_record
from app.services.permissions import (
    area_scope,
    can_access_person,
    event_read_for_user,
    require_area_access,
)
from app.services.realtime import publish_realtime_signal
from app.services.snapshot_legal_holds import (
    SnapshotLegalHoldReconciler,
    queue_snapshot_legal_hold,
)
from app.services.snapshots import (
    SnapshotStorageError,
    get_snapshot_storage,
    snapshot_camera_id,
)

router = APIRouter(prefix="/events", tags=["events"])
EVENT_STATUS_TRANSITIONS = {
    EventStatus.OPEN.value: {
        EventStatus.ACKNOWLEDGED.value,
        EventStatus.RESOLVED.value,
        EventStatus.FALSE_POSITIVE.value,
    },
    EventStatus.ACKNOWLEDGED.value: {
        EventStatus.RESOLVED.value,
        EventStatus.FALSE_POSITIVE.value,
    },
    EventStatus.RESOLVED.value: set(),
    EventStatus.FALSE_POSITIVE.value: set(),
}


@router.get("", response_model=Page)
def list_events(
    page: int = 1,
    page_size: int = 30,
    event_type: str | None = None,
    event_status: str | None = None,
    severity: str | None = None,
    query: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Page:
    stmt, count_stmt = event_query(), select(func.count()).select_from(Event)
    scope = area_scope(user)
    if query and len(query) > 100:
        raise HTTPException(status_code=422, detail="搜索条件不能超过 100 个字符")
    normalized_query = query.strip().lower() if query else ""
    if scope is not None or normalized_query:
        stmt = stmt.join(Event.camera)
        count_stmt = count_stmt.join(Event.camera)
    if scope is not None:
        stmt = stmt.where(Camera.area.in_(scope))
        count_stmt = count_stmt.where(Camera.area.in_(scope))
    if normalized_query:
        condition = or_(
            func.lower(Event.title).contains(normalized_query, autoescape=True),
            func.lower(Camera.name).contains(normalized_query, autoescape=True),
            func.lower(Camera.code).contains(normalized_query, autoescape=True),
            func.lower(Camera.area).contains(normalized_query, autoescape=True),
        )
        stmt, count_stmt = stmt.where(condition), count_stmt.where(condition)
    for condition in [
        Event.event_type == event_type if event_type else None,
        Event.status == event_status if event_status else None,
        Event.severity == severity if severity else None,
    ]:
        if condition is not None:
            stmt, count_stmt = stmt.where(condition), count_stmt.where(condition)
    safe_page, safe_size = max(page, 1), min(max(page_size, 1), 100)
    events = db.scalars(
        stmt.order_by(Event.occurred_at.desc()).offset((safe_page - 1) * safe_size).limit(safe_size)
    ).unique().all()
    return Page(
        items=[event_read_for_user(event, user) for event in events],
        total=db.scalar(count_stmt) or 0,
        page=safe_page,
        page_size=safe_size,
    )


@router.post("", response_model=EventRead, status_code=status.HTTP_201_CREATED)
def ingest_event(
    payload: EventCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key", min_length=8, max_length=160)] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR)),
) -> EventRead:
    camera = db.get(Camera, payload.camera_id)
    if not camera:
        raise HTTPException(status_code=404, detail="摄像头不存在")
    require_area_access(user, camera.area)
    if (
        payload.snapshot_url
        and snapshot_camera_id(payload.snapshot_url) != camera.id
    ):
        raise HTTPException(status_code=422, detail="快照引用与摄像头不匹配")
    if payload.person_id is not None and not can_access_person(db, user, payload.person_id):
        raise HTTPException(status_code=404, detail="人员档案不存在")
    event, created = ingest_event_record(db, payload, idempotency_key)
    if created:
        write_audit(db, user, "event.ingest", "event", event.id, {"type": payload.event_type.value})
    db.commit()
    return event_read_for_user(
        db.scalar(event_query().where(Event.id == event.id)), user
    )


@router.patch("/{event_id}/status", response_model=EventRead)
def update_event_status(
    event_id: int,
    payload: EventStatusUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    user: User = Depends(require_roles(Role.ADMIN, Role.OPERATOR)),
) -> EventRead:
    event = db.scalar(
        select(Event).where(Event.id == event_id).with_for_update()
    )
    if not event:
        raise HTTPException(status_code=404, detail="事件不存在")
    require_area_access(user, event.camera.area)
    requested_status = payload.status.value
    if requested_status == event.status:
        return event_read_for_user(
            db.scalar(event_query().where(Event.id == event.id)), user
        )
    enforce_if_match(event, if_match)
    if requested_status not in EVENT_STATUS_TRANSITIONS.get(event.status, set()):
        raise HTTPException(status_code=409, detail="事件状态只能按处置流程向前迁移")
    event.status = requested_status
    event.acknowledged_by = user.id
    if payload.status in {EventStatus.RESOLVED, EventStatus.FALSE_POSITIVE}:
        event.resolved_at = datetime.now(UTC)
    publish_realtime_signal(
        db, "events", event.id, "status_changed", area=event.camera.area
    )
    write_audit(db, user, "event.status_change", "event", event.id, {"status": requested_status, "note": payload.note}, request)
    db.commit()
    return event_read_for_user(
        db.scalar(event_query().where(Event.id == event.id)), user
    )


@router.patch("/{event_id}/legal-hold", response_model=EventRead)
def update_event_legal_hold(
    event_id: int,
    payload: LegalHoldUpdate,
    request: Request,
    if_match: str | None = Header(default=None, alias="If-Match"),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles(Role.ADMIN)),
) -> EventRead:
    event = db.scalar(select(Event).where(Event.id == event_id).with_for_update())
    if not event:
        raise HTTPException(status_code=404, detail="事件不存在")
    if event.legal_hold != payload.enabled:
        enforce_if_match(event, if_match)
    if event.snapshot_url:
        queue_snapshot_legal_hold(
            db,
            event,
            desired_enabled=payload.enabled,
            requested_by=actor.id,
            reason=payload.reason,
        )
        write_audit(
            db,
            actor,
            "event.legal_hold_requested",
            "event",
            event.id,
            {
                "enabled": payload.enabled,
                "reason": payload.reason,
                "legal_hold": True,
                "reconciliation_pending": True,
            },
            request,
        )
        db.commit()
        result = SnapshotLegalHoldReconciler(
            storage_factory=get_snapshot_storage
        ).reconcile_one(
            db,
            event.id,
            expected_enabled=payload.enabled,
        )
        if result == "retry":
            raise HTTPException(
                status_code=503,
                detail="快照法律保留同步已进入后台自动重试",
                headers={"Retry-After": "5"},
            )
        if result == "superseded":
            raise HTTPException(
                status_code=409,
                detail="法律保留请求已被更新的管理操作替代",
            )
        return event_read_for_user(
            db.scalar(event_query().where(Event.id == event_id)), actor
        )
    if event.legal_hold == payload.enabled:
        return event_read_for_user(
            db.scalar(event_query().where(Event.id == event.id)), actor
        )
    event.legal_hold = payload.enabled
    if payload.enabled:
        db.execute(
            update(AuditLog)
            .where(
                AuditLog.resource_type == "event",
                AuditLog.resource_id == str(event.id),
            )
            .values(legal_hold=True)
        )
    publish_realtime_signal(
        db, "events", event.id, "legal_hold_changed", area=event.camera.area
    )
    write_audit(
        db,
        actor,
        "event.legal_hold",
        "event",
        event.id,
        {"enabled": payload.enabled, "reason": payload.reason, "legal_hold": True},
        request,
    )
    db.commit()
    return event_read_for_user(
        db.scalar(event_query().where(Event.id == event.id)), actor
    )


@router.get("/{event_id}/snapshot-access", response_model=SnapshotAccessGrant)
def create_snapshot_access(
    event_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SnapshotAccessGrant:
    event = db.scalar(event_query().where(Event.id == event_id))
    if not event:
        raise HTTPException(status_code=404, detail="事件不存在")
    require_area_access(user, event.camera.area)
    if not event.snapshot_url:
        raise HTTPException(status_code=404, detail="事件没有快照")
    try:
        return get_snapshot_storage().create_access_grant(event.snapshot_url)
    except SnapshotStorageError as exc:
        raise HTTPException(
            status_code=503,
            detail="快照存储暂时不可用，请稍后重试",
            headers={"Retry-After": "5"},
        ) from exc
