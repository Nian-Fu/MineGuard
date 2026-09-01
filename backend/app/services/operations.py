from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import Session

from app.models import (
    AuditLog,
    DeliveryStatus,
    Event,
    EventStatus,
    FaceTemplate,
    NotificationDelivery,
    RefreshSession,
    SnapshotLegalHoldJob,
    ServiceHeartbeat,
)

WORKER_SERVICE = "notification-worker"


def as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def record_service_heartbeat(
    db: Session,
    *,
    instance_id: str,
    service: str,
    started_at: datetime,
    consecutive_failures: int = 0,
    detail: dict | None = None,
) -> ServiceHeartbeat:
    now = datetime.now(UTC)
    heartbeat = db.get(ServiceHeartbeat, instance_id)
    if heartbeat is None:
        heartbeat = ServiceHeartbeat(
            instance_id=instance_id,
            service=service,
            status="running" if consecutive_failures == 0 else "degraded",
            started_at=started_at,
            last_heartbeat_at=now,
            last_success_at=now if consecutive_failures == 0 else None,
            consecutive_failures=consecutive_failures,
            detail=detail or {},
        )
        db.add(heartbeat)
        return heartbeat

    heartbeat.status = "running" if consecutive_failures == 0 else "degraded"
    heartbeat.last_heartbeat_at = now
    heartbeat.consecutive_failures = consecutive_failures
    heartbeat.detail = detail or {}
    if consecutive_failures == 0:
        heartbeat.last_success_at = now
    return heartbeat


def summarize_service_health(
    db: Session,
    *,
    service: str,
    timeout_seconds: int,
    now: datetime | None = None,
) -> dict[str, int | str]:
    checked_at = now or datetime.now(UTC)
    cutoff = checked_at - timedelta(seconds=timeout_seconds)
    rows = db.scalars(
        select(ServiceHeartbeat).where(ServiceHeartbeat.service == service)
    ).all()
    online = [row for row in rows if as_utc(row.last_heartbeat_at) >= cutoff]
    degraded = [
        row
        for row in online
        if row.status == "degraded" or row.consecutive_failures > 0
    ]
    latest = max((as_utc(row.last_heartbeat_at) for row in rows), default=None)
    if not online:
        status = "offline"
    elif degraded:
        status = "degraded"
    else:
        status = "online"
    return {
        "status": status,
        "instances_online": len(online),
        "instances_degraded": len(degraded),
        "last_seen_seconds": max(int((checked_at - latest).total_seconds()), 0)
        if latest
        else -1,
    }


def summarize_media_gateway_health(
    db: Session,
    *,
    timeout_seconds: int,
    now: datetime | None = None,
) -> dict[str, int | str]:
    checked_at = now or datetime.now(UTC)
    cutoff = checked_at - timedelta(seconds=timeout_seconds)
    rows = db.scalars(
        select(ServiceHeartbeat).where(
            ServiceHeartbeat.service == WORKER_SERVICE,
            ServiceHeartbeat.last_heartbeat_at >= cutoff,
        )
    ).all()
    details = [
        row.detail.get("media_gateway", {})
        for row in rows
        if isinstance(row.detail, dict)
        and isinstance(row.detail.get("media_gateway"), dict)
    ]
    configured = [detail for detail in details if detail.get("configured") is True]
    if any(detail.get("status") == "online" for detail in configured):
        status = "online"
    elif configured:
        status = "recovering"
    else:
        status = "disabled"
    return {
        "status": status,
        "instances_configured": len(configured),
        "consecutive_failures": max(
            (
                int(detail.get("consecutive_failures", 0))
                for detail in configured
                if isinstance(detail.get("consecutive_failures", 0), int)
                and not isinstance(detail.get("consecutive_failures", 0), bool)
            ),
            default=0,
        ),
    }


def prune_service_heartbeats(db: Session, retention_days: int = 7) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    result = db.execute(
        delete(ServiceHeartbeat).where(ServiceHeartbeat.last_heartbeat_at < cutoff)
    )
    return result.rowcount or 0


def _delete_ids(db: Session, model, ids: list[int]) -> int:
    if not ids:
        return 0
    result = db.execute(delete(model).where(model.id.in_(ids)))
    return result.rowcount or 0


def prune_data_lifecycle(
    db: Session,
    settings,
    *,
    now: datetime | None = None,
) -> dict[str, int]:
    """Prune bounded batches without deleting active, retrying, or held records."""
    checked_at = now or datetime.now(UTC)
    limit = settings.lifecycle_cleanup_batch_size
    counts: dict[str, int] = {}

    session_cutoff = checked_at - timedelta(
        days=settings.refresh_session_retention_days
    )
    session_ids = list(
        db.scalars(
            select(RefreshSession.id)
            .where(
                or_(
                    RefreshSession.expires_at < session_cutoff,
                    RefreshSession.revoked_at < session_cutoff,
                )
            )
            .order_by(RefreshSession.id)
            .limit(limit)
        )
    )
    counts["refresh_sessions"] = _delete_ids(db, RefreshSession, session_ids)

    delivery_cutoff = checked_at - timedelta(
        days=settings.notification_delivery_retention_days
    )
    delivery_candidates = db.scalars(
        select(NotificationDelivery)
        .join(Event, NotificationDelivery.event_id == Event.id)
        .where(
            NotificationDelivery.status == DeliveryStatus.SENT.value,
            or_(
                NotificationDelivery.sent_at < delivery_cutoff,
                and_(
                    NotificationDelivery.sent_at.is_(None),
                    NotificationDelivery.created_at < delivery_cutoff,
                ),
            ),
            Event.legal_hold.is_(False),
        )
        .order_by(NotificationDelivery.id)
        .limit(limit)
    ).all()
    counts["notification_deliveries"] = _delete_ids(
        db,
        NotificationDelivery,
        [item.id for item in delivery_candidates],
    )

    if settings.inactive_face_template_retention_days:
        face_cutoff = checked_at - timedelta(
            days=settings.inactive_face_template_retention_days
        )
        face_ids = list(
            db.scalars(
                select(FaceTemplate.id)
                .where(
                    FaceTemplate.active.is_(False),
                    FaceTemplate.legal_hold.is_(False),
                    FaceTemplate.created_at < face_cutoff,
                )
                .order_by(FaceTemplate.id)
                .limit(limit)
            )
        )
        counts["face_templates"] = _delete_ids(db, FaceTemplate, face_ids)
    else:
        counts["face_templates"] = 0

    event_cutoff = checked_at - timedelta(days=settings.closed_event_retention_days)
    event_candidates = db.scalars(
        select(Event)
        .where(
            Event.status.in_(
                [EventStatus.RESOLVED.value, EventStatus.FALSE_POSITIVE.value]
            ),
            Event.occurred_at < event_cutoff,
            Event.legal_hold.is_(False),
            ~select(SnapshotLegalHoldJob.event_id)
            .where(SnapshotLegalHoldJob.event_id == Event.id)
            .exists(),
        )
        .order_by(Event.id)
        .limit(limit)
    ).all()
    candidate_event_ids = {event.id for event in event_candidates}
    referenced_event_ids = set(
        db.scalars(
            select(NotificationDelivery.event_id).where(
                NotificationDelivery.event_id.in_(candidate_event_ids)
            )
        )
    )
    counts["events"] = _delete_ids(
        db, Event, sorted(candidate_event_ids - referenced_event_ids)
    )

    audit_cutoff = checked_at - timedelta(days=settings.audit_log_retention_days)
    audit_candidates = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.created_at < audit_cutoff,
            AuditLog.legal_hold.is_(False),
        )
        .order_by(AuditLog.id)
        .limit(limit)
    ).all()
    referenced_ids: set[int] = set()
    for audit in audit_candidates:
        if audit.resource_type != "event" or not audit.resource_id:
            continue
        try:
            referenced_ids.add(int(audit.resource_id))
        except ValueError:
            continue
    held_audit_event_ids = {
        event.id
        for event in db.scalars(
            select(Event).where(Event.id.in_(referenced_ids))
        ).all()
        if event.legal_hold
    }
    audit_ids = []
    for audit in audit_candidates:
        if audit.resource_type == "event" and audit.resource_id:
            try:
                if int(audit.resource_id) in held_audit_event_ids:
                    continue
            except ValueError:
                pass
        audit_ids.append(audit.id)
    counts["audit_logs"] = _delete_ids(db, AuditLog, audit_ids)
    return counts
