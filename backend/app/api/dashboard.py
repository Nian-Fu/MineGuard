from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.core.config import get_settings
from app.core.database import get_db
from app.dependencies import get_current_user
from app.models import (
    Camera,
    CameraStatus,
    DeliveryStatus,
    EdgeNode,
    EdgeNodeStatus,
    Event,
    EventStatus,
    EventType,
    NotificationDelivery,
    Person,
    PersonAreaGrant,
    Severity,
    SnapshotLegalHoldJob,
    User,
)
from app.schemas import DashboardSummary
from app.services.metrics import request_latency, summarize_edge_camera_reports
from app.services.operations import (
    WORKER_SERVICE,
    as_utc,
    summarize_media_gateway_health,
    summarize_service_health,
)
from app.services.permissions import area_scope, event_read_for_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(
    db: Session = Depends(get_db), user: User = Depends(get_current_user)
) -> DashboardSummary:
    now = datetime.now(UTC)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    def scalar_count(stmt) -> int:
        return db.scalar(stmt) or 0

    scope = area_scope(user)

    def event_count(*conditions) -> int:
        stmt = select(func.count()).select_from(Event).where(*conditions)
        if scope is not None:
            stmt = stmt.where(Event.camera.has(Camera.area.in_(scope)))
        return scalar_count(stmt)

    event_types = {
        event_type.value: event_count(Event.event_type == event_type.value)
        for event_type in EventType
    }
    severities = {
        severity.value: event_count(Event.severity == severity.value)
        for severity in Severity
    }
    recent_stmt = (
        select(Event)
        .options(joinedload(Event.camera), joinedload(Event.person))
        .order_by(Event.occurred_at.desc())
        .limit(8)
    )
    if scope is not None:
        recent_stmt = recent_stmt.where(Event.camera.has(Camera.area.in_(scope)))
    recent = db.scalars(recent_stmt).unique().all()
    hourly = []
    for offset in range(11, -1, -1):
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=offset)
        end = start + timedelta(hours=1)
        count = event_count(Event.occurred_at >= start, Event.occurred_at < end)
        hourly.append({"time": start.strftime("%H:00"), "count": count})
    camera_count_stmt = select(func.count()).select_from(Camera)
    online_stmt = select(func.count()).select_from(Camera).where(
        Camera.status == CameraStatus.ONLINE.value
    )
    if scope is not None:
        camera_count_stmt = camera_count_stmt.where(Camera.area.in_(scope))
        online_stmt = online_stmt.where(Camera.area.in_(scope))
    total_cameras = scalar_count(camera_count_stmt)
    online = scalar_count(online_stmt)
    latency = request_latency.snapshot()
    delivery_stmt = select(func.count()).select_from(NotificationDelivery).where(
        NotificationDelivery.status.in_(
            [DeliveryStatus.PENDING.value, DeliveryStatus.FAILED.value]
        )
    )
    if scope is not None:
        delivery_stmt = delivery_stmt.where(
            NotificationDelivery.event_id.in_(
                select(Event.id).where(Event.camera.has(Camera.area.in_(scope)))
            )
        )
    delivery_queue_depth = scalar_count(delivery_stmt)
    snapshot_hold_stmt = (
        select(func.count())
        .select_from(SnapshotLegalHoldJob)
        .join(Event, SnapshotLegalHoldJob.event_id == Event.id)
    )
    if scope is not None:
        snapshot_hold_stmt = snapshot_hold_stmt.where(
            Event.camera.has(Camera.area.in_(scope))
        )
    snapshot_legal_hold_pending = scalar_count(snapshot_hold_stmt)
    oldest_delivery_stmt = select(func.min(NotificationDelivery.created_at)).where(
        NotificationDelivery.status.in_(
            [DeliveryStatus.PENDING.value, DeliveryStatus.FAILED.value]
        )
    )
    if scope is not None:
        oldest_delivery_stmt = oldest_delivery_stmt.where(
            NotificationDelivery.event_id.in_(
                select(Event.id).where(Event.camera.has(Camera.area.in_(scope)))
            )
        )
    oldest_delivery = db.scalar(oldest_delivery_stmt)
    oldest_delivery_seconds = (
        max(int((now - as_utc(oldest_delivery)).total_seconds()), 0)
        if oldest_delivery
        else 0
    )
    settings = get_settings()
    worker_health = summarize_service_health(
        db,
        service=WORKER_SERVICE,
        timeout_seconds=settings.worker_heartbeat_timeout_seconds,
        now=now,
    )
    media_gateway_health = summarize_media_gateway_health(
        db,
        timeout_seconds=settings.worker_heartbeat_timeout_seconds,
        now=now,
    )
    allowed_camera_ids = None
    if scope is not None:
        allowed_camera_ids = set(
            db.scalars(select(Camera.id).where(Camera.area.in_(scope))).all()
        )
    edge_reconnects_last_5m = 0
    unhealthy_gpu_nodes = 0
    edge_dead_letter_depth = 0
    edge_outbox_depth = 0
    edge_outbox_capacity = 0
    edge_outbox_max_utilization = 0.0
    visible_edge_nodes = []
    for node in db.scalars(select(EdgeNode).where(EdgeNode.active.is_(True))).all():
        if allowed_camera_ids is not None and not any(
            camera_id in allowed_camera_ids for camera_id in node.camera_ids
        ):
            continue
        visible_edge_nodes.append(node)
        edge_reconnects_last_5m += int(
            node.telemetry.get("stream_reconnects_last_5m", 0)
        ) + int(node.telemetry.get("central_reconnects_last_5m", 0))
        edge_dead_letter_depth += int(node.telemetry.get("dead_letter_depth", 0))
        node_outbox_depth = int(node.telemetry.get("queue_depth", 0)) + int(
            node.telemetry.get("dead_letter_depth", 0)
        )
        node_outbox_capacity = max(
            int(node.telemetry.get("outbox_capacity", 100_000)), 1
        )
        edge_outbox_depth += node_outbox_depth
        edge_outbox_capacity += node_outbox_capacity
        edge_outbox_max_utilization = max(
            edge_outbox_max_utilization,
            node_outbox_depth / node_outbox_capacity,
        )
        if node.telemetry.get("gpu_healthy") is False:
            unhealthy_gpu_nodes += 1
    edge_camera_reports = summarize_edge_camera_reports(
        visible_edge_nodes, allowed_camera_ids
    )
    operational_alerts = []
    if worker_health["status"] == "offline":
        operational_alerts.append(
            {
                "code": "notification_worker_offline",
                "severity": "critical",
                "message": "后台任务服务心跳超时或尚未启动",
            }
        )
    elif worker_health["status"] == "degraded":
        operational_alerts.append(
            {
                "code": "notification_worker_degraded",
                "severity": "high",
                "message": "后台任务服务正在从连续失败中自动恢复",
            }
        )
    if media_gateway_health["status"] == "recovering":
        operational_alerts.append(
            {
                "code": "media_gateway_recovering",
                "severity": "high",
                "message": "媒体网关控制链路中断，后台正在自动重新对账",
            }
        )
    if oldest_delivery_seconds >= settings.notification_queue_stale_seconds:
        operational_alerts.append(
            {
                "code": "notification_queue_stale",
                "severity": "high",
                "message": "最早待投递通知已超过时效阈值",
            }
        )
    if snapshot_legal_hold_pending:
        operational_alerts.append(
            {
                "code": "snapshot_legal_hold_recovering",
                "severity": "high",
                "message": "事件快照法律保留正在等待对象存储自动对账",
            }
        )
    if edge_reconnects_last_5m >= settings.reconnect_storm_threshold:
        operational_alerts.append(
            {
                "code": "edge_reconnect_storm",
                "severity": "high",
                "message": "边缘视频或中心连接在五分钟内频繁重连",
            }
        )
    if edge_camera_reports["degraded"]:
        operational_alerts.append(
            {
                "code": "edge_camera_degraded",
                "severity": "high",
                "message": "边缘节点存在视频或算法子链路降级的摄像头",
            }
        )
    if unhealthy_gpu_nodes:
        operational_alerts.append(
            {
                "code": "edge_gpu_unhealthy",
                "severity": "critical",
                "message": "边缘节点 GPU 遥测不可用或硬件异常",
            }
        )
    if edge_dead_letter_depth:
        operational_alerts.append(
            {
                "code": "edge_events_quarantined",
                "severity": "critical",
                "message": "边缘节点存在被中心永久拒绝且已隔离保留的事件",
            }
        )
    if edge_outbox_max_utilization >= 0.8:
        operational_alerts.append(
            {
                "code": "edge_outbox_capacity",
                "severity": "critical"
                if edge_outbox_max_utilization >= 1
                else "high",
                "message": "边缘事件持久队列接近或已经达到容量上限",
            }
        )
    area_reports: dict[str, list[int]] = {}
    for node in db.scalars(
        select(EdgeNode).where(
            EdgeNode.active.is_(True),
            EdgeNode.status == EdgeNodeStatus.ONLINE.value,
        )
    ).all():
        for area, count in node.telemetry.get("area_counts", {}).items():
            if scope is not None and area not in scope:
                continue
            area_reports.setdefault(area, []).append(int(count))
    area_occupancy = {
        area: max(counts) for area, counts in area_reports.items()
    }
    if any(len(counts) > 1 for counts in area_reports.values()):
        operational_alerts.append(
            {
                "code": "area_counter_conflict",
                "severity": "high",
                "message": "同一区域存在多个在线权威计数源，已停止相加并采用单源最大值",
            }
        )
    person_count_stmt = select(func.count()).select_from(Person)
    if scope is not None:
        person_count_stmt = person_count_stmt.where(
            Person.area_grants.any(PersonAreaGrant.area.in_(scope))
        )
    return DashboardSummary(
        cameras_total=total_cameras,
        cameras_online=online,
        open_events=event_count(
            Event.status.in_([EventStatus.OPEN.value, EventStatus.ACKNOWLEDGED.value])
        ),
        critical_events=event_count(
            Event.severity == Severity.CRITICAL.value,
            Event.status.in_([EventStatus.OPEN.value, EventStatus.ACKNOWLEDGED.value]),
        ),
        persons_total=scalar_count(person_count_stmt),
        today_events=event_count(Event.occurred_at >= today),
        current_person_count=sum(area_occupancy.values()),
        area_occupancy=area_occupancy,
        event_types=event_types,
        severity_distribution=severities,
        recent_events=[event_read_for_user(event, user) for event in recent],
        hourly_trend=hourly,
        operational_alerts=operational_alerts,
        system_health={
            "status": "healthy"
            if (
                (total_cameras == 0 or online / total_cameras >= 0.8)
                and not operational_alerts
            )
            else "degraded",
            "camera_availability": round(online / total_cameras * 100, 1) if total_cameras else 100,
            "api_latency_ms": latency["p95_ms"],
            "api_latency_samples": latency["sample_count"],
            "metric_scope": "current-api-worker",
            "event_queue_depth": delivery_queue_depth,
            "notification_oldest_pending_seconds": oldest_delivery_seconds,
            "snapshot_legal_hold_pending": snapshot_legal_hold_pending,
            "worker_status": worker_health["status"],
            "worker_instances_online": worker_health["instances_online"],
            "worker_instances_degraded": worker_health["instances_degraded"],
            "worker_last_seen_seconds": worker_health["last_seen_seconds"],
            "media_gateway_status": media_gateway_health["status"],
            "media_gateway_reconcile_failures": media_gateway_health[
                "consecutive_failures"
            ],
            "edge_reconnects_last_5m": edge_reconnects_last_5m,
            "edge_camera_reports_degraded": edge_camera_reports["degraded"],
            "edge_camera_error_codes": edge_camera_reports["error_codes"],
            "edge_gpu_unhealthy_nodes": unhealthy_gpu_nodes,
            "edge_dead_letter_depth": edge_dead_letter_depth,
            "edge_outbox_depth": edge_outbox_depth,
            "edge_outbox_capacity": edge_outbox_capacity,
            "edge_outbox_max_utilization": round(
                edge_outbox_max_utilization, 4
            ),
        },
    )
