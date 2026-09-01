from collections import deque
from datetime import UTC, datetime
from math import ceil
from threading import Lock

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    Camera,
    CameraStatus,
    DeliveryStatus,
    EdgeNode,
    EdgeNodeStatus,
    NotificationDelivery,
    SnapshotLegalHoldJob,
)
from app.services.operations import (
    WORKER_SERVICE,
    as_utc,
    summarize_media_gateway_health,
    summarize_service_health,
)


class RequestLatencyTracker:
    def __init__(self, capacity: int = 2000) -> None:
        self._samples: deque[float] = deque(maxlen=capacity)
        self._lock = Lock()

    def observe(self, milliseconds: float) -> None:
        with self._lock:
            self._samples.append(milliseconds)

    def snapshot(self) -> dict[str, float | int]:
        with self._lock:
            values = sorted(self._samples)
        if not values:
            return {"sample_count": 0, "p50_ms": 0.0, "p95_ms": 0.0}
        return {
            "sample_count": len(values),
            "p50_ms": round(self._percentile(values, 0.50), 1),
            "p95_ms": round(self._percentile(values, 0.95), 1),
        }

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        index = min(max(ceil(len(values) * percentile) - 1, 0), len(values) - 1)
        return values[index]


request_latency = RequestLatencyTracker()


def summarize_edge_camera_reports(
    nodes: list[EdgeNode], allowed_camera_ids: set[int] | None = None
) -> dict[str, int]:
    degraded = 0
    error_codes = 0
    for node in nodes:
        reports = node.telemetry.get("cameras", [])
        if not isinstance(reports, list):
            continue
        for report in reports:
            if not isinstance(report, dict):
                continue
            camera_id = report.get("camera_id")
            if allowed_camera_ids is not None and camera_id not in allowed_camera_ids:
                continue
            errors = report.get("errors", [])
            valid_errors = errors if isinstance(errors, list) else []
            error_codes += sum(isinstance(error, str) for error in valid_errors)
            if report.get("status") != CameraStatus.ONLINE.value or valid_errors:
                degraded += 1
    return {"degraded": degraded, "error_codes": error_codes}


def render_prometheus_metrics(db: Session, settings: Settings) -> str:
    now = datetime.now(UTC)
    worker = summarize_service_health(
        db,
        service=WORKER_SERVICE,
        timeout_seconds=settings.worker_heartbeat_timeout_seconds,
        now=now,
    )
    media_gateway = summarize_media_gateway_health(
        db,
        timeout_seconds=settings.worker_heartbeat_timeout_seconds,
        now=now,
    )
    pending_condition = NotificationDelivery.status.in_(
        [DeliveryStatus.PENDING.value, DeliveryStatus.FAILED.value]
    )
    queue_depth = db.scalar(
        select(func.count()).select_from(NotificationDelivery).where(pending_condition)
    ) or 0
    snapshot_legal_hold_pending = (
        db.scalar(select(func.count()).select_from(SnapshotLegalHoldJob)) or 0
    )
    oldest = db.scalar(
        select(func.min(NotificationDelivery.created_at)).where(pending_condition)
    )
    oldest_seconds = (
        max(int((now - as_utc(oldest)).total_seconds()), 0) if oldest else 0
    )
    cameras_total = db.scalar(select(func.count()).select_from(Camera)) or 0
    cameras_online = db.scalar(
        select(func.count())
        .select_from(Camera)
        .where(Camera.status == CameraStatus.ONLINE.value)
    ) or 0
    edge_online = db.scalar(
        select(func.count())
        .select_from(EdgeNode)
        .where(
            EdgeNode.active.is_(True),
            EdgeNode.status == EdgeNodeStatus.ONLINE.value,
        )
    ) or 0
    edge_offline = db.scalar(
        select(func.count())
        .select_from(EdgeNode)
        .where(
            EdgeNode.active.is_(True),
            EdgeNode.status != EdgeNodeStatus.ONLINE.value,
        )
    ) or 0
    active_nodes = db.scalars(
        select(EdgeNode).where(EdgeNode.active.is_(True))
    ).all()
    edge_camera_reports = summarize_edge_camera_reports(active_nodes)
    reconnects = sum(
        int(node.telemetry.get("stream_reconnects_last_5m", 0))
        + int(node.telemetry.get("central_reconnects_last_5m", 0))
        for node in active_nodes
    )
    unhealthy_gpus = sum(
        node.telemetry.get("gpu_healthy") is False
        for node in active_nodes
    )
    dead_letters = sum(
        int(node.telemetry.get("dead_letter_depth", 0)) for node in active_nodes
    )
    edge_outbox_depths = [
        int(node.telemetry.get("queue_depth", 0))
        + int(node.telemetry.get("dead_letter_depth", 0))
        for node in active_nodes
    ]
    edge_outbox_capacities = [
        max(int(node.telemetry.get("outbox_capacity", 100_000)), 1)
        for node in active_nodes
    ]
    edge_outbox_max_utilization = max(
        (
            depth / capacity
            for depth, capacity in zip(
                edge_outbox_depths, edge_outbox_capacities, strict=True
            )
        ),
        default=0,
    )
    latency = request_latency.snapshot()
    samples = {
        "mineguard_worker_up": 1 if worker["status"] != "offline" else 0,
        "mineguard_worker_degraded": 1 if worker["status"] == "degraded" else 0,
        "mineguard_worker_instances": worker["instances_online"],
        "mineguard_media_gateway_up": 1
        if media_gateway["status"] == "online"
        else 0,
        "mineguard_media_gateway_reconcile_failures": media_gateway[
            "consecutive_failures"
        ],
        "mineguard_notification_queue_depth": queue_depth,
        "mineguard_snapshot_legal_hold_pending": snapshot_legal_hold_pending,
        "mineguard_notification_oldest_seconds": oldest_seconds,
        "mineguard_cameras_total": cameras_total,
        "mineguard_cameras_online": cameras_online,
        "mineguard_edge_nodes_online": edge_online,
        "mineguard_edge_nodes_offline": edge_offline,
        "mineguard_edge_camera_reports_degraded": edge_camera_reports["degraded"],
        "mineguard_edge_camera_error_codes": edge_camera_reports["error_codes"],
        "mineguard_edge_reconnects_last_5m": reconnects,
        "mineguard_edge_gpu_unhealthy_nodes": unhealthy_gpus,
        "mineguard_edge_dead_letter_depth": dead_letters,
        "mineguard_edge_outbox_depth": sum(edge_outbox_depths),
        "mineguard_edge_outbox_capacity": sum(edge_outbox_capacities),
        "mineguard_edge_outbox_max_utilization_ratio": edge_outbox_max_utilization,
        "mineguard_api_latency_p95_ms": latency["p95_ms"],
    }
    return "".join(f"{name} {value}\n" for name, value in samples.items())
