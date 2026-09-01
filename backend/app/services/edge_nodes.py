from datetime import UTC, datetime, timedelta
from math import isfinite

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import Camera, CameraStatus, EdgeNode, EdgeNodeStatus, EventType, Severity
from app.schemas import EventCreate
from app.services.events import ingest_event_record
from app.services.operations import as_utc
from app.services.realtime import publish_realtime_signal

CAMERA_RECONCILE_BATCH_SIZE = 1000
STALE_NODE_BATCH_SIZE = 20
STALE_EVENT_NODE_SUMMARY_LIMIT = 100


def reconcile_camera_states(
    db: Session,
    camera_ids: set[int],
    *,
    now: datetime | None = None,
) -> set[int]:
    """Aggregate fresh redundant edge reports without last-writer-wins state."""
    if not camera_ids:
        return set()
    checked_at = now or datetime.now(UTC)
    if len(camera_ids) > CAMERA_RECONCILE_BATCH_SIZE:
        changed_camera_ids: set[int] = set()
        ordered_ids = sorted(camera_ids)
        for offset in range(0, len(ordered_ids), CAMERA_RECONCILE_BATCH_SIZE):
            changed_camera_ids.update(
                reconcile_camera_states(
                    db,
                    set(ordered_ids[offset : offset + CAMERA_RECONCILE_BATCH_SIZE]),
                    now=checked_at,
                )
            )
        return changed_camera_ids
    cutoff = checked_at - timedelta(
        seconds=get_settings().edge_heartbeat_timeout_seconds
    )
    cameras = db.scalars(
        select(Camera)
        .where(Camera.id.in_(camera_ids))
        .order_by(Camera.id)
        .with_for_update()
    ).all()
    reports: dict[int, list[tuple[str, float, int, datetime]]] = {
        camera.id: [] for camera in cameras
    }
    nodes = db.scalars(
        select(EdgeNode).where(
            EdgeNode.active.is_(True),
            EdgeNode.status != EdgeNodeStatus.OFFLINE.value,
            EdgeNode.last_seen_at.is_not(None),
        )
    ).all()
    valid_statuses = {status.value for status in CameraStatus}
    for node in nodes:
        seen_at = as_utc(node.last_seen_at)
        if seen_at < cutoff or not isinstance(node.telemetry, dict):
            continue
        bound_ids = {
            camera_id
            for camera_id in (node.camera_ids or [])
            if isinstance(camera_id, int) and not isinstance(camera_id, bool)
        } & camera_ids
        raw_reports = node.telemetry.get("cameras", [])
        if not isinstance(raw_reports, list):
            continue
        for report in raw_reports[:1000]:
            if not isinstance(report, dict):
                continue
            camera_id = report.get("camera_id")
            status = report.get("status")
            fps = report.get("fps")
            latency_ms = report.get("latency_ms")
            if (
                isinstance(camera_id, bool)
                or not isinstance(camera_id, int)
                or camera_id not in bound_ids
                or not isinstance(status, str)
                or status not in valid_statuses
                or isinstance(fps, bool)
                or not isinstance(fps, (int, float))
                or not isfinite(fps)
                or not 0 <= fps <= 240
                or isinstance(latency_ms, bool)
                or not isinstance(latency_ms, int)
                or not 0 <= latency_ms <= 60_000
            ):
                continue
            effective_status = (
                CameraStatus.DEGRADED.value
                if node.status == EdgeNodeStatus.DEGRADED.value
                else status
            )
            reports[camera_id].append(
                (effective_status, float(fps), latency_ms, seen_at)
            )

    changed_camera_ids: set[int] = set()
    for camera in cameras:
        camera_reports = reports[camera.id]
        previous_status = camera.status
        statuses = {report[0] for report in camera_reports}
        if not statuses:
            camera.status = CameraStatus.OFFLINE.value
            camera.fps = 0.0
            camera.latency_ms = 0
        elif statuses == {CameraStatus.ONLINE.value}:
            camera.status = CameraStatus.ONLINE.value
        elif statuses == {CameraStatus.OFFLINE.value}:
            camera.status = CameraStatus.OFFLINE.value
            camera.fps = 0.0
            camera.latency_ms = 0
        elif statuses == {CameraStatus.MAINTENANCE.value}:
            camera.status = CameraStatus.MAINTENANCE.value
            camera.fps = 0.0
            camera.latency_ms = 0
        else:
            camera.status = CameraStatus.DEGRADED.value

        if camera_reports:
            camera.last_seen_at = max(report[3] for report in camera_reports)
            if camera.status in {
                CameraStatus.ONLINE.value,
                CameraStatus.DEGRADED.value,
            }:
                live_reports = [
                    report
                    for report in camera_reports
                    if report[0]
                    in {CameraStatus.ONLINE.value, CameraStatus.DEGRADED.value}
                ]
                if live_reports:
                    camera.fps = max(report[1] for report in live_reports)
                    camera.latency_ms = min(report[2] for report in live_reports)
                else:
                    camera.fps = 0.0
                    camera.latency_ms = 0
        if camera.status != previous_status:
            changed_camera_ids.add(camera.id)
    return changed_camera_ids


def mark_stale_edge_nodes(db: Session) -> int:
    now = datetime.now(UTC)
    cutoff = now - timedelta(seconds=get_settings().edge_heartbeat_timeout_seconds)
    nodes = db.scalars(
        select(EdgeNode).where(
            EdgeNode.active.is_(True),
            EdgeNode.status != EdgeNodeStatus.OFFLINE.value,
            EdgeNode.last_seen_at.is_not(None),
            EdgeNode.last_seen_at < cutoff,
        )
        .order_by(EdgeNode.id)
        .limit(STALE_NODE_BATCH_SIZE)
        .with_for_update(skip_locked=True)
    ).all()
    affected_camera_ids: set[int] = set()
    stale_nodes_by_camera: dict[int, list[EdgeNode]] = {}
    for node in nodes:
        node.status = EdgeNodeStatus.OFFLINE.value
        for camera_id in node.camera_ids:
            camera = db.get(Camera, camera_id)
            if not camera:
                continue
            affected_camera_ids.add(camera_id)
            stale_nodes_by_camera.setdefault(camera_id, []).append(node)
    changed_camera_ids = reconcile_camera_states(db, affected_camera_ids, now=now)
    for camera_id, stale_nodes in stale_nodes_by_camera.items():
        camera = db.get(Camera, camera_id)
        if (
            not camera
            or camera_id not in changed_camera_ids
            or camera.status != CameraStatus.OFFLINE.value
        ):
            continue
        latest_node = max(stale_nodes, key=lambda item: as_utc(item.last_seen_at))
        summarized_nodes = sorted(stale_nodes, key=lambda item: item.id)[
            :STALE_EVENT_NODE_SUMMARY_LIMIT
        ]
        stale_codes = [node.code for node in summarized_nodes]
        stale_ids = [node.id for node in summarized_nodes]
        payload = EventCreate(
            event_type=EventType.CAMERA_OFFLINE,
            severity=Severity.HIGH,
            camera_id=camera.id,
            title=f"摄像头 {camera.code} 的边缘上报全部失联",
            description=(
                f"超过 {get_settings().edge_heartbeat_timeout_seconds} 秒未收到任何有效节点心跳"
            ),
            confidence=1.0,
            occurred_at=now,
            metadata_json={
                "edge_node_ids": stale_ids,
                "edge_node_codes": stale_codes,
                "edge_node_count": len(stale_nodes),
                "edge_node_summary_truncated": len(stale_nodes) > len(summarized_nodes),
            },
        )
        heartbeat_epoch = int(as_utc(latest_node.last_seen_at).timestamp())
        ingest_event_record(
            db,
            payload,
            f"camera-offline:{camera.id}:heartbeat:{heartbeat_epoch}",
        )
    for camera_id in changed_camera_ids:
        if camera := db.get(Camera, camera_id):
            publish_realtime_signal(
                db, "cameras", camera.id, "state_changed", area=camera.area
            )
    db.commit()
    return len(nodes)
