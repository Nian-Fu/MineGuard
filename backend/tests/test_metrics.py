from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import Camera, EdgeNode, Event, SnapshotLegalHoldJob, User
from app.services.edge_nodes import mark_stale_edge_nodes, reconcile_camera_states
from app.services.metrics import RequestLatencyTracker, render_prometheus_metrics
from app.services.operations import (
    WORKER_SERVICE,
    record_service_heartbeat,
    summarize_media_gateway_health,
    summarize_service_health,
)
from app.worker import retry_delay


def test_latency_tracker_uses_nearest_rank_percentiles():
    tracker = RequestLatencyTracker(capacity=3)
    tracker.observe(10)
    tracker.observe(20)
    snapshot = tracker.snapshot()
    assert snapshot == {"sample_count": 2, "p50_ms": 10, "p95_ms": 20}
    tracker.observe(30)
    tracker.observe(40)
    assert tracker.snapshot()["sample_count"] == 3
    assert tracker.snapshot()["p95_ms"] == 40


def test_worker_retry_delay_is_bounded(monkeypatch):
    monkeypatch.setattr("app.worker.random.uniform", lambda _low, _high: 1.0)
    assert retry_delay(1) == 1
    assert retry_delay(5) == 16
    assert retry_delay(100) == 30


def test_worker_heartbeat_detects_recovery_and_staleness():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    started_at = datetime.now(UTC)
    with Session(engine) as db:
        record_service_heartbeat(
            db,
            instance_id="worker-test",
            service=WORKER_SERVICE,
            started_at=started_at,
            consecutive_failures=2,
        )
        db.commit()
        degraded = summarize_service_health(
            db,
            service=WORKER_SERVICE,
            timeout_seconds=15,
            now=started_at + timedelta(seconds=1),
        )
        assert degraded["status"] == "degraded"

        record_service_heartbeat(
            db,
            instance_id="worker-test",
            service=WORKER_SERVICE,
            started_at=started_at,
        )
        db.commit()
        recovered = summarize_service_health(
            db,
            service=WORKER_SERVICE,
            timeout_seconds=15,
            now=started_at + timedelta(seconds=2),
        )
        assert recovered["status"] == "online"

        stale = summarize_service_health(
            db,
            service=WORKER_SERVICE,
            timeout_seconds=15,
            now=started_at + timedelta(seconds=60),
        )
        assert stale["status"] == "offline"
        assert stale["instances_online"] == 0


def test_prometheus_reports_degraded_worker_heartbeat():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        record_service_heartbeat(
            db,
            instance_id="worker-metrics",
            service=WORKER_SERVICE,
            started_at=datetime.now(UTC),
            consecutive_failures=3,
        )
        db.commit()
        metrics = render_prometheus_metrics(
            db, SimpleNamespace(worker_heartbeat_timeout_seconds=15)
        )
        assert "mineguard_worker_up 1\n" in metrics
        assert "mineguard_worker_degraded 1\n" in metrics


def test_prometheus_reports_snapshot_legal_hold_backlog():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as db:
        user = User(
            username="snapshot-metrics-admin",
            full_name="Snapshot Metrics Admin",
            password_hash="test",
            role="admin",
        )
        camera = Camera(
            code="SNAPSHOT-METRICS-CAM",
            name="Snapshot metrics camera",
            area="shaft-a",
            stream_url="rtsp://source/snapshot-metrics",
            playback_path="/media/snapshot-metrics/index.m3u8",
        )
        db.add_all([user, camera])
        db.flush()
        event = Event(
            event_type="intrusion",
            severity="critical",
            status="resolved",
            camera_id=camera.id,
            title="Snapshot hold backlog",
            confidence=0.99,
            snapshot_url=(
                "/snapshots/camera-1/2026/08/22/"
                "ffffffffffffffffffffffffffffffff.jpg"
            ),
        )
        db.add(event)
        db.flush()
        db.add(
            SnapshotLegalHoldJob(
                event_id=event.id,
                desired_enabled=True,
                requested_by=user.id,
                reason="Metrics backlog",
                next_attempt_at=now,
            )
        )
        db.commit()
        metrics = render_prometheus_metrics(
            db, SimpleNamespace(worker_heartbeat_timeout_seconds=15)
        )
        assert "mineguard_snapshot_legal_hold_pending 1\n" in metrics


def test_media_gateway_health_reports_recovery_and_metrics():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    started_at = datetime.now(UTC)
    with Session(engine) as db:
        record_service_heartbeat(
            db,
            instance_id="worker-media",
            service=WORKER_SERVICE,
            started_at=started_at,
            consecutive_failures=4,
            detail={
                "media_gateway": {
                    "configured": True,
                    "status": "recovering",
                    "consecutive_failures": 4,
                }
            },
        )
        db.commit()
        health = summarize_media_gateway_health(
            db, timeout_seconds=15, now=started_at + timedelta(seconds=1)
        )
        assert health == {
            "status": "recovering",
            "instances_configured": 1,
            "consecutive_failures": 4,
        }
        metrics = render_prometheus_metrics(
            db, SimpleNamespace(worker_heartbeat_timeout_seconds=15)
        )
        assert "mineguard_media_gateway_up 0\n" in metrics
        assert "mineguard_media_gateway_reconcile_failures 4\n" in metrics

        record_service_heartbeat(
            db,
            instance_id="worker-media",
            service=WORKER_SERVICE,
            started_at=started_at,
            detail={
                "media_gateway": {
                    "configured": True,
                    "status": "online",
                    "managed_paths": 3,
                }
            },
        )
        db.commit()
        recovered = summarize_media_gateway_health(
            db, timeout_seconds=15, now=started_at + timedelta(seconds=2)
        )
        assert recovered["status"] == "online"


def test_prometheus_reports_unhealthy_edge_gpu():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(
            EdgeNode(
                code="gpu-unhealthy-metrics",
                name="GPU unhealthy metrics",
                api_key_hash="c" * 64,
                status="degraded",
                active=True,
                telemetry={
                    "gpu_healthy": False,
                    "cameras": [
                        {
                            "camera_id": 1,
                            "status": "degraded",
                            "errors": [
                                "face_recognition_unavailable",
                                "stream_unavailable",
                            ],
                        }
                    ],
                },
            )
        )
        db.commit()
        metrics = render_prometheus_metrics(
            db, SimpleNamespace(worker_heartbeat_timeout_seconds=15)
        )
        assert "mineguard_edge_gpu_unhealthy_nodes 1\n" in metrics
        assert "mineguard_edge_camera_reports_degraded 1\n" in metrics
        assert "mineguard_edge_camera_error_codes 2\n" in metrics


def test_stale_edge_node_creates_one_deterministic_offline_event(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(
        "app.services.edge_nodes.get_settings",
        lambda: SimpleNamespace(edge_heartbeat_timeout_seconds=30),
    )
    with Session(engine) as db:
        camera = Camera(
            code="STALE-CAM",
            name="Stale camera",
            area="shaft-a",
            stream_url="rtsp://source/stale",
            playback_path="/media/stale-cam/index.m3u8",
            status="online",
        )
        db.add(camera)
        db.flush()
        node = EdgeNode(
            code="stale-node",
            name="Stale node",
            api_key_hash="b" * 64,
            status="online",
            camera_ids=[camera.id],
            last_seen_at=datetime.now(UTC) - timedelta(minutes=2),
        )
        db.add(node)
        db.commit()

        assert mark_stale_edge_nodes(db) == 1
        assert mark_stale_edge_nodes(db) == 0
        assert db.scalar(select(func.count()).select_from(Event)) == 1


def test_redundant_edge_reports_are_aggregated_and_fail_over(monkeypatch):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(
        "app.services.edge_nodes.get_settings",
        lambda: SimpleNamespace(edge_heartbeat_timeout_seconds=30),
    )
    now = datetime.now(UTC)
    with Session(engine) as db:
        camera = Camera(
            code="REDUNDANT-CAM",
            name="Redundant camera",
            area="shaft-a",
            stream_url="rtsp://source/redundant",
            playback_path="/media/redundant-cam/index.m3u8",
            status="online",
        )
        db.add(camera)
        db.flush()
        first = EdgeNode(
            code="redundant-a",
            name="Redundant A",
            api_key_hash="a" * 64,
            status="online",
            camera_ids=[camera.id],
            last_seen_at=now,
            telemetry={
                "cameras": [
                    {"camera_id": camera.id, "status": "online", "fps": 25.0, "latency_ms": 80}
                ]
            },
        )
        second = EdgeNode(
            code="redundant-b",
            name="Redundant B",
            api_key_hash="b" * 64,
            status="online",
            camera_ids=[camera.id],
            last_seen_at=now,
            telemetry={
                "cameras": [
                    {"camera_id": camera.id, "status": "offline", "fps": 0.0, "latency_ms": 0}
                ]
            },
        )
        db.add_all([first, second])
        db.commit()

        assert reconcile_camera_states(db, {camera.id}, now=now) == {camera.id}
        assert camera.status == "degraded"
        assert camera.fps == 25.0
        assert camera.latency_ms == 80

        second.telemetry = {
            "cameras": [
                {"camera_id": camera.id, "status": "online", "fps": 24.0, "latency_ms": 90}
            ]
        }
        assert reconcile_camera_states(db, {camera.id}, now=now) == {camera.id}
        assert camera.status == "online"

        first.last_seen_at = now - timedelta(minutes=2)
        db.commit()
        assert mark_stale_edge_nodes(db) == 1
        assert camera.status == "online"
        assert db.scalar(select(func.count()).select_from(Event)) == 0

        second.last_seen_at = datetime.now(UTC) - timedelta(minutes=2)
        db.commit()
        assert mark_stale_edge_nodes(db) == 1
        assert camera.status == "offline"
        assert db.scalar(select(func.count()).select_from(Event)) == 1
