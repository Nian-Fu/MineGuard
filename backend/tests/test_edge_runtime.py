import asyncio
import json
from collections import deque
from types import SimpleNamespace

import pytest

from app.edge.outbox import PersistentOutbox
from app.edge.runtime import (
    CameraProgressWatchdog,
    CameraRuntimeState,
    CameraWorkerConfig,
    EdgeApiClient,
    EdgeWorker,
    EdgeWorkerConfig,
    FaceProbe,
    StreamResetAfterBackpressure,
    edge_event_idempotency_key,
)
from app.services.stream_supervisor import StreamState

VALID_EDGE_KEY = "mg_edge_" + "a" * 54


def test_camera_worker_config_validates_normalized_polygons():
    config = CameraWorkerConfig.from_dict(
        {
            "camera_id": 4,
            "code": "CAM-004",
            "area": "运输巷",
            "stream_url": "rtsp://camera.local/cam004",
            "intrusion_polygon": [[0.1, 0.1], [0.9, 0.1], [0.9, 0.9]],
        }
    )
    assert config.camera_id == 4
    assert config.intrusion_polygon[0] == (0.1, 0.1)
    assert config.face_recognition_enabled is False

    with pytest.raises(ValueError, match="normalized points"):
        CameraWorkerConfig.from_dict(
            {
                "camera_id": 4,
                "code": "CAM-004",
                "area": "运输巷",
                "stream_url": "rtsp://camera.local/cam004",
                "intrusion_polygon": [[0, 0], [1.2, 0], [1, 1]],
            }
        )
    with pytest.raises(ValueError, match="thresholds"):
        CameraWorkerConfig.from_dict(
            {
                "camera_id": 4,
                "code": "CAM-004",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam004",
                "crowding_threshold": 100_001,
            }
        )
    with pytest.raises(ValueError, match="RTSP stream_url"):
        CameraWorkerConfig.from_dict(
            {
                "camera_id": 4,
                "code": "CAM-004",
                "area": "运输巷",
                "stream_url": "rtsp://",
            }
        )
    with pytest.raises(ValueError, match="RTSP stream_url"):
        CameraWorkerConfig.from_dict(
            {
                "camera_id": 4.5,
                "code": "CAM-004",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam004",
            }
        )
    with pytest.raises(ValueError, match="normalized points"):
        CameraWorkerConfig.from_dict(
            {
                "camera_id": 4,
                "code": "CAM-004",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam004",
                "intrusion_polygon": [[False, 0], [1, 0], [1, 1]],
            }
        )
    with pytest.raises(ValueError, match="counting_authority"):
        CameraWorkerConfig.from_dict(
            {
                "camera_id": 4,
                "code": "CAM-004",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam004",
                "counting_authority": "true",
            }
        )
    with pytest.raises(ValueError, match="geometry"):
        CameraWorkerConfig.from_dict(
            {
                "camera_id": 4,
                "code": "CAM-004",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam004",
                "intrusion_polygon": [[0, 0], [0.5, 0.5], [1, 1]],
            }
        )


def test_camera_worker_config_validates_face_recognition_controls():
    config = CameraWorkerConfig.from_dict(
        {
            "camera_id": 4,
            "code": "CAM-FACE",
            "area": "shaft-a",
            "stream_url": "rtsp://camera.local/face",
            "face_recognition_enabled": True,
            "face_probe_interval_seconds": 2,
            "face_event_cooldown_seconds": 120,
        }
    )
    assert config.face_recognition_enabled is True
    assert config.face_probe_interval_seconds == 2
    assert config.face_event_cooldown_seconds == 120

    for field, value in (
        ("face_recognition_enabled", "true"),
        ("face_probe_interval_seconds", 0.1),
        ("face_probe_interval_seconds", float("nan")),
        ("face_event_cooldown_seconds", 0),
    ):
        with pytest.raises(ValueError):
            CameraWorkerConfig.from_dict(
                {
                    "camera_id": 4,
                    "code": "CAM-FACE",
                    "area": "shaft-a",
                    "stream_url": "rtsp://camera.local/face",
                    field: value,
                }
            )


def test_edge_face_identification_response_contract_is_strict():
    matched = {
        "matched": True,
        "unknown": False,
        "quality": 0.9,
        "liveness": 0.95,
        "model_version": "face-v1",
        "model_sha256": "a" * 64,
        "authorized_for_camera": True,
        "candidate": {"person_id": 7, "similarity": 0.88},
    }
    unknown = {
        "matched": False,
        "unknown": True,
        "quality": 0.9,
        "liveness": 0.95,
        "model_version": "face-v1",
        "model_sha256": "a" * 64,
        "authorized_for_camera": None,
        "candidate": None,
    }
    EdgeApiClient._validate_face_identification(matched)
    EdgeApiClient._validate_face_identification(unknown)

    invalid = {**unknown, "matched": True}
    with pytest.raises(ValueError, match="contract"):
        EdgeApiClient._validate_face_identification(invalid)
    with pytest.raises(ValueError, match="contract"):
        EdgeApiClient._validate_face_identification(
            {**matched, "embedding": [0.1] * 128}
        )
    with pytest.raises(ValueError, match="candidate"):
        EdgeApiClient._validate_face_identification(
            {
                **matched,
                "candidate": {
                    **matched["candidate"],
                    "name": "must-not-cross-edge-contract",
                },
            }
        )


def test_face_probe_scheduler_allows_one_inflight_task_and_resets_state():
    async def scenario():
        worker = EdgeWorker.__new__(EdgeWorker)
        worker._face_tasks = {}
        worker._face_last_probe = {}
        worker._face_last_event = {}
        release = asyncio.Event()
        calls = []

        async def process(_camera, _state, probe, _crop, _timestamp):
            calls.append(probe.track_id)
            await release.wait()

        worker._process_face_probe = process
        worker._face_crop = lambda _frame, _box: object()
        camera = CameraWorkerConfig(
            camera_id=9,
            code="CAM-FACE-09",
            area="shaft-a",
            stream_url="rtsp://camera.local/face-09",
            face_recognition_enabled=True,
            face_probe_interval_seconds=5,
        )
        state = CameraRuntimeState(status="online")
        probe = FaceProbe(41, SimpleNamespace(), 0.9)

        worker._schedule_face_probe(camera, state, object(), [probe], 100)
        first_task = worker._face_tasks[9]
        worker._schedule_face_probe(camera, state, object(), [probe], 101)
        assert worker._face_tasks[9] is first_task
        await asyncio.sleep(0)
        assert calls == [41]

        worker._reset_face_state(9)
        assert first_task.cancelled() is False
        await asyncio.gather(first_task, return_exceptions=True)
        assert 9 not in worker._face_tasks
        assert not worker._face_last_probe
        assert not worker._face_last_event

    asyncio.run(scenario())


def test_face_probe_results_are_private_persistent_and_fault_isolated(tmp_path):
    class FaceApi:
        def __init__(self):
            self.result = None
            self.error = None

        async def identify_face(self, **_values):
            if self.error:
                raise self.error
            return self.result

    async def scenario():
        worker = EdgeWorker.__new__(EdgeWorker)
        worker.config = SimpleNamespace(node_code="edge-face-runtime")
        worker.outbox = PersistentOutbox(tmp_path / "face-outbox.db")
        worker.api = FaceApi()
        worker._stop = asyncio.Event()
        worker._face_last_event = {}
        worker._encode_face_probe = lambda _crop: b"x" * 256
        camera = CameraWorkerConfig(
            camera_id=3,
            code="CAM-FACE-03",
            area="shaft-a",
            stream_url="rtsp://camera.local/face-03",
            face_recognition_enabled=True,
            face_event_cooldown_seconds=60,
        )
        state = CameraRuntimeState(status="online")

        await worker._process_face_probe(
            camera,
            state,
            FaceProbe(1, SimpleNamespace(), 0.8),
            object(),
            100,
        )
        assert worker.outbox.size() == 0

        worker.api.error = ConnectionError("provider offline")
        await worker._process_face_probe(
            camera,
            state,
            FaceProbe(2, SimpleNamespace(), 0.8),
            object(),
            101,
        )
        assert state.status == "degraded"
        assert "face_recognition_unavailable" in state.degradation_reasons

        worker._mark_camera_issue(state, "snapshot_persistence_failed")
        worker.api.error = None
        worker.api.result = {
            "matched": False,
            "unknown": True,
            "quality": 0.87,
            "liveness": 0.93,
            "model_version": "face-v1",
            "model_sha256": "a" * 64,
            "authorized_for_camera": None,
            "candidate": None,
        }
        await worker._process_face_probe(
            camera,
            state,
            FaceProbe(3, SimpleNamespace(), 0.84),
            object(),
            102,
        )
        assert "face_recognition_unavailable" not in state.degradation_reasons
        assert state.status == "degraded"
        assert state.last_error == "snapshot_persistence_failed"
        item = worker.outbox.due()[0]
        assert item.payload["event_type"] == "unknown_face"
        assert item.payload["person_id"] is None
        serialized = json.dumps(item.payload)
        assert "image" not in serialized
        assert "embedding" not in serialized
        assert "face_model_sha256" in serialized

        worker._clear_camera_issue(state, "snapshot_persistence_failed")
        worker.api.result = {
            **worker.api.result,
            "matched": True,
            "unknown": False,
            "authorized_for_camera": False,
            "candidate": {"person_id": 7, "similarity": -0.2},
        }
        await worker._process_face_probe(
            camera,
            state,
            FaceProbe(4, SimpleNamespace(), 0.82),
            object(),
            103,
        )
        matched = [
            queued.payload
            for queued in worker.outbox.due()
            if queued.payload["event_type"] == "face_match"
        ][0]
        assert matched["person_id"] == 7
        assert matched["confidence"] == 0
        assert matched["severity"] == "high"
        assert state.status == "online"

    asyncio.run(scenario())


def test_heartbeat_reports_all_bounded_camera_failure_codes():
    class Gpu:
        def sample(self):
            return 0.1, 0.2, True

    class Outbox:
        maximum_items = 100

        def size(self):
            return 2

        def dead_letter_size(self):
            return 1

    worker = EdgeWorker.__new__(EdgeWorker)
    camera = CameraWorkerConfig(
        camera_id=5,
        code="CAM-005",
        area="shaft-a",
        stream_url="rtsp://camera.local/cam005",
    )
    worker.config = SimpleNamespace(
        software_version="edge-test",
        cameras=(camera,),
    )
    worker.gpu = Gpu()
    worker.outbox = Outbox()
    worker.manifest = SimpleNamespace(
        edge_report=lambda ready: {
            "algorithm_type": "object_detection",
            "model_version": "v1",
            "sha256": "a" * 64,
            "runtime": "triton",
            "ready": ready,
        }
    )
    worker._central_reconnect_timestamps = deque()
    worker._central_reconnect_attempts_total = 0
    worker.states = {
        5: CameraRuntimeState(
            status="degraded",
            stream_error="ConnectionError",
            degradation_reasons={
                "face_recognition_unavailable",
                "snapshot_persistence_failed",
            },
        )
    }

    payload = worker._heartbeat_payload()

    assert payload["cameras"][0]["errors"] == [
        "ConnectionError",
        "face_recognition_unavailable",
        "snapshot_persistence_failed",
    ]


def test_edge_worker_config_uses_environment_secret_and_relative_paths(tmp_path, monkeypatch):
    config_file = tmp_path / "edge.json"
    config_file.write_text(
        json.dumps(
            {
                "central_url": "https://mineguard.example/",
                "node_code": "edge-test",
                "software_version": "0.1.0",
                "triton_url": "triton:8000",
                "model_manifest": "models/manifest.json",
                "model_root": "models",
                "cameras": [
                    {
                        "camera_id": 1,
                        "code": "CAM-001",
                        "area": "主井口",
                        "stream_url": "rtsp://camera.local/cam001",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MINEGUARD_EDGE_KEY", VALID_EDGE_KEY)
    config = EdgeWorkerConfig.load(config_file)
    assert config.node_key == VALID_EDGE_KEY
    assert config.central_url == "https://mineguard.example"
    assert config.model_manifest_path == tmp_path / "models" / "manifest.json"
    assert config.outbox_path == tmp_path / "data" / "event-outbox.db"
    assert config.snapshot_spool_path == tmp_path / "data" / "event-snapshots"
    assert config.event_snapshots_enabled is False
    assert config.snapshot_jpeg_quality == 85
    assert config.snapshot_maximum_bytes == 8 * 1024 * 1024
    assert config.outbox_maximum_items == 100_000
    assert config.outbox_maximum_payload_bytes == 64 * 1024
    assert config.resolved_dead_letter_retention_days == 90
    assert config.cameras[0].counting_authority is True
    assert VALID_EDGE_KEY not in repr(config)
    assert "rtsp://camera.local/cam001" not in repr(config)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("outbox_maximum_items", False),
        ("outbox_maximum_items", 0),
        ("outbox_maximum_items", 10_000_001),
        ("outbox_maximum_items", 1.5),
        ("outbox_maximum_payload_bytes", 1023),
        ("outbox_maximum_payload_bytes", 1_048_577),
        ("resolved_dead_letter_retention_days", 0),
        ("resolved_dead_letter_retention_days", 3651),
        ("snapshot_jpeg_quality", 49),
        ("snapshot_jpeg_quality", 96),
        ("snapshot_maximum_bytes", 1023),
        ("snapshot_maximum_bytes", 20 * 1024 * 1024 + 1),
    ],
)
def test_edge_worker_config_rejects_invalid_outbox_limits(
    tmp_path, monkeypatch, field, value
):
    payload = {
        "central_url": "https://mineguard.example",
        "node_code": "edge-test",
        "software_version": "0.1.0",
        "triton_url": "triton:8000",
        "model_manifest": "models/manifest.json",
        "model_root": "models",
        "cameras": [
            {
                "camera_id": 1,
                "code": "CAM-001",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam001",
            }
        ],
        field: value,
    }
    config_file = tmp_path / f"invalid-{field}.json"
    config_file.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("MINEGUARD_EDGE_KEY", VALID_EDGE_KEY)
    with pytest.raises(ValueError, match=field):
        EdgeWorkerConfig.load(config_file)


def test_edge_worker_config_requires_strict_snapshot_toggle(
    tmp_path, monkeypatch
):
    config_file = tmp_path / "invalid-snapshot-toggle.json"
    config_file.write_text(
        json.dumps(
            {
                "central_url": "https://mineguard.example",
                "node_code": "edge-test",
                "software_version": "0.1.0",
                "triton_url": "triton:8000",
                "model_manifest": "models/manifest.json",
                "model_root": "models",
                "event_snapshots_enabled": "true",
                "cameras": [
                    {
                        "camera_id": 1,
                        "code": "CAM-001",
                        "area": "shaft-a",
                        "stream_url": "rtsp://camera.local/cam001",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MINEGUARD_EDGE_KEY", VALID_EDGE_KEY)
    with pytest.raises(ValueError, match="event_snapshots_enabled"):
        EdgeWorkerConfig.load(config_file)


def test_edge_worker_config_requires_service_key(tmp_path, monkeypatch):
    config_file = tmp_path / "edge.json"
    config_file.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("MINEGUARD_EDGE_KEY", raising=False)
    with pytest.raises(ValueError, match="MINEGUARD_EDGE_KEY"):
        EdgeWorkerConfig.load(config_file)


def test_edge_worker_config_requires_one_counting_authority_per_area(
    tmp_path, monkeypatch
):
    payload = {
        "central_url": "https://mineguard.example",
        "node_code": "edge-test",
        "software_version": "0.1.0",
        "triton_url": "triton:8000",
        "model_manifest": "models/manifest.json",
        "model_root": "models",
        "cameras": [
            {
                "camera_id": 1,
                "code": "CAM-001",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam001",
            },
            {
                "camera_id": 2,
                "code": "CAM-002",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam002",
            },
        ],
    }
    config_file = tmp_path / "duplicate-authority.json"
    config_file.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("MINEGUARD_EDGE_KEY", VALID_EDGE_KEY)
    with pytest.raises(ValueError, match="exactly one counting authority"):
        EdgeWorkerConfig.load(config_file)

    payload["cameras"][1]["counting_authority"] = False
    config_file.write_text(json.dumps(payload), encoding="utf-8")
    config = EdgeWorkerConfig.load(config_file)
    assert config.stream_stall_timeout_seconds == 60
    assert [camera.code for camera in config.cameras if camera.counting_authority] == [
        "CAM-001"
    ]


def test_edge_worker_config_rejects_malformed_service_key(tmp_path, monkeypatch):
    config_file = tmp_path / "edge.json"
    config_file.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("MINEGUARD_EDGE_KEY", "mg_edge_too-short")
    with pytest.raises(ValueError, match="service-key format"):
        EdgeWorkerConfig.load(config_file)


def test_edge_worker_config_rejects_central_url_credentials(tmp_path, monkeypatch):
    config_file = tmp_path / "edge.json"
    config_file.write_text(
        json.dumps(
            {
                "central_url": "https://user:secret@mineguard.example",
                "node_code": "edge-test",
                "software_version": "0.1.0",
                "triton_url": "triton:8000",
                "model_manifest": "models/manifest.json",
                "model_root": "models",
                "cameras": [
                    {
                        "camera_id": 1,
                        "code": "CAM-001",
                        "area": "主井口",
                        "stream_url": "rtsp://camera.local/cam001",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MINEGUARD_EDGE_KEY", VALID_EDGE_KEY)
    with pytest.raises(ValueError, match="without credentials"):
        EdgeWorkerConfig.load(config_file)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("central_url", "https://mineguard.example/base", "central_url"),
        ("central_url", "http://mineguard.example", "central_url"),
        ("central_url", 123, "text fields"),
        ("node_code", "invalid node code", "node_code"),
        ("triton_url", "https://triton.example:8000", "triton_url"),
        ("person_classes", "person", "person_classes"),
        ("person_classes", [1], "person_classes"),
        ("heartbeat_seconds", "15", "heartbeat_seconds"),
        ("stream_stall_timeout_seconds", 10, "stream_stall_timeout_seconds"),
        ("model_manifest", "../outside/manifest.json", "configuration directory"),
    ],
)
def test_edge_worker_config_rejects_values_that_cannot_reconnect_to_central(
    tmp_path, monkeypatch, field, value, message
):
    payload = {
        "central_url": "https://mineguard.example",
        "node_code": "edge-test",
        "software_version": "0.1.0",
        "triton_url": "triton:8000",
        "model_manifest": "models/manifest.json",
        "model_root": "models",
        "cameras": [
            {
                "camera_id": 1,
                "code": "CAM-001",
                "area": "shaft-a",
                "stream_url": "rtsp://camera.local/cam001",
            }
        ],
    }
    payload[field] = value
    config_file = tmp_path / f"invalid-{field}.json"
    config_file.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("MINEGUARD_EDGE_KEY", VALID_EDGE_KEY)
    with pytest.raises(ValueError, match=message):
        EdgeWorkerConfig.load(config_file)


def test_edge_event_idempotency_key_is_fixed_length_and_deterministic():
    first = edge_event_idempotency_key(
        "n" * 64, 2**63 - 1, "e" * 40, 2**63 - 1, 1_787_600_000.123
    )
    repeated = edge_event_idempotency_key(
        "n" * 64, 2**63 - 1, "e" * 40, 2**63 - 1, 1_787_600_000.123
    )
    different = edge_event_idempotency_key(
        "n" * 64, 2**63 - 1, "e" * 40, 2**63 - 2, 1_787_600_000.123
    )
    assert first == repeated
    assert first != different
    assert len(first) == 69


def test_recent_reconnect_counter_prunes_old_attempts(monkeypatch):
    monkeypatch.setattr("app.edge.runtime.time.monotonic", lambda: 1000.0)
    timestamps = deque([699.0, 700.0, 850.0, 999.0])
    assert EdgeWorker._recent_reconnect_count(timestamps) == 3
    assert list(timestamps) == [700.0, 850.0, 999.0]


def test_outbox_capacity_backpressure_requests_stream_reset_after_recovery():
    class RecoveringOutbox:
        maximum_items = 1

        def __init__(self):
            self.attempts = 0

        def enqueue(self, _key, _event):
            self.attempts += 1
            if self.attempts == 1:
                raise OverflowError("capacity reached")
            return True

        def size(self):
            return 0

        def dead_letter_size(self):
            return 1 if self.attempts == 1 else 0

    async def scenario():
        worker = EdgeWorker.__new__(EdgeWorker)
        worker.config = SimpleNamespace(node_code="edge-backpressure")
        worker.outbox = RecoveringOutbox()
        worker._stop = asyncio.Event()
        state = SimpleNamespace(status="online", last_error=None)
        camera = CameraWorkerConfig(
            camera_id=1,
            code="CAM-001",
            area="shaft-a",
            stream_url="rtsp://camera.local/cam001",
        )
        assert await worker._enqueue_with_backpressure(
            camera, state, "event-1", {"event_type": "intrusion"}
        ) is True
        assert worker.outbox.attempts == 2
        assert state.status == "online"
        assert state.last_error is None

    asyncio.run(scenario())


def test_camera_reconnects_only_after_backpressured_frame_events_are_enqueued():
    class RecoveringOutbox:
        maximum_items = 2

        def __init__(self):
            self.attempts = 0
            self.enqueued = []

        def enqueue(self, key, _event):
            self.attempts += 1
            if self.attempts == 1:
                raise OverflowError("capacity reached")
            self.enqueued.append(key)

        def size(self):
            return len(self.enqueued)

        def dead_letter_size(self):
            return 0

    class Analyzer:
        def analyze(self, _frame, timestamp, _monotonic_timestamp):
            return 1, [
                {
                    "event_type": "intrusion",
                    "metadata_json": {"track_id": 1},
                },
                {
                    "event_type": "no_helmet",
                    "metadata_json": {"track_id": 1},
                },
            ]

    async def scenario():
        worker = EdgeWorker.__new__(EdgeWorker)
        worker.config = SimpleNamespace(node_code="edge-backpressure")
        worker.outbox = RecoveringOutbox()
        worker._stop = asyncio.Event()
        worker.states = {1: CameraRuntimeState()}
        camera = CameraWorkerConfig(
            camera_id=1,
            code="CAM-001",
            area="shaft-a",
            stream_url="rtsp://camera.local/cam001",
        )
        supervisor = worker._camera_supervisor(camera, Analyzer())

        with pytest.raises(StreamResetAfterBackpressure):
            await supervisor.on_frame(object())

        assert worker.outbox.attempts == 3
        assert len(worker.outbox.enqueued) == 2

    asyncio.run(scenario())


def test_camera_fps_counter_accumulates_until_window_is_complete(monkeypatch):
    class Outbox:
        def enqueue(self, _key, _event):
            return None

    class Analyzer:
        def analyze(self, _frame, _timestamp, _monotonic_timestamp):
            return 1, []

    async def scenario():
        clock = iter(
            [
                101.0,
                101.1,
                101.2,
                102.0,
                102.1,
                102.2,
                106.0,
                106.1,
                106.2,
                106.3,
            ]
        )
        monkeypatch.setattr(
            "app.edge.runtime.time.monotonic", lambda: next(clock)
        )
        worker = EdgeWorker.__new__(EdgeWorker)
        worker.config = SimpleNamespace(node_code="edge-fps")
        worker.outbox = Outbox()
        worker._stop = asyncio.Event()
        worker.states = {
            1: CameraRuntimeState(fps_window_started=100.0)
        }
        camera = CameraWorkerConfig(
            camera_id=1,
            code="CAM-001",
            area="shaft-a",
            stream_url="rtsp://camera.local/cam001",
        )
        supervisor = worker._camera_supervisor(camera, Analyzer())

        await supervisor.on_frame(object())
        await supervisor.on_frame(object())
        assert worker.states[1].frame_count == 2
        assert worker.states[1].fps == 0

        await supervisor.on_frame(object())
        assert worker.states[1].frame_count == 0
        assert worker.states[1].fps > 0

    asyncio.run(scenario())


def test_camera_degradation_clears_stale_people_and_fps():
    class Analyzer:
        def __init__(self):
            self.reset_called = False

        def reset(self):
            self.reset_called = True

    async def scenario():
        worker = EdgeWorker.__new__(EdgeWorker)
        worker.config = SimpleNamespace(node_code="edge-degraded")
        worker.states = {
            1: CameraRuntimeState(
                status="online",
                fps=25,
                latency_ms=80,
                count=7,
                frame_count=50,
            )
        }
        camera = CameraWorkerConfig(
            camera_id=1,
            code="CAM-001",
            area="shaft-a",
            stream_url="rtsp://camera.local/cam001",
        )
        analyzer = Analyzer()
        supervisor = worker._camera_supervisor(camera, analyzer)

        await supervisor.on_state(StreamState.DEGRADED, "ConnectionError")

        state = worker.states[1]
        assert state.status == "degraded"
        assert state.count == 0
        assert state.fps == 0
        assert state.latency_ms == 0
        assert state.frame_count == 0
        assert analyzer.reset_called is True

    asyncio.run(scenario())


def test_snapshot_upload_retry_reuses_persisted_reference_and_cleans_after_ack(
    tmp_path,
):
    key = "edge:" + "a" * 64
    reference = (
        "/snapshots/camera-1/2026/08/22/"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.jpg"
    )

    class RecoveringApi:
        def __init__(self):
            self.references = []
            self.upload_attempts = 0
            self.sent = []

        async def create_snapshot_upload(self, **values):
            self.references.append(values["reference"])
            return {"reference": values["reference"] or reference}

        async def upload_snapshot(self, _grant, _snapshot):
            self.upload_attempts += 1
            if self.upload_attempts == 1:
                raise ConnectionError("temporary object storage outage")

        async def send_event(self, idempotency_key, payload):
            self.sent.append((idempotency_key, payload))

    async def scenario():
        worker = EdgeWorker.__new__(EdgeWorker)
        worker.config = SimpleNamespace(snapshot_maximum_bytes=4096)
        worker.snapshot_spool_path = tmp_path / "snapshots"
        worker.snapshot_spool_path.mkdir()
        worker.outbox = PersistentOutbox(tmp_path / "outbox.db")
        worker.api = RecoveringApi()
        payload = {
            "camera_id": 1,
            "event_type": "intrusion",
            "metadata_json": {},
        }
        worker._attach_persisted_snapshot(key, payload, b"x" * 2048)
        assert worker.outbox.enqueue(key, payload) is True

        with pytest.raises(ConnectionError, match="temporary"):
            await worker._send_persisted_event(
                key, worker.outbox.due()[0].payload
            )
        persisted = worker.outbox.due()[0]
        assert persisted.payload["_snapshot"]["reference"] == reference
        assert worker.api.references == [None]

        await worker._send_persisted_event(key, persisted.payload)
        assert worker.api.references == [None, reference]
        assert worker.api.sent == [
            (
                key,
                {
                    "camera_id": 1,
                    "event_type": "intrusion",
                    "metadata_json": {},
                    "snapshot_url": reference,
                },
            )
        ]
        snapshot_path = worker._snapshot_path("a" * 64 + ".jpg")
        assert snapshot_path.exists()
        worker.outbox.acknowledge(persisted.id)
        worker._delete_acknowledged_snapshot(persisted)
        assert not snapshot_path.exists()

    asyncio.run(scenario())


def test_snapshot_startup_cleanup_only_removes_unreferenced_managed_files(
    tmp_path,
):
    worker = EdgeWorker.__new__(EdgeWorker)
    worker.config = SimpleNamespace(node_code="edge-snapshot-cleanup")
    worker.snapshot_spool_path = tmp_path / "snapshots"
    worker.snapshot_spool_path.mkdir()
    worker.outbox = PersistentOutbox(tmp_path / "outbox.db")
    retained = "c" * 64 + ".jpg"
    orphaned = "d" * 64 + ".jpg"
    unmanaged = "operator-note.jpg"
    for file_name in (retained, orphaned, unmanaged):
        (worker.snapshot_spool_path / file_name).write_bytes(b"snapshot")
    worker.outbox.enqueue(
        "retained-event",
        {"_snapshot": {"file_name": retained}},
    )

    worker._remove_orphaned_snapshots()

    assert (worker.snapshot_spool_path / retained).exists()
    assert not (worker.snapshot_spool_path / orphaned).exists()
    assert (worker.snapshot_spool_path / unmanaged).exists()


def test_fatal_child_task_stops_and_closes_edge_worker():
    class FailingOutbox:
        def due(self):
            raise RuntimeError("outbox failed")

        def size(self):
            return 0

    class FakeApi:
        def __init__(self):
            self.closed = False

        async def send_event(self, _key, _payload):
            return None

        async def heartbeat(self, _payload):
            await asyncio.Event().wait()

        async def close(self):
            self.closed = True

    class FakeGpu:
        def __init__(self):
            self.closed = False

        def sample(self):
            return 0.0, 0.0, True

        def close(self):
            self.closed = True

    async def scenario():
        worker = EdgeWorker.__new__(EdgeWorker)
        worker.config = SimpleNamespace(
            node_code="edge-fatal-test",
            cameras=(),
            person_classes=(),
            head_classes=(),
            helmet_classes=(),
            heartbeat_seconds=15,
            software_version="test",
        )
        worker.outbox = FailingOutbox()
        worker.manifest = SimpleNamespace(model_version="test", sha256="a" * 64)
        worker.api = FakeApi()
        worker.gpu = FakeGpu()
        worker.detectors = {}
        worker.states = {}
        worker.supervisors = []
        worker._central_reconnect_attempts_total = 0
        worker._central_reconnect_timestamps = deque()
        worker._stop = asyncio.Event()

        with pytest.raises(RuntimeError, match="outbox failed"):
            await asyncio.wait_for(worker.run(), timeout=1)
        assert worker._stop.is_set()
        assert worker.api.closed is True
        assert worker.gpu.closed is True

    asyncio.run(scenario())


def test_camera_progress_watchdog_tracks_each_camera_without_exiting(monkeypatch):
    current = 100.0
    monkeypatch.setattr("app.edge.runtime.time.monotonic", lambda: current)
    cameras = (
        CameraWorkerConfig(
            camera_id=1,
            code="CAM-WATCH-01",
            area="shaft-a",
            stream_url="rtsp://camera.local/watch-01",
        ),
        CameraWorkerConfig(
            camera_id=2,
            code="CAM-WATCH-02",
            area="shaft-b",
            stream_url="rtsp://camera.local/watch-02",
        ),
    )
    watchdog = CameraProgressWatchdog(cameras, 60, "edge-watchdog-test")

    assert watchdog.stale_camera_codes(now=160) == []
    current = 150
    watchdog.progress(1)
    assert watchdog.stale_camera_codes(now=160.001) == ["CAM-WATCH-02"]
    current = 200
    watchdog.progress(2)
    assert watchdog.stale_camera_codes(now=210) == []
    assert watchdog.stale_camera_codes(now=210.001) == ["CAM-WATCH-01"]
