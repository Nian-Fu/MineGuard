import pytest
from pydantic import ValidationError

from app.schemas import (
    AlertRuleCreate,
    AlertRuleUpdate,
    AlgorithmUpdate,
    CameraCreate,
    CameraUpdate,
    EdgeHeartbeat,
    EdgeNodeCreate,
    EdgeNodeUpdate,
    EventCreate,
    LegalHoldUpdate,
    ModelArtifactApproval,
    ModelArtifactCreate,
    PersonUpdate,
    SnapshotVerifyRequest,
    UserUpdate,
)


def artifact_payload(**overrides):
    payload = {
        "name": "Detector",
        "algorithm_type": "object_detection",
        "model_version": "1.0.0",
        "sha256": "a" * 64,
        "runtime": "tensorrt-10",
        "license_id": "Apache-2.0",
        "source_repository": "https://github.com/example/detector",
        "source_commit": "b" * 40,
        "metrics": {"recall": 0.95},
    }
    payload.update(overrides)
    return payload


def test_camera_payload_normalizes_and_bounds_algorithm_identifiers():
    camera = CameraCreate(
        code="CAM-1",
        name="Camera one",
        area="shaft-a",
        stream_url="rtsp://source/camera-one",
        enabled_algorithms=[" intrusion ", "helmet"],
    )
    assert camera.enabled_algorithms == ["intrusion", "helmet"]
    with pytest.raises(ValidationError, match="enabled_algorithms"):
        CameraUpdate(enabled_algorithms=["intrusion", "intrusion"])
    with pytest.raises(ValidationError):
        CameraUpdate(area="")
    with pytest.raises(ValidationError, match="with a host"):
        CameraUpdate(stream_url="rtsp://")
    with pytest.raises(ValidationError, match="cannot be null"):
        CameraUpdate(name=None)


def test_algorithm_config_and_model_metrics_have_serialized_size_bounds():
    with pytest.raises(ValidationError, match="config cannot exceed 32 KiB"):
        AlgorithmUpdate(config={"payload": "x" * (33 * 1024)})
    with pytest.raises(ValidationError, match="invalid key or value"):
        ModelArtifactCreate(**artifact_payload(metrics={"recall": float("inf")}))
    with pytest.raises(ValidationError, match="metrics cannot exceed 16 KiB"):
        ModelArtifactCreate(
            **artifact_payload(
                metrics={f"metric_{index}": "x" * 200 for index in range(100)}
            )
        )
    with pytest.raises(ValidationError, match="without credentials"):
        ModelArtifactCreate(
            **artifact_payload(
                source_repository="https://user:secret@example.test/detector"
            )
        )
    with pytest.raises(ValidationError, match="without credentials, query"):
        ModelArtifactCreate(
            **artifact_payload(
                source_repository="https://example.test/detector?token=secret"
            )
        )


def test_alert_rule_normalizes_areas_and_rejects_inconsistent_channels():
    rule = AlertRuleCreate(
        name="Shaft intrusion",
        event_types=["intrusion"],
        areas=[" shaft-b ", "shaft-a"],
        channels=["console"],
    )
    assert rule.areas == ["shaft-a", "shaft-b"]
    with pytest.raises(ValidationError, match="duplicates"):
        AlertRuleCreate(
            name="Duplicate channels",
            event_types=["intrusion"],
            channels=["console", "console"],
        )


@pytest.mark.parametrize(
    "snapshot_url",
    [
        "javascript:alert(1)",
        "https://user:secret@example.test/snapshot.jpg",
        "https://example.test/snapshot.jpg?signature=secret",
        "https://objects.example.test/camera-1/event-42.jpg",
        "/snapshots/../secrets/file",
        "/snapshots/%2e%2e/secrets/file",
        "/snapshots\\camera-1\\file.jpg",
        "/snapshots/camera-1/2026/99/22/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg",
    ],
)
def test_event_rejects_unsafe_snapshot_references(snapshot_url):
    with pytest.raises(ValidationError, match="snapshot_url"):
        EventCreate(
            event_type="intrusion",
            severity="high",
            camera_id=1,
            title="Unsafe snapshot",
            confidence=0.9,
            snapshot_url=snapshot_url,
        )


def test_event_accepts_only_canonical_internal_snapshot_references():
    payload = {
        "event_type": "intrusion",
        "severity": "high",
        "camera_id": 1,
        "title": "Safe snapshot",
        "confidence": 0.9,
    }
    reference = (
        "/snapshots/camera-1/2026/08/22/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg"
    )
    assert EventCreate(
        **payload, snapshot_url=reference
    ).snapshot_url == reference
    with pytest.raises(ValidationError, match="enabled channel"):
        AlertRuleUpdate(
            channels=["console"],
            channel_targets={"sms": "shift-supervisor"},
        )


def test_snapshot_verify_requires_and_validates_the_internal_reference():
    payload = {
        "camera_id": 1,
        "content_type": "image/jpeg",
        "content_length": 2048,
        "sha256": "a" * 64,
    }
    reference = (
        "/snapshots/camera-1/2026/08/22/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jpg"
    )
    assert SnapshotVerifyRequest(**payload, reference=reference).reference == reference
    with pytest.raises(ValidationError, match="reference"):
        SnapshotVerifyRequest(**payload)
    with pytest.raises(ValidationError, match="snapshot_url"):
        SnapshotVerifyRequest(
            **payload,
            reference="https://objects.example.test/snapshot.jpg",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("camera_id", True),
        ("camera_id", "1"),
        ("person_id", False),
        ("person_id", "2"),
        ("confidence", True),
        ("confidence", "0.9"),
        ("confidence", float("nan")),
        ("confidence", float("inf")),
    ],
)
def test_event_rejects_coerced_or_non_finite_numeric_fields(field, value):
    payload = {
        "event_type": "intrusion",
        "severity": "high",
        "camera_id": 1,
        "title": "Numeric contract",
        "confidence": 0.9,
        field: value,
    }
    with pytest.raises(ValidationError):
        EventCreate(**payload)


def test_float_contracts_accept_json_integers():
    event = EventCreate(
        event_type="intrusion",
        severity="high",
        camera_id=1,
        title="Integer confidence",
        confidence=1,
    )
    assert event.confidence == 1.0
    assert AlgorithmUpdate(threshold=1).threshold == 1.0
    heartbeat = EdgeHeartbeat(
        software_version="1.0.0",
        gpu_utilization=0,
        gpu_memory_utilization=1,
        queue_depth=0,
        cameras=[
            {
                "camera_id": 1,
                "status": "degraded",
                "fps": 25,
                "latency_ms": 20,
                "errors": [
                    "snapshot_persistence_failed",
                    "ConnectionError",
                ],
            }
        ],
    )
    assert heartbeat.gpu_memory_utilization == 1.0
    assert heartbeat.cameras[0].fps == 25.0
    assert heartbeat.cameras[0].errors == [
        "ConnectionError",
        "snapshot_persistence_failed",
    ]
    with pytest.raises(ValidationError, match="stable codes"):
        EdgeHeartbeat(
            software_version="1.0.0",
            gpu_utilization=0,
            gpu_memory_utilization=0,
            queue_depth=0,
            cameras=[
                {
                    "camera_id": 1,
                    "status": "degraded",
                    "fps": 0,
                    "latency_ms": 0,
                    "errors": ["secret leaked in free-form text"],
                }
            ],
        )


@pytest.mark.parametrize("threshold", [True, "0.8", float("nan"), float("inf")])
def test_algorithm_threshold_rejects_coerced_or_non_finite_values(threshold):
    with pytest.raises(ValidationError):
        AlgorithmUpdate(threshold=threshold)


def test_model_metrics_reject_boolean_values_without_rejecting_numbers():
    with pytest.raises(ValidationError, match="invalid key or value"):
        ModelArtifactCreate(**artifact_payload(metrics={"passed": True}))
    artifact = ModelArtifactCreate(
        **artifact_payload(metrics={"samples": 42, "recall": 0.95})
    )
    assert artifact.metrics == {"samples": 42, "recall": 0.95}


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (UserUpdate, {"active": "false"}),
        (PersonUpdate, {"active": 0}),
        (LegalHoldUpdate, {"enabled": "true", "reason": "compliance hold"}),
        (AlgorithmUpdate, {"enabled": 1}),
        (ModelArtifactApproval, {"approved": "false", "reason": "not ready"}),
        (AlertRuleUpdate, {"enabled": "true"}),
        (EdgeNodeUpdate, {"active": 0}),
    ],
)
def test_control_plane_boolean_fields_reject_coerced_values(schema, payload):
    with pytest.raises(ValidationError):
        schema(**payload)


@pytest.mark.parametrize("cooldown", [True, 1.5, "60"])
def test_alert_rule_cooldown_rejects_coerced_values(cooldown):
    with pytest.raises(ValidationError):
        AlertRuleCreate(
            name="Strict cooldown",
            event_types=["intrusion"],
            channels=["console"],
            cooldown_seconds=cooldown,
        )
    with pytest.raises(ValidationError):
        AlertRuleUpdate(cooldown_seconds=cooldown)


@pytest.mark.parametrize("camera_ids", [[True], ["1"], [1.5]])
def test_edge_node_camera_ids_reject_coerced_identifiers(camera_ids):
    with pytest.raises(ValidationError, match="camera_ids"):
        EdgeNodeCreate(code="EDGE-1", name="Edge one", camera_ids=camera_ids)
    with pytest.raises(ValidationError, match="camera_ids"):
        EdgeNodeUpdate(camera_ids=camera_ids)


def test_edge_heartbeat_normalizes_areas_and_rejects_duplicate_normalized_keys():
    heartbeat = EdgeHeartbeat(
        software_version="1.0.0",
        gpu_utilization=0.4,
        gpu_memory_utilization=0.5,
        queue_depth=2,
        area_counts={" shaft-a ": 3},
    )
    assert heartbeat.area_counts == {"shaft-a": 3}
    with pytest.raises(ValidationError, match="area_counts"):
        EdgeHeartbeat(
            software_version="1.0.0",
            gpu_utilization=0.4,
            gpu_memory_utilization=0.5,
            queue_depth=2,
            area_counts={"shaft-a": 3, " shaft-a ": 4},
        )


def test_edge_heartbeat_accepts_configured_depth_and_rejects_impossible_total():
    heartbeat = EdgeHeartbeat(
        software_version="1.0.0",
        gpu_utilization=0.4,
        gpu_memory_utilization=0.5,
        queue_depth=1_500_000,
        dead_letter_depth=500_000,
        outbox_capacity=2_000_000,
    )
    assert heartbeat.queue_depth + heartbeat.dead_letter_depth == 2_000_000
    with pytest.raises(ValidationError, match="cannot exceed outbox_capacity"):
        EdgeHeartbeat(
            software_version="1.0.0",
            gpu_utilization=0.4,
            gpu_memory_utilization=0.5,
            queue_depth=9,
            dead_letter_depth=2,
            outbox_capacity=10,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("queue_depth", True),
        ("dead_letter_depth", 1.5),
        ("outbox_capacity", "100000"),
        ("gpu_utilization", False),
        ("gpu_utilization", "0.4"),
        ("gpu_memory_utilization", "0.5"),
        ("gpu_memory_utilization", float("nan")),
        ("gpu_memory_utilization", float("inf")),
        ("area_counts", {"shaft-a": True}),
    ],
)
def test_edge_heartbeat_rejects_coerced_numeric_telemetry(field, value):
    payload = {
        "software_version": "1.0.0",
        "gpu_utilization": 0.4,
        "gpu_memory_utilization": 0.5,
        "queue_depth": 0,
        field: value,
    }
    with pytest.raises(ValidationError):
        EdgeHeartbeat(**payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("camera_id", "1"),
        ("camera_id", True),
        ("fps", "25.0"),
        ("fps", False),
        ("fps", float("nan")),
        ("fps", float("inf")),
        ("latency_ms", "20"),
        ("latency_ms", True),
    ],
)
def test_camera_heartbeat_rejects_coerced_or_non_finite_telemetry(field, value):
    camera = {
        "camera_id": 1,
        "status": "online",
        "fps": 25.0,
        "latency_ms": 20,
        field: value,
    }
    with pytest.raises(ValidationError):
        EdgeHeartbeat(
            software_version="1.0.0",
            gpu_utilization=0.4,
            gpu_memory_utilization=0.5,
            queue_depth=0,
            cameras=[camera],
        )


def test_patch_models_reject_null_non_nullable_fields():
    with pytest.raises(ValidationError, match="cannot be null"):
        EdgeNodeUpdate(camera_ids=None)
    with pytest.raises(ValidationError, match="cannot be null"):
        UserUpdate(role=None)
    assert UserUpdate(permitted_areas=None).permitted_areas is None
