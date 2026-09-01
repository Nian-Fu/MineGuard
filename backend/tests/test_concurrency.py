from datetime import UTC, datetime

from app.models import Camera, EdgeNode, FaceTemplate
from app.schemas import FaceTemplateRead


def test_camera_concurrency_token_ignores_live_telemetry():
    camera = Camera(
        code="TOKEN-CAM",
        name="Token camera",
        area="shaft-a",
        stream_url="rtsps://source/token?credential=secret",
        playback_path="/media/token-cam/index.m3u8",
        enabled_algorithms=["intrusion"],
        status="online",
        fps=25,
        latency_ms=50,
    )
    original = camera.concurrency_token
    camera.status = "degraded"
    camera.fps = 12
    camera.latency_ms = 500
    assert camera.concurrency_token == original
    camera.area = "shaft-b"
    assert camera.concurrency_token != original
    assert "secret" not in camera.concurrency_token


def test_edge_concurrency_token_ignores_heartbeat_telemetry_but_tracks_key_rotation():
    node = EdgeNode(
        code="token-edge",
        name="Token edge",
        api_key_hash="a" * 64,
        active=True,
        camera_ids=[2, 1],
        status="online",
        telemetry={"queue_depth": 0},
    )
    original = node.concurrency_token
    node.status = "degraded"
    node.telemetry = {"queue_depth": 5}
    assert node.concurrency_token == original
    node.api_key_hash = "b" * 64
    assert node.concurrency_token != original


def test_face_template_concurrency_token_tracks_mutable_state_without_embedding():
    template = FaceTemplate(
        id=7,
        person_id=3,
        provider="onnx",
        model_version="arcface-1",
        key_version="key-2026-08",
        encrypted_embedding=b"sensitive-template-bytes",
        nonce=b"0123456789ab",
        quality=0.91,
        liveness=0.95,
        consent_reference="consent-7",
        active=True,
        legal_hold=False,
        created_by=1,
        created_at=datetime(2026, 8, 21, tzinfo=UTC),
    )
    original = template.concurrency_token
    template.quality = 0.92
    template.liveness = 0.96
    assert template.concurrency_token == original
    template.legal_hold = True
    assert template.concurrency_token != original
    assert "sensitive" not in template.concurrency_token
    serialized = FaceTemplateRead.model_validate(template)
    assert serialized.concurrency_token == template.concurrency_token
