from types import SimpleNamespace

from app.edge.inference import Detection, TrackedDetection
from app.edge.runtime import CameraAnalyzer, CameraWorkerConfig


class FakeDetector:
    def detect(self, _):
        return [Detection(40, 20, 60, 90, 0.95, 0, "person")]


class FakeTracker:
    def update(self, _):
        return [TrackedDetection(40, 20, 60, 90, 0.95, 0, "person", 17)]


class FaceProbeDetector:
    def detect(self, _):
        return [
            Detection(40, 20, 60, 90, 0.95, 0, "person"),
            Detection(44, 22, 56, 38, 0.91, 1, "head"),
        ]


def test_camera_analyzer_emits_transition_and_dwell_events():
    config = CameraWorkerConfig(
        camera_id=1,
        code="CAM-001",
        area="主井口",
        stream_url="rtsp://camera.local/cam001",
        intrusion_polygon=((0.3, 0.1), (0.7, 0.1), (0.7, 1.0), (0.3, 1.0)),
        crowding_polygon=((0.3, 0.1), (0.7, 0.1), (0.7, 1.0), (0.3, 1.0)),
        crowding_threshold=1,
        intrusion_dwell_seconds=1,
        helmet_dwell_seconds=1,
    )
    analyzer = CameraAnalyzer(
        config,
        FakeDetector(),
        person_classes=("person",),
        head_classes=("head",),
        helmet_classes=("helmet",),
        tracker=FakeTracker(),
    )
    frame = SimpleNamespace(shape=(100, 100, 3))
    count, first_events = analyzer.analyze(frame, timestamp=10)
    assert count == 1
    assert [event["event_type"] for event in first_events] == ["crowding"]

    _, second_events = analyzer.analyze(frame, timestamp=11)
    assert {event["event_type"] for event in second_events} == {"intrusion", "no_helmet"}
    assert all(event["camera_id"] == 1 for event in second_events)

    _, third_events = analyzer.analyze(frame, timestamp=12)
    assert third_events == []


def test_camera_analyzer_resets_dwell_and_transition_state_after_disconnect():
    config = CameraWorkerConfig(
        camera_id=1,
        code="CAM-RESET",
        area="主井口",
        stream_url="rtsp://camera.local/reset",
        intrusion_polygon=((0.3, 0.1), (0.7, 0.1), (0.7, 1.0), (0.3, 1.0)),
        crowding_polygon=((0.3, 0.1), (0.7, 0.1), (0.7, 1.0), (0.3, 1.0)),
        crowding_threshold=1,
        intrusion_dwell_seconds=1,
        helmet_dwell_seconds=1,
    )
    analyzer = CameraAnalyzer(
        config,
        FakeDetector(),
        person_classes=("person",),
        head_classes=("head",),
        helmet_classes=("helmet",),
        tracker=FakeTracker(),
    )
    frame = SimpleNamespace(shape=(100, 100, 3))
    analyzer.analyze(frame, timestamp=100, monotonic_timestamp=10)
    analyzer.reset()

    _, recovered = analyzer.analyze(
        frame, timestamp=90, monotonic_timestamp=20
    )
    assert [event["event_type"] for event in recovered] == ["crowding"]
    _, after_dwell = analyzer.analyze(
        frame, timestamp=91, monotonic_timestamp=21
    )
    assert {event["event_type"] for event in after_dwell} == {
        "intrusion",
        "no_helmet",
    }
    assert all(
        event["occurred_at"].startswith("1970-01-01T00:01:31")
        for event in after_dwell
    )


def test_camera_analyzer_emits_one_face_probe_for_an_assigned_head():
    config = CameraWorkerConfig(
        camera_id=1,
        code="CAM-FACE",
        area="主井口",
        stream_url="rtsp://camera.local/face",
        face_recognition_enabled=True,
    )
    analyzer = CameraAnalyzer(
        config,
        FaceProbeDetector(),
        person_classes=("person",),
        head_classes=("head",),
        helmet_classes=("helmet",),
        tracker=FakeTracker(),
    )

    count, _, probes = analyzer.analyze_with_face_probes(
        SimpleNamespace(shape=(100, 100, 3)),
        timestamp=10,
    )

    assert count == 1
    assert len(probes) == 1
    assert probes[0].track_id == 17
    assert probes[0].confidence == 0.91
    assert probes[0].box.left == 44
