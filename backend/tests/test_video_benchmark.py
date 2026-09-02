import pytest

from app.schemas import VideoCaseManifest
from app.video_benchmark import StableIouTracker, percentile
from app.edge.inference import Detection


def test_percentile_is_deterministic() -> None:
    assert percentile([], 0.95) == 0
    assert percentile([1, 3, 5, 7], 0.5) == 4
    assert percentile([1, 3, 5, 7], 0.95) == pytest.approx(6.7)


def test_tracker_preserves_id_for_overlapping_person() -> None:
    tracker = StableIouTracker()
    first = Detection(10, 10, 80, 180, 0.8, 0, "person")
    second = Detection(14, 12, 84, 182, 0.8, 0, "person")
    assert tracker.update([first])[0].track_id == 1
    assert tracker.update([second])[0].track_id == 1


def test_video_case_manifest_contract() -> None:
    manifest = VideoCaseManifest.model_validate({
        "title": "Offline real-video case benchmark",
        "generated_at": "2026-09-02T00:00:00+00:00",
        "method": "OpenCV HOG",
        "limitations": "No ground truth is included.",
        "cases": [{
            "id": "velenje-chairlift-exit", "title": "Chairlift", "scenario": "personnel passage",
            "video_file": "velenje-chairlift-exit-480p.webm", "video_path": "/cases/velenje-chairlift-exit-480p.webm",
            "source_url": "https://commons.wikimedia.org/wiki/File:example", "source_attribution": "Sounds of Changes", "license": "CC BY 3.0",
            "metrics": {"decoded_frames": 1, "analyzed_frames": 1, "frame_sampling_interval": 1, "source_fps": 25, "frames_with_people": 1, "detection_coverage": 1, "detected_people": 1, "rule_events": {}, "latency_ms_mean": 1, "latency_ms_p50": 1, "latency_ms_p95": 1, "effective_analysis_fps": 1},
            "samples": [],
        }],
    })
    assert manifest.cases[0].metrics.analyzed_frames == 1
