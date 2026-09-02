"""Run the documented offline benchmark for the bundled real video cases.

This command intentionally reports operational measurements only.  The source
videos do not have manual ground-truth annotations, so it must not be used to
claim precision, recall, or production-camera performance.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from app.edge.inference import Detection, TrackedDetection
from app.edge.runtime import CameraAnalyzer, CameraWorkerConfig


CASE_SOURCES = (
    {
        "id": "velenje-chairlift-exit",
        "title": "Velenje Coal Mine - Chairlift Exit",
        "scenario": "underground personnel passage",
        "video_file": "velenje-chairlift-exit-480p.webm",
        "source_url": "https://commons.wikimedia.org/wiki/File:The_Velenje_Coal_Mine,_Mine_chairlift,_exit.webm",
    },
    {
        "id": "velenje-chairlift-start",
        "title": "Velenje Coal Mine - Chairlift Start",
        "scenario": "underground personnel transport",
        "video_file": "velenje-chairlift-start-480p.webm",
        "source_url": "https://commons.wikimedia.org/wiki/File:The_Velenje_Coal_Mine,_Mine_chairlift,_starting_of_chairlift.webm",
    },
    {
        "id": "velenje-mine-locomotive",
        "title": "Velenje Coal Mine - Mine Locomotive Ride",
        "scenario": "underground auxiliary transport",
        "video_file": "velenje-mine-locomotive-480p.webm",
        "source_url": "https://commons.wikimedia.org/wiki/File:The_Velenje_Coal_Mine,_Ride_with_mine_locomotive.webm",
    },
)
ATTRIBUTION = "Sounds of Changes, via Wikimedia Commons"
LICENSE = "CC BY 3.0"


def percentile(values: list[float], fraction: float) -> float:
    """Return a deterministic linear-interpolated percentile."""
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower, upper = math.floor(position), math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def iou(first: Detection | TrackedDetection, second: Detection | TrackedDetection) -> float:
    left, top = max(first.left, second.left), max(first.top, second.top)
    right, bottom = min(first.right, second.right), min(first.bottom, second.bottom)
    intersection = max(0.0, right - left) * max(0.0, bottom - top)
    union = (
        (first.right - first.left) * (first.bottom - first.top)
        + (second.right - second.left) * (second.bottom - second.top)
        - intersection
    )
    return intersection / union if union > 0 else 0.0


class StableIouTracker:
    """Small deterministic tracker for offline rule-chain exercise."""

    def __init__(self, minimum_iou: float = 0.2) -> None:
        self.minimum_iou = minimum_iou
        self._next_id = 1
        self._previous: list[TrackedDetection] = []

    def reset(self) -> None:
        self._next_id = 1
        self._previous = []

    def update(self, detections: list[Detection]) -> list[TrackedDetection]:
        available = set(range(len(self._previous)))
        tracked: list[TrackedDetection] = []
        for detection in detections:
            candidates = [
                (iou(detection, self._previous[index]), index)
                for index in available
            ]
            overlap, index = max(candidates, default=(0.0, -1))
            if overlap >= self.minimum_iou:
                track_id = self._previous[index].track_id
                available.remove(index)
            else:
                track_id = self._next_id
                self._next_id += 1
            tracked.append(TrackedDetection(**detection.__dict__, track_id=track_id))
        self._previous = tracked
        return tracked


class HogPersonDetector:
    """OpenCV's built-in HOG people detector, adapted to the edge contract."""

    def __init__(self) -> None:
        import cv2

        self.cv2 = cv2
        self.hog = cv2.HOGDescriptor()
        self.hog.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())

    def detect(self, frame: Any) -> list[Detection]:
        boxes, weights = self.hog.detectMultiScale(
            frame, winStride=(8, 8), padding=(8, 8), scale=1.04
        )
        results = []
        for (left, top, width, height), weight in zip(boxes, weights, strict=False):
            # HOG emits an SVM margin, not a calibrated probability.  This value
            # exists solely because the existing rule interface requires one.
            confidence = 1 / (1 + math.exp(-float(weight)))
            results.append(
                Detection(
                    left=float(left), top=float(top), right=float(left + width),
                    bottom=float(top + height), confidence=confidence,
                    class_id=0, class_name="person",
                )
            )
        return results


@dataclass(frozen=True)
class BenchmarkOptions:
    video_root: Path
    output_path: Path
    max_samples_per_case: int = 360


def _analyzer(case_index: int) -> CameraAnalyzer:
    config = CameraWorkerConfig(
        camera_id=90_000 + case_index,
        code=f"OFFLINE-CASE-{case_index:02d}",
        area="Offline real-video case",
        stream_url="rtsp://offline.invalid/video-case",
        intrusion_polygon=((0.38, 0.22), (0.68, 0.22), (0.68, 0.95), (0.38, 0.95)),
        crowding_polygon=((0.12, 0.15), (0.88, 0.15), (0.88, 0.95), (0.12, 0.95)),
        crowding_threshold=3,
        intrusion_dwell_seconds=2.0,
        helmet_dwell_seconds=86_400.0,
    )
    return CameraAnalyzer(
        config=config,
        detector=HogPersonDetector(),
        person_classes=("person",),
        head_classes=("head",),
        helmet_classes=("helmet",),
        tracker=StableIouTracker(),
    )


def benchmark_case(source: dict[str, str], case_index: int, options: BenchmarkOptions) -> dict[str, Any]:
    import cv2

    path = options.video_root / source["video_file"]
    capture = cv2.VideoCapture(str(path))
    if not capture.isOpened():
        raise RuntimeError(f"OpenCV cannot open {path}")
    fps = float(capture.get(cv2.CAP_PROP_FPS) or 25.0)
    declared_frames = max(int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0), 1)
    interval = max(int(round(fps / 2)), math.ceil(declared_frames / options.max_samples_per_case), 1)
    analyzer = _analyzer(case_index)
    decoded = analyzed = frames_with_people = detected_people = 0
    latencies: list[float] = []
    events: Counter[str] = Counter()
    samples: list[dict[str, Any]] = []
    frame_index = 0
    started = perf_counter()
    while True:
        ok, frame = capture.read()
        if not ok:
            break
        decoded += 1
        if frame_index % interval == 0:
            inference_started = perf_counter()
            people, frame_events = analyzer.analyze(
                frame, timestamp=frame_index / fps, monotonic_timestamp=frame_index / fps
            )
            latencies.append((perf_counter() - inference_started) * 1000)
            analyzed += 1
            frames_with_people += int(people > 0)
            detected_people += people
            events.update(event["event_type"] for event in frame_events)
            if len(samples) < 12 and (people or frame_events):
                samples.append({
                    "frame": frame_index,
                    "timestamp_seconds": round(frame_index / fps, 2),
                    "people": people,
                    "events": [event["event_type"] for event in frame_events],
                })
        frame_index += 1
    capture.release()
    elapsed = perf_counter() - started
    return {
        **source,
        "source_attribution": ATTRIBUTION,
        "license": LICENSE,
        "video_path": f"/cases/{source['video_file']}",
        "metrics": {
            "decoded_frames": decoded,
            "analyzed_frames": analyzed,
            "frame_sampling_interval": interval,
            "source_fps": round(fps, 3),
            "frames_with_people": frames_with_people,
            "detection_coverage": round(frames_with_people / analyzed, 4) if analyzed else 0,
            "detected_people": detected_people,
            "rule_events": dict(sorted(events.items())),
            "latency_ms_mean": round(sum(latencies) / len(latencies), 2) if latencies else 0,
            "latency_ms_p50": round(percentile(latencies, 0.5), 2),
            "latency_ms_p95": round(percentile(latencies, 0.95), 2),
            "effective_analysis_fps": round(analyzed / elapsed, 2) if elapsed else 0,
        },
        "samples": samples,
    }


def run(options: BenchmarkOptions) -> dict[str, Any]:
    cases = [benchmark_case(source, index + 1, options) for index, source in enumerate(CASE_SOURCES)]
    manifest = {
        "title": "Offline real-video case benchmark",
        "generated_at": datetime.now(UTC).isoformat(),
        "method": "OpenCV HOG people detector + deterministic IoU tracking + MineGuard intrusion/crowding rules",
        "limitations": "No manual ground-truth annotations are included. Detection coverage and rule counts are operational observations, not precision, recall, or a production acceptance result.",
        "cases": cases,
    }
    options.output_path.parent.mkdir(parents=True, exist_ok=True)
    options.output_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--video-root", type=Path, default=Path("/cases"))
    parser.add_argument("--output", type=Path, default=Path("/results/manifest.json"))
    parser.add_argument("--max-samples", type=int, default=360)
    args = parser.parse_args()
    if not 1 <= args.max_samples <= 10_000:
        raise SystemExit("--max-samples must be between 1 and 10000")
    run(BenchmarkOptions(args.video_root, args.output, args.max_samples))


if __name__ == "__main__":
    main()
