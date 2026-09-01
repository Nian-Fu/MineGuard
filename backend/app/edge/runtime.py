import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import random
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from math import isfinite
from pathlib import Path
from threading import Event as ThreadEvent, Lock, Thread
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.edge.inference import ByteTrackAdapter, Detection, TrackedDetection, TritonDetector
from app.edge.model_manifest import ModelManifest
from app.edge.outbox import OutboxDispatcher, PermanentDeliveryError, PersistentOutbox
from app.services.stream_supervisor import ReconnectPolicy, StreamState, StreamSupervisor
from app.vision.rules import (
    BoundingBox,
    HelmetRule,
    IntrusionRule,
    Point,
    Track,
    count_in_area,
    validate_polygon,
)

logger = logging.getLogger("mineguard.edge")
os.environ.setdefault("OPENCV_LOG_LEVEL", "SILENT")
os.environ.setdefault("OPENCV_FFMPEG_LOGLEVEL", "-8")


class StreamResetAfterBackpressure(ConnectionError):
    pass


def edge_event_idempotency_key(
    node_code: str,
    camera_id: int,
    event_type: str,
    track: object,
    timestamp: float,
) -> str:
    identity = (
        f"{node_code}:{camera_id}:{event_type}:{track}:{int(timestamp * 1000)}"
    )
    return f"edge:{hashlib.sha256(identity.encode('utf-8')).hexdigest()}"


@dataclass(frozen=True)
class CameraWorkerConfig:
    camera_id: int
    code: str
    area: str
    stream_url: str = field(repr=False)
    counting_authority: bool = True
    intrusion_polygon: tuple[tuple[float, float], ...] = ()
    crowding_polygon: tuple[tuple[float, float], ...] = ()
    crowding_threshold: int = 8
    intrusion_dwell_seconds: float = 2.0
    helmet_dwell_seconds: float = 1.0
    face_recognition_enabled: bool = False
    face_probe_interval_seconds: float = 5.0
    face_event_cooldown_seconds: float = 60.0

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CameraWorkerConfig":
        def polygon(name: str) -> tuple[tuple[float, float], ...]:
            raw = payload.get(name, [])
            if not isinstance(raw, list) or any(
                not isinstance(point, (list, tuple))
                or len(point) != 2
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    for value in point
                )
                for point in raw
            ):
                raise ValueError(f"{name} must contain at least three normalized points")
            if len(raw) > 100:
                raise ValueError(f"{name} cannot exceed 100 points")
            points = tuple((float(point[0]), float(point[1])) for point in raw)
            if points and (
                len(points) < 3
                or any(
                    not isfinite(value) or not 0 <= value <= 1
                    for point in points
                    for value in point
                )
            ):
                raise ValueError(f"{name} must contain at least three normalized points")
            if points:
                try:
                    validate_polygon([Point(*point) for point in points])
                except ValueError as exc:
                    raise ValueError(f"{name} geometry is invalid") from exc
            return points

        if (
            isinstance(payload.get("camera_id"), bool)
            or not isinstance(payload.get("camera_id"), int)
            or not isinstance(payload.get("stream_url"), str)
        ):
            raise ValueError("camera_id and RTSP stream_url are invalid")
        camera_id = payload["camera_id"]
        stream_url = payload["stream_url"]
        if (
            isinstance(payload.get("crowding_threshold", 8), bool)
            or not isinstance(payload.get("crowding_threshold", 8), int)
            or any(
                isinstance(payload.get(name, default), bool)
                or not isinstance(payload.get(name, default), (int, float))
                for name, default in (
                    ("intrusion_dwell_seconds", 2.0),
                    ("helmet_dwell_seconds", 1.0),
                )
            )
        ):
            raise ValueError("camera rule thresholds are invalid")
        crowding_threshold = payload.get("crowding_threshold", 8)
        try:
            intrusion_dwell_seconds = float(
                payload.get("intrusion_dwell_seconds", 2.0)
            )
            helmet_dwell_seconds = float(
                payload.get("helmet_dwell_seconds", 1.0)
            )
        except OverflowError as exc:
            raise ValueError("camera rule thresholds are invalid") from exc
        stream_parts = urlsplit(stream_url)
        if (
            not 1 <= camera_id <= 2**63 - 1
            or stream_parts.scheme.lower() not in {"rtsp", "rtsps"}
            or not stream_parts.hostname
            or stream_parts.fragment
            or any(char.isspace() for char in stream_url)
        ):
            raise ValueError("camera_id and RTSP stream_url are invalid")
        if not isinstance(payload.get("code"), str) or not isinstance(
            payload.get("area"), str
        ):
            raise ValueError("camera code and area are required")
        counting_authority = payload.get("counting_authority", True)
        if not isinstance(counting_authority, bool):
            raise ValueError("counting_authority must be boolean")
        face_recognition_enabled = payload.get("face_recognition_enabled", False)
        if not isinstance(face_recognition_enabled, bool):
            raise ValueError("face_recognition_enabled must be boolean")
        face_timing_values = (
            payload.get("face_probe_interval_seconds", 5.0),
            payload.get("face_event_cooldown_seconds", 60.0),
        )
        if any(
            isinstance(value, bool) or not isinstance(value, (int, float))
            for value in face_timing_values
        ):
            raise ValueError("face recognition timing values are invalid")
        face_probe_interval_seconds, face_event_cooldown_seconds = (
            float(value) for value in face_timing_values
        )
        code = payload["code"].strip()
        area = payload["area"].strip()
        if not code or len(code) > 50 or not area or len(area) > 100:
            raise ValueError("camera code and area are required")
        if (
            not 1 <= crowding_threshold <= 100_000
            or not isfinite(intrusion_dwell_seconds)
            or not isfinite(helmet_dwell_seconds)
            or not 0 <= intrusion_dwell_seconds <= 86400
            or not 0 <= helmet_dwell_seconds <= 86400
            or not isfinite(face_probe_interval_seconds)
            or not 0.5 <= face_probe_interval_seconds <= 300
            or not isfinite(face_event_cooldown_seconds)
            or not 1 <= face_event_cooldown_seconds <= 86400
        ):
            raise ValueError("camera rule thresholds are invalid")
        return cls(
            camera_id=camera_id,
            code=code,
            area=area,
            stream_url=stream_url,
            counting_authority=counting_authority,
            intrusion_polygon=polygon("intrusion_polygon"),
            crowding_polygon=polygon("crowding_polygon"),
            crowding_threshold=crowding_threshold,
            intrusion_dwell_seconds=intrusion_dwell_seconds,
            helmet_dwell_seconds=helmet_dwell_seconds,
            face_recognition_enabled=face_recognition_enabled,
            face_probe_interval_seconds=face_probe_interval_seconds,
            face_event_cooldown_seconds=face_event_cooldown_seconds,
        )


@dataclass(frozen=True)
class EdgeWorkerConfig:
    central_url: str
    node_code: str
    node_key: str = field(repr=False)
    software_version: str
    triton_url: str
    model_manifest_path: Path
    model_root: Path
    outbox_path: Path
    cameras: tuple[CameraWorkerConfig, ...]
    snapshot_spool_path: Path = Path("data/event-snapshots")
    event_snapshots_enabled: bool = False
    snapshot_jpeg_quality: int = 85
    snapshot_maximum_bytes: int = 8 * 1024 * 1024
    outbox_maximum_items: int = 100_000
    outbox_maximum_payload_bytes: int = 64 * 1024
    resolved_dead_letter_retention_days: int = 90
    heartbeat_seconds: float = 15.0
    stream_stall_timeout_seconds: float = 60.0
    person_classes: tuple[str, ...] = ("person",)
    head_classes: tuple[str, ...] = ("head",)
    helmet_classes: tuple[str, ...] = ("helmet", "hardhat", "hard_hat")

    @classmethod
    def load(cls, path: str | Path) -> "EdgeWorkerConfig":
        config_path = Path(path).resolve()
        if config_path.stat().st_size > 1024 * 1024:
            raise ValueError("edge configuration exceeds 1 MiB")
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("edge configuration must be a JSON object")
        node_key = os.environ.get("MINEGUARD_EDGE_KEY", "")
        if not node_key:
            raise ValueError("MINEGUARD_EDGE_KEY is required")
        if not re.fullmatch(r"mg_edge_[a-zA-Z0-9_-]{40,80}", node_key):
            raise ValueError("MINEGUARD_EDGE_KEY has an invalid service-key format")
        base = config_path.parent
        raw_cameras = payload["cameras"]
        if not isinstance(raw_cameras, list) or any(
            not isinstance(item, dict) for item in raw_cameras
        ):
            raise ValueError("cameras must be a list of camera configurations")
        cameras = tuple(CameraWorkerConfig.from_dict(item) for item in raw_cameras)
        camera_ids = [camera.camera_id for camera in cameras]
        camera_codes = [camera.code.lower() for camera in cameras]
        if (
            not cameras
            or len(cameras) > 256
            or len(camera_ids) != len(set(camera_ids))
            or len(camera_codes) != len(set(camera_codes))
        ):
            raise ValueError(
                "cameras must contain at most 256 unique identifiers and codes"
            )
        areas = {camera.area for camera in cameras}
        authority_areas = [
            camera.area for camera in cameras if camera.counting_authority
        ]
        if set(authority_areas) != areas or len(authority_areas) != len(areas):
            raise ValueError(
                "cameras must define exactly one counting authority per area"
            )
        raw_heartbeat_seconds = payload.get("heartbeat_seconds", 15)
        if (
            isinstance(raw_heartbeat_seconds, bool)
            or not isinstance(raw_heartbeat_seconds, (int, float))
        ):
            raise ValueError("heartbeat_seconds must be between 2 and 300")
        heartbeat_seconds = float(raw_heartbeat_seconds)
        if not isfinite(heartbeat_seconds) or not 2 <= heartbeat_seconds <= 300:
            raise ValueError("heartbeat_seconds must be between 2 and 300")
        raw_stall_timeout = payload.get("stream_stall_timeout_seconds", 60)
        if (
            isinstance(raw_stall_timeout, bool)
            or not isinstance(raw_stall_timeout, (int, float))
        ):
            raise ValueError("stream_stall_timeout_seconds must be between 30 and 600")
        stream_stall_timeout_seconds = float(raw_stall_timeout)
        if (
            not isfinite(stream_stall_timeout_seconds)
            or not 30 <= stream_stall_timeout_seconds <= 600
        ):
            raise ValueError("stream_stall_timeout_seconds must be between 30 and 600")

        def bounded_integer(name: str, default: int, minimum: int, maximum: int) -> int:
            value = payload.get(name, default)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(
                    f"{name} must be an integer between {minimum} and {maximum}"
                )
            return value

        outbox_maximum_items = bounded_integer(
            "outbox_maximum_items", 100_000, 1, 10_000_000
        )
        outbox_maximum_payload_bytes = bounded_integer(
            "outbox_maximum_payload_bytes", 64 * 1024, 1024, 1024 * 1024
        )
        resolved_dead_letter_retention_days = bounded_integer(
            "resolved_dead_letter_retention_days", 90, 1, 3650
        )
        snapshot_jpeg_quality = bounded_integer(
            "snapshot_jpeg_quality", 85, 50, 95
        )
        snapshot_maximum_bytes = bounded_integer(
            "snapshot_maximum_bytes", 8 * 1024 * 1024, 1024, 20 * 1024 * 1024
        )
        event_snapshots_enabled = payload.get("event_snapshots_enabled", False)
        if not isinstance(event_snapshots_enabled, bool):
            raise ValueError("event_snapshots_enabled must be boolean")
        required_text_fields = (
            "central_url",
            "node_code",
            "software_version",
            "triton_url",
            "model_manifest",
            "model_root",
        )
        if any(
            not isinstance(payload.get(name), str) or not payload[name].strip()
            for name in required_text_fields
        ) or any(
            not isinstance(payload.get(name, default), str)
            or not payload.get(name, default).strip()
            for name, default in (
                ("outbox_path", "data/event-outbox.db"),
                ("snapshot_spool_path", "data/event-snapshots"),
            )
        ):
            raise ValueError("edge configuration text fields are invalid")
        central_url = payload["central_url"].rstrip("/")
        central_parts = urlsplit(central_url)
        if (
            central_parts.scheme not in {"http", "https"}
            or not central_parts.hostname
            or (
                central_parts.scheme != "https"
                and central_parts.hostname not in {"localhost", "127.0.0.1", "::1"}
            )
            or central_parts.username is not None
            or central_parts.password is not None
            or central_parts.path
            or central_parts.query
            or central_parts.fragment
        ):
            raise ValueError(
                "central_url must use HTTPS (except loopback development) without credentials, query, or fragment"
            )
        node_code = payload["node_code"].strip()
        software_version = payload["software_version"].strip()
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{2,64}", node_code):
            raise ValueError("node_code must match the central node identifier format")
        if not software_version or len(software_version) > 100:
            raise ValueError("software_version must contain 1-100 characters")
        triton_url = payload["triton_url"].strip()
        triton_parts = urlsplit(f"http://{triton_url}")
        try:
            triton_port = triton_parts.port
        except ValueError as exc:
            raise ValueError("triton_url must be a host and TCP port") from exc
        if (
            not triton_parts.hostname
            or triton_port is None
            or not 1 <= triton_port <= 65535
            or triton_parts.username is not None
            or triton_parts.password is not None
            or triton_parts.path
            or triton_parts.query
            or triton_parts.fragment
        ):
            raise ValueError("triton_url must be a host and TCP port")

        def class_names(name: str, default: list[str]) -> tuple[str, ...]:
            raw_values = payload.get(name, default)
            if not isinstance(raw_values, list) or any(
                not isinstance(item, str) for item in raw_values
            ):
                raise ValueError(f"{name} contains invalid or duplicate class names")
            values = tuple(item.strip() for item in raw_values)
            if (
                not values
                or len(values) > 100
                or len(values) != len(set(values))
                or any(
                    not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", item)
                    for item in values
                )
            ):
                raise ValueError(f"{name} contains invalid or duplicate class names")
            return values
        model_manifest_path = (base / payload["model_manifest"]).resolve()
        model_root = (base / payload["model_root"]).resolve()
        if (
            not model_manifest_path.is_relative_to(base)
            or not model_root.is_relative_to(base)
            or not model_manifest_path.is_relative_to(model_root)
        ):
            raise ValueError(
                "model manifest and root must stay inside the edge configuration directory"
            )
        outbox_path = (
            base / payload.get("outbox_path", "data/event-outbox.db")
        ).resolve()
        snapshot_spool_path = (
            base / payload.get("snapshot_spool_path", "data/event-snapshots")
        ).resolve()
        if (
            snapshot_spool_path == Path(snapshot_spool_path.anchor)
            or snapshot_spool_path == outbox_path
        ):
            raise ValueError("snapshot_spool_path must be a dedicated directory")
        return cls(
            central_url=central_url,
            node_code=node_code,
            node_key=node_key,
            software_version=software_version,
            triton_url=triton_url,
            model_manifest_path=model_manifest_path,
            model_root=model_root,
            outbox_path=outbox_path,
            cameras=cameras,
            snapshot_spool_path=snapshot_spool_path,
            event_snapshots_enabled=event_snapshots_enabled,
            snapshot_jpeg_quality=snapshot_jpeg_quality,
            snapshot_maximum_bytes=snapshot_maximum_bytes,
            outbox_maximum_items=outbox_maximum_items,
            outbox_maximum_payload_bytes=outbox_maximum_payload_bytes,
            resolved_dead_letter_retention_days=(
                resolved_dead_letter_retention_days
            ),
            heartbeat_seconds=heartbeat_seconds,
            stream_stall_timeout_seconds=stream_stall_timeout_seconds,
            person_classes=class_names("person_classes", ["person"]),
            head_classes=class_names("head_classes", ["head"]),
            helmet_classes=class_names(
                "helmet_classes", ["helmet", "hardhat", "hard_hat"]
            ),
        )


@dataclass
class CameraRuntimeState:
    status: str = "offline"
    fps: float = 0.0
    latency_ms: int = 0
    count: int = 0
    last_error: str | None = None
    frame_count: int = 0
    fps_window_started: float = field(default_factory=time.monotonic)
    reconnect_attempts_total: int = 0
    reconnect_timestamps: deque[float] = field(default_factory=deque)
    stream_status: str = "offline"
    stream_error: str | None = None
    degradation_reasons: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.stream_status == "offline" and self.status != "offline":
            self.stream_status = self.status


@dataclass(frozen=True)
class FaceProbe:
    track_id: int
    box: BoundingBox
    confidence: float


class CameraProgressWatchdog:
    """Exit when a native capture or inference call makes no camera progress."""

    def __init__(
        self,
        cameras: tuple[CameraWorkerConfig, ...],
        timeout_seconds: float,
        node_code: str,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.node_code = node_code
        now = time.monotonic()
        self._camera_codes = {camera.camera_id: camera.code for camera in cameras}
        self._last_progress = {camera.camera_id: now for camera in cameras}
        self._lock = Lock()
        self._stop = ThreadEvent()
        self._thread = Thread(
            target=self._monitor,
            name="mineguard-edge-stream-watchdog",
            daemon=True,
        )

    def progress(self, camera_id: int) -> None:
        with self._lock:
            if camera_id in self._last_progress:
                self._last_progress[camera_id] = time.monotonic()

    def stale_camera_codes(self, now: float | None = None) -> list[str]:
        checked_at = time.monotonic() if now is None else now
        with self._lock:
            return sorted(
                self._camera_codes[camera_id]
                for camera_id, last_progress in self._last_progress.items()
                if checked_at - last_progress > self.timeout_seconds
            )

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def _monitor(self) -> None:
        interval = min(max(self.timeout_seconds / 4, 1), 5)
        while not self._stop.wait(interval):
            stale = self.stale_camera_codes()
            if not stale:
                continue
            logger.critical(
                "edge_stream_watchdog_stalled node=%s cameras=%s timeout_seconds=%s",
                self.node_code,
                ",".join(stale),
                self.timeout_seconds,
            )
            os._exit(70)


class OpenCVStreamConnector:
    def __init__(self, stream_url: str, open_timeout_ms: int = 10_000, read_timeout_ms: int = 10_000) -> None:
        self.stream_url = stream_url
        self.open_timeout_ms = open_timeout_ms
        self.read_timeout_ms = read_timeout_ms

    async def __call__(self):
        capture = await asyncio.to_thread(self._open)

        async def frames():
            try:
                while True:
                    ok, frame = await asyncio.to_thread(capture.read)
                    if not ok or frame is None:
                        raise ConnectionError("RTSP frame read failed")
                    yield frame
            finally:
                await asyncio.to_thread(capture.release)

        return frames()

    def _open(self):
        try:
            import cv2
        except ImportError as exc:
            raise RuntimeError("install mineguard-api[edge] on inference nodes") from exc
        capture = cv2.VideoCapture()
        parameters = []
        if hasattr(cv2, "CAP_PROP_OPEN_TIMEOUT_MSEC"):
            parameters.extend([cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, self.open_timeout_ms])
        if hasattr(cv2, "CAP_PROP_READ_TIMEOUT_MSEC"):
            parameters.extend([cv2.CAP_PROP_READ_TIMEOUT_MSEC, self.read_timeout_ms])
        if not capture.open(self.stream_url, cv2.CAP_FFMPEG, parameters):
            capture.release()
            raise ConnectionError("RTSP stream open failed")
        return capture


class CameraAnalyzer:
    def __init__(
        self,
        config: CameraWorkerConfig,
        detector: TritonDetector,
        person_classes: tuple[str, ...],
        head_classes: tuple[str, ...],
        helmet_classes: tuple[str, ...],
        tracker: Any | None = None,
    ) -> None:
        self.config = config
        self.detector = detector
        self.person_classes = set(person_classes)
        self.head_classes = set(head_classes)
        self.helmet_classes = set(helmet_classes)
        self.tracker = tracker or ByteTrackAdapter()
        self.helmet_rule = HelmetRule(config.helmet_dwell_seconds)
        self.intrusion_rule: IntrusionRule | None = None
        self.crowding_polygon: list[Point] = []
        self._frame_shape: tuple[int, int] | None = None
        self._crowding_active = False

    def analyze(
        self,
        frame,
        timestamp: float,
        monotonic_timestamp: float | None = None,
    ) -> tuple[int, list[dict[str, Any]]]:
        count, events, _ = self.analyze_with_face_probes(
            frame,
            timestamp,
            monotonic_timestamp,
        )
        return count, events

    def analyze_with_face_probes(
        self,
        frame,
        timestamp: float,
        monotonic_timestamp: float | None = None,
    ) -> tuple[int, list[dict[str, Any]], list[FaceProbe]]:
        rule_timestamp = timestamp if monotonic_timestamp is None else monotonic_timestamp
        self._configure_geometry(frame.shape[1], frame.shape[0])
        detections = self.detector.detect(frame)
        tracked = self.tracker.update([item for item in detections if item.class_name in self.person_classes])
        people = [self._track(item) for item in tracked]
        head_detections = [
            item for item in detections if item.class_name in self.head_classes
        ]
        heads = [self._box(item) for item in head_detections]
        helmets = [self._box(item) for item in detections if item.class_name in self.helmet_classes]
        events: list[dict[str, Any]] = []

        if self.intrusion_rule:
            for intrusion in self.intrusion_rule.evaluate(people, rule_timestamp):
                events.append(self._event(
                    "intrusion", "high", "检测到限制区域入侵", intrusion.confidence,
                    timestamp, {"track_id": intrusion.track_id, "dwell_seconds": round(intrusion.dwell_seconds, 3)},
                ))
        for violation in self.helmet_rule.evaluate(
            people, helmets, rule_timestamp, heads
        ):
            events.append(self._event(
                "no_helmet", "high", "检测到未佩戴安全帽人员", violation.confidence,
                timestamp, {"track_id": violation.track_id, "missing_seconds": round(violation.missing_seconds, 3)},
            ))
        if self.crowding_polygon:
            crowd = count_in_area(people, self.crowding_polygon, self.config.crowding_threshold)
            if crowd.exceeded and not self._crowding_active:
                confidence = max((person.confidence for person in people if person.track_id in crowd.track_ids), default=1.0)
                events.append(self._event(
                    "crowding", "critical", "检测到区域人员聚集", confidence,
                    timestamp, {"count": crowd.count, "track_ids": list(crowd.track_ids)},
                ))
            self._crowding_active = crowd.exceeded
        return len(people), events, self._face_probes(people, head_detections)

    def reset(self) -> None:
        reset_tracker = getattr(self.tracker, "reset", None)
        if callable(reset_tracker):
            reset_tracker()
        self.helmet_rule = HelmetRule(self.config.helmet_dwell_seconds)
        self.intrusion_rule = None
        self.crowding_polygon = []
        self._frame_shape = None
        self._crowding_active = False

    def _configure_geometry(self, width: int, height: int) -> None:
        if self._frame_shape == (width, height):
            return
        self._frame_shape = (width, height)

        def scale(points: tuple[tuple[float, float], ...]) -> list[Point]:
            return [Point(x * width, y * height) for x, y in points]

        intrusion_polygon = scale(self.config.intrusion_polygon)
        self.intrusion_rule = (
            IntrusionRule(intrusion_polygon, self.config.intrusion_dwell_seconds)
            if intrusion_polygon else None
        )
        self.crowding_polygon = scale(self.config.crowding_polygon)

    def _event(
        self,
        event_type: str,
        severity: str,
        title: str,
        confidence: float,
        timestamp: float,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "event_type": event_type,
            "severity": severity,
            "camera_id": self.config.camera_id,
            "title": title,
            "description": f"{self.config.area} · {self.config.code}",
            "confidence": min(max(float(confidence), 0.0), 1.0),
            "occurred_at": datetime.fromtimestamp(timestamp, UTC).isoformat(),
            "metadata_json": metadata,
        }

    @classmethod
    def _face_probes(
        cls,
        people: list[Track],
        heads: list[Detection],
    ) -> list[FaceProbe]:
        candidates = sorted(
            (
                cls._center_distance_squared(person.box, cls._box(head)),
                person.track_id,
                head_index,
                person,
            )
            for person in people
            for head_index, head in enumerate(heads)
            if cls._head_matches_person(cls._box(head), person.box)
        )
        assigned_tracks: set[int] = set()
        assigned_heads: set[int] = set()
        probes = []
        for _, track_id, head_index, person in candidates:
            if track_id in assigned_tracks or head_index in assigned_heads:
                continue
            assigned_tracks.add(track_id)
            assigned_heads.add(head_index)
            head = heads[head_index]
            probes.append(
                FaceProbe(
                    track_id=track_id,
                    box=cls._box(head),
                    confidence=min(person.confidence, head.confidence),
                )
            )
        return probes

    @staticmethod
    def _head_matches_person(head: BoundingBox, person: BoundingBox) -> bool:
        center_x = (head.left + head.right) / 2
        center_y = (head.top + head.bottom) / 2
        upper_bottom = person.top + (person.bottom - person.top) * 0.45
        return (
            person.left <= center_x <= person.right
            and person.top <= center_y <= upper_bottom
        )

    @staticmethod
    def _center_distance_squared(first: BoundingBox, second: BoundingBox) -> float:
        first_x = (first.left + first.right) / 2
        first_y = (first.top + first.bottom) / 2
        second_x = (second.left + second.right) / 2
        second_y = (second.top + second.bottom) / 2
        return (first_x - second_x) ** 2 + (first_y - second_y) ** 2

    @staticmethod
    def _box(item: Detection | TrackedDetection) -> BoundingBox:
        return BoundingBox(item.left, item.top, item.right, item.bottom)

    @classmethod
    def _track(cls, item: TrackedDetection) -> Track:
        return Track(item.track_id, cls._box(item), item.confidence)


class EdgeApiClient:
    def __init__(self, config: EdgeWorkerConfig) -> None:
        self.client = httpx.AsyncClient(
            base_url=f"{config.central_url}/api/v1/",
            headers={"X-Edge-Node": config.node_code, "X-Edge-Key": config.node_key},
            timeout=httpx.Timeout(15, connect=10),
        )
        self.upload_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30, connect=10),
            follow_redirects=False,
        )

    async def identify_face(
        self,
        *,
        camera_id: int,
        image: bytes,
    ) -> dict[str, Any] | None:
        async with self.client.stream(
            "POST",
            "faces/edge-identify",
            data={"camera_id": str(camera_id)},
            files={"image": ("face-probe.jpg", image, "image/jpeg")},
        ) as response:
            if response.status_code == 422:
                await response.aclose()
                return None
            response.raise_for_status()
            declared_length = response.headers.get("content-length")
            if declared_length is not None:
                try:
                    parsed_length = int(declared_length)
                except ValueError as exc:
                    raise ValueError(
                        "face identification Content-Length is invalid"
                    ) from exc
                if parsed_length < 0:
                    raise ValueError(
                        "face identification Content-Length is invalid"
                    )
                if parsed_length > 64 * 1024:
                    raise ValueError("face identification response is oversized")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > 64 * 1024:
                    raise ValueError("face identification response is oversized")
        try:
            result = json.loads(body)
        except (TypeError, ValueError) as exc:
            raise ValueError("face identification response is invalid JSON") from exc
        self._validate_face_identification(result)
        return result

    @staticmethod
    def _validate_face_identification(result: Any) -> None:
        if not isinstance(result, dict):
            raise ValueError("face identification response must be an object")
        if set(result) != {
            "matched",
            "unknown",
            "quality",
            "liveness",
            "model_version",
            "model_sha256",
            "authorized_for_camera",
            "candidate",
        }:
            raise ValueError("face identification response violates its contract")
        matched = result.get("matched")
        unknown = result.get("unknown")
        scores = (result.get("quality"), result.get("liveness"))
        model_version = result.get("model_version")
        model_sha256 = result.get("model_sha256")
        candidate = result.get("candidate")
        authorized = result.get("authorized_for_camera")
        if (
            not isinstance(matched, bool)
            or not isinstance(unknown, bool)
            or matched == unknown
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not isfinite(value)
                or not 0 <= value <= 1
                for value in scores
            )
            or not isinstance(model_version, str)
            or not 1 <= len(model_version) <= 100
            or not isinstance(model_sha256, str)
            or not re.fullmatch(r"[a-f0-9]{64}", model_sha256)
        ):
            raise ValueError("face identification response violates its contract")
        if unknown:
            if candidate is not None or authorized is not None:
                raise ValueError("unknown face response contains a candidate")
            return
        if (
            not isinstance(candidate, dict)
            or set(candidate) != {"person_id", "similarity"}
            or isinstance(candidate.get("person_id"), bool)
            or not isinstance(candidate.get("person_id"), int)
            or candidate["person_id"] < 1
            or isinstance(candidate.get("similarity"), bool)
            or not isinstance(candidate.get("similarity"), (int, float))
            or not isfinite(candidate["similarity"])
            or not 0 <= candidate["similarity"] <= 1
            or not isinstance(authorized, bool)
        ):
            raise ValueError("matched face response contains an invalid candidate")

    async def create_snapshot_upload(
        self,
        *,
        camera_id: int,
        content_length: int,
        sha256_hex: str,
        reference: str | None,
    ) -> dict[str, Any]:
        payload = {
            "camera_id": camera_id,
            "content_type": "image/jpeg",
            "content_length": content_length,
            "sha256": sha256_hex,
            "reference": reference,
        }
        async with self.client.stream(
            "POST", "edge/snapshots/upload", json=payload
        ) as response:
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if response.status_code in {400, 413, 415, 422}:
                    raise PermanentDeliveryError(
                        f"snapshot_grant_rejected_{response.status_code}"
                    ) from exc
                raise
            body = await response.aread()
        if len(body) > 64 * 1024:
            raise ValueError("snapshot upload grant exceeds 64 KiB")
        try:
            grant = json.loads(body)
        except (TypeError, ValueError) as exc:
            raise ValueError("snapshot upload grant is not valid JSON") from exc
        self._validate_snapshot_grant(
            grant,
            camera_id=camera_id,
            content_length=content_length,
            sha256_hex=sha256_hex,
            requested_reference=reference,
        )
        return grant

    async def upload_snapshot(
        self, grant: dict[str, Any], snapshot_bytes: bytes
    ) -> None:
        response = await self.upload_client.put(
            grant["upload_url"],
            content=snapshot_bytes,
            headers=grant["required_headers"],
        )
        if response.status_code == 412:
            reference_match = re.fullmatch(
                r"/snapshots/camera-([1-9][0-9]{0,18})/[0-9]{4}/[0-9]{2}/[0-9]{2}/[a-f0-9]{32}\.jpg",
                grant["reference"],
            )
            if not reference_match:
                raise ValueError("snapshot reference changed after grant validation")
            await self.verify_snapshot(
                camera_id=int(reference_match.group(1)),
                content_length=len(snapshot_bytes),
                sha256_hex=hashlib.sha256(snapshot_bytes).hexdigest(),
                reference=grant["reference"],
            )
            return
        response.raise_for_status()

    async def verify_snapshot(
        self,
        *,
        camera_id: int,
        content_length: int,
        sha256_hex: str,
        reference: str,
    ) -> None:
        payload = {
            "camera_id": camera_id,
            "content_type": "image/jpeg",
            "content_length": content_length,
            "sha256": sha256_hex,
            "reference": reference,
        }
        async with self.client.stream(
            "POST", "edge/snapshots/verify", json=payload
        ) as response:
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if response.status_code in {400, 413, 415, 422}:
                    raise PermanentDeliveryError(
                        f"snapshot_verification_rejected_{response.status_code}"
                    ) from exc
                raise

    @staticmethod
    def _validate_snapshot_grant(
        grant: Any,
        *,
        camera_id: int,
        content_length: int,
        sha256_hex: str,
        requested_reference: str | None,
    ) -> None:
        if not isinstance(grant, dict):
            raise ValueError("snapshot upload grant must be an object")
        reference = grant.get("reference")
        reference_match = re.fullmatch(
            r"/snapshots/camera-([1-9][0-9]{0,18})/[0-9]{4}/[0-9]{2}/[0-9]{2}/[a-f0-9]{32}\.jpg",
            reference if isinstance(reference, str) else "",
        )
        upload_url = grant.get("upload_url")
        url_parts = urlsplit(upload_url if isinstance(upload_url, str) else "")
        headers = grant.get("required_headers")
        expires = grant.get("expires_in_seconds")
        checksum = base64.b64encode(bytes.fromhex(sha256_hex)).decode("ascii")
        expected_headers = {
            "Content-Type": "image/jpeg",
            "Content-Length": str(content_length),
            "x-amz-checksum-sha256": checksum,
            "If-None-Match": "*",
            "x-amz-server-side-encryption": "AES256",
            "x-amz-tagging": "mineguard-legal-hold=false",
        }
        if (
            not reference_match
            or int(reference_match.group(1)) != camera_id
            or requested_reference is not None
            and reference != requested_reference
            or not isinstance(upload_url, str)
            or len(upload_url) > 16 * 1024
            or url_parts.scheme not in {"http", "https"}
            or not url_parts.hostname
            or url_parts.username is not None
            or url_parts.password is not None
            or bool(url_parts.fragment)
            or (
                url_parts.scheme != "https"
                and url_parts.hostname not in {"localhost", "127.0.0.1", "::1"}
            )
            or headers != expected_headers
            or isinstance(expires, bool)
            or not isinstance(expires, int)
            or not 60 <= expires <= 900
        ):
            raise ValueError("snapshot upload grant violates the edge contract")

    async def send_event(self, idempotency_key: str, payload: dict[str, Any]) -> None:
        async with self.client.stream(
            "POST",
            "edge/events",
            json=payload,
            headers={"Idempotency-Key": idempotency_key},
        ) as response:
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                if response.status_code in {400, 413, 415, 422}:
                    raise PermanentDeliveryError(
                        f"central_rejected_{response.status_code}"
                    ) from exc
                raise

    async def heartbeat(self, payload: dict[str, Any]) -> None:
        async with self.client.stream(
            "POST", "edge/heartbeat", json=payload
        ) as response:
            response.raise_for_status()

    async def close(self) -> None:
        clients = [self.client]
        if upload_client := getattr(self, "upload_client", None):
            clients.append(upload_client)
        await asyncio.gather(*(client.aclose() for client in clients))


class GpuTelemetry:
    def __init__(self) -> None:
        self.pynvml = None
        self.handle = None
        try:
            import pynvml

            pynvml.nvmlInit()
            self.pynvml = pynvml
            self.handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        except Exception:
            self.pynvml = None
            self.handle = None

    def sample(self) -> tuple[float, float, bool]:
        if not self.pynvml or self.handle is None:
            return 0.0, 0.0, False
        try:
            utilization = self.pynvml.nvmlDeviceGetUtilizationRates(self.handle)
            memory = self.pynvml.nvmlDeviceGetMemoryInfo(self.handle)
            return (
                utilization.gpu / 100,
                memory.used / max(memory.total, 1),
                True,
            )
        except Exception:
            return 0.0, 0.0, False

    def close(self) -> None:
        if self.pynvml:
            try:
                self.pynvml.nvmlShutdown()
            except Exception:
                pass


class EdgeWorker:
    def __init__(self, config: EdgeWorkerConfig) -> None:
        self.config = config
        config.outbox_path.parent.mkdir(parents=True, exist_ok=True)
        self.outbox = PersistentOutbox(
            config.outbox_path,
            maximum_items=config.outbox_maximum_items,
            maximum_payload_bytes=config.outbox_maximum_payload_bytes,
            resolved_dead_letter_retention_days=(
                config.resolved_dead_letter_retention_days
            ),
        )
        self.snapshot_spool_path = config.snapshot_spool_path
        if config.event_snapshots_enabled:
            self.snapshot_spool_path.mkdir(parents=True, exist_ok=True)
            self._remove_orphaned_snapshots()
        self.manifest = ModelManifest.load(config.model_manifest_path, config.model_root)
        self.manifest.verify_artifact()
        self.detectors = {
            camera.camera_id: TritonDetector(
                config.triton_url, self.manifest, verify_artifact=False
            )
            for camera in config.cameras
        }
        self.api = EdgeApiClient(config)
        self.gpu = GpuTelemetry()
        self.states = {camera.camera_id: CameraRuntimeState() for camera in config.cameras}
        self.supervisors: list[StreamSupervisor] = []
        self._central_reconnect_attempts_total = 0
        self._central_reconnect_timestamps: deque[float] = deque()
        self._next_dead_letter_prune = 0.0
        self._face_tasks: dict[int, asyncio.Task] = {}
        self._face_last_probe: dict[tuple[int, int], float] = {}
        self._face_last_event: dict[tuple[int, str], float] = {}
        self._stop = asyncio.Event()

    async def run(self) -> None:
        logger.info(
            "edge_worker_started node=%s cameras=%d model=%s sha256=%s",
            self.config.node_code,
            len(self.config.cameras),
            self.manifest.model_version,
            self.manifest.sha256[:12],
        )
        dispatcher = OutboxDispatcher(
            self.outbox,
            self._send_persisted_event,
            acknowledged=self._delete_acknowledged_snapshot,
        )
        self._stream_watchdog = CameraProgressWatchdog(
            self.config.cameras,
            getattr(self.config, "stream_stall_timeout_seconds", 60),
            self.config.node_code,
        )
        self._stream_watchdog.start()
        for camera in self.config.cameras:
            analyzer = CameraAnalyzer(
                camera,
                self.detectors[camera.camera_id],
                self.config.person_classes,
                self.config.head_classes,
                self.config.helmet_classes,
            )
            supervisor = self._camera_supervisor(camera, analyzer)
            self.supervisors.append(supervisor)
        tasks = [
            asyncio.create_task(dispatcher.run()),
            asyncio.create_task(self._heartbeat_loop()),
            *(asyncio.create_task(supervisor.run()) for supervisor in self.supervisors),
        ]
        stop_task = asyncio.create_task(self._stop.wait())
        try:
            done, _ = await asyncio.wait([*tasks, stop_task], return_when=asyncio.FIRST_COMPLETED)
            failed = next((task for task in done if task is not stop_task), None)
            if failed:
                exception = failed.exception()
                raise exception or RuntimeError("edge worker task stopped unexpectedly")
        finally:
            self._stop.set()
            self._stream_watchdog.close()
            stop_task.cancel()
            await asyncio.gather(stop_task, return_exceptions=True)
            dispatcher.stop()
            for supervisor in self.supervisors:
                await supervisor.stop()
            for task in tasks:
                if not task.done():
                    task.cancel()
            for task in self._face_tasks.values():
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.gather(
                *self._face_tasks.values(), return_exceptions=True
            )
            self._face_tasks.clear()
            await self.api.close()
            self.gpu.close()
            logger.info("edge_worker_stopped node=%s", self.config.node_code)

    def stop(self) -> None:
        self._stop.set()

    def _camera_supervisor(
        self, camera: CameraWorkerConfig, analyzer: CameraAnalyzer
    ) -> StreamSupervisor:
        state = self.states[camera.camera_id]

        async def on_frame(frame) -> None:
            self._record_camera_progress(camera.camera_id)
            started = time.monotonic()
            timestamp = time.time()
            count, events, face_probes = await asyncio.to_thread(
                analyzer.analyze_with_face_probes,
                frame,
                timestamp,
                started,
            )
            state.count = count
            state.latency_ms = round((time.monotonic() - started) * 1000)
            state.frame_count += 1
            if camera.face_recognition_enabled:
                self._schedule_face_probe(
                    camera,
                    state,
                    frame,
                    face_probes,
                    timestamp,
                )
            window = time.monotonic() - state.fps_window_started
            if window >= 5:
                state.fps = round(state.frame_count / window, 2)
                state.frame_count = 0
                state.fps_window_started = time.monotonic()
            reset_stream = False
            snapshot_bytes: bytes | None = None
            if events and getattr(
                self.config, "event_snapshots_enabled", False
            ):
                try:
                    snapshot_bytes = await asyncio.to_thread(
                        self._encode_snapshot,
                        frame,
                        self.config.snapshot_jpeg_quality,
                        self.config.snapshot_maximum_bytes,
                    )
                except Exception as exc:
                    self._mark_camera_issue(state, "snapshot_persistence_failed")
                    logger.warning(
                        "edge_snapshot_encode_failed node=%s camera=%s error_type=%s",
                        self.config.node_code,
                        camera.code,
                        type(exc).__name__,
                    )
            for event in events:
                track = event["metadata_json"].get("track_id", "area")
                key = edge_event_idempotency_key(
                    self.config.node_code,
                    camera.camera_id,
                    event["event_type"],
                    track,
                    timestamp,
                )
                if snapshot_bytes is not None:
                    try:
                        await asyncio.to_thread(
                            self._attach_persisted_snapshot,
                            key,
                            event,
                            snapshot_bytes,
                        )
                        self._clear_camera_issue(
                            state, "snapshot_persistence_failed"
                        )
                    except Exception as exc:
                        self._mark_camera_issue(
                            state, "snapshot_persistence_failed"
                        )
                        logger.warning(
                            "edge_snapshot_persist_failed node=%s camera=%s error_type=%s",
                            self.config.node_code,
                            camera.code,
                            type(exc).__name__,
                        )
                recovered_from_backpressure = await self._enqueue_with_backpressure(
                    camera, state, key, event
                )
                if recovered_from_backpressure is None:
                    return
                reset_stream = reset_stream or recovered_from_backpressure
            if reset_stream:
                raise StreamResetAfterBackpressure

        async def on_state(stream_state: StreamState, error: str | None) -> None:
            self._record_camera_progress(camera.camera_id)
            state.stream_status = {
                StreamState.ONLINE: "online",
                StreamState.CONNECTING: "degraded",
                StreamState.DEGRADED: "degraded",
                StreamState.OFFLINE: "offline",
                StreamState.STOPPED: "offline",
            }[stream_state]
            state.stream_error = error
            self._refresh_camera_state(state)
            if error:
                state.count = 0
                state.fps = 0.0
                state.latency_ms = 0
                state.frame_count = 0
                state.fps_window_started = time.monotonic()
                analyzer.reset()
                self._reset_face_state(camera.camera_id)
                state.reconnect_attempts_total += 1
                state.reconnect_timestamps.append(time.monotonic())
                logger.warning(
                    "camera_stream_degraded node=%s camera=%s error_type=%s",
                    self.config.node_code,
                    camera.code,
                    error[:80],
                )

        return StreamSupervisor(
            OpenCVStreamConnector(camera.stream_url),
            on_frame,
            on_state,
            ReconnectPolicy(initial_delay_seconds=1, maximum_delay_seconds=30),
        )

    def _schedule_face_probe(
        self,
        camera: CameraWorkerConfig,
        state: CameraRuntimeState,
        frame,
        probes: list[FaceProbe],
        timestamp: float,
    ) -> None:
        active = self._face_tasks.get(camera.camera_id)
        if active and not active.done():
            return
        now = time.monotonic()
        cutoff = now - max(camera.face_event_cooldown_seconds * 2, 300)
        self._face_last_probe = {
            key: value for key, value in self._face_last_probe.items()
            if value >= cutoff
        }
        self._face_last_event = {
            key: value for key, value in self._face_last_event.items()
            if value >= cutoff
        }
        eligible = [
            probe
            for probe in probes
            if now - self._face_last_probe.get(
                (camera.camera_id, probe.track_id), 0
            )
            >= camera.face_probe_interval_seconds
        ]
        if not eligible:
            return
        probe = max(eligible, key=lambda item: item.confidence)
        crop = self._face_crop(frame, probe.box)
        if crop is None:
            return
        self._face_last_probe[(camera.camera_id, probe.track_id)] = now
        task = asyncio.create_task(
            self._process_face_probe(camera, state, probe, crop, timestamp)
        )
        self._face_tasks[camera.camera_id] = task
        task.add_done_callback(
            lambda completed, camera_id=camera.camera_id: self._finish_face_task(
                camera_id, completed
            )
        )

    def _finish_face_task(
        self,
        camera_id: int,
        task: asyncio.Task,
    ) -> None:
        if self._face_tasks.get(camera_id) is task:
            self._face_tasks.pop(camera_id, None)
        if not task.cancelled():
            try:
                task.exception()
            except (asyncio.CancelledError, Exception):
                pass

    def _reset_face_state(self, camera_id: int) -> None:
        task = self._face_tasks.pop(camera_id, None)
        if task and not task.done():
            task.cancel()
        self._face_last_probe = {
            key: value
            for key, value in self._face_last_probe.items()
            if key[0] != camera_id
        }
        self._face_last_event = {
            key: value
            for key, value in self._face_last_event.items()
            if key[0] != camera_id
        }

    @staticmethod
    def _face_crop(frame, box: BoundingBox):
        height, width = frame.shape[:2]
        left = max(int(box.left), 0)
        top = max(int(box.top), 0)
        right = min(int(box.right + 0.999), width)
        bottom = min(int(box.bottom + 0.999), height)
        if right - left < 24 or bottom - top < 24:
            return None
        return frame[top:bottom, left:right].copy()

    @staticmethod
    def _encode_face_probe(crop) -> bytes:
        try:
            import cv2
        except ImportError as exc:
            raise RuntimeError(
                "install mineguard-api[edge] on inference nodes"
            ) from exc
        encoded, buffer = cv2.imencode(
            ".jpg", crop, [cv2.IMWRITE_JPEG_QUALITY, 90]
        )
        if not encoded:
            raise RuntimeError("OpenCV could not encode the face probe")
        image = buffer.tobytes()
        if not 256 <= len(image) <= 1024 * 1024:
            raise ValueError("face probe is outside the bounded size")
        return image

    async def _process_face_probe(
        self,
        camera: CameraWorkerConfig,
        state: CameraRuntimeState,
        probe: FaceProbe,
        crop,
        timestamp: float,
    ) -> None:
        try:
            image = await asyncio.to_thread(self._encode_face_probe, crop)
            del crop
            result = await self.api.identify_face(
                camera_id=camera.camera_id,
                image=image,
            )
            self._clear_camera_issue(state, "face_recognition_unavailable")
            if result is None:
                return
            candidate = result.get("candidate")
            matched = bool(result["matched"])
            event_identity = (
                f"person:{candidate['person_id']}"
                if matched
                else f"unknown-track:{probe.track_id}"
            )
            now = time.monotonic()
            event_key = (camera.camera_id, event_identity)
            if (
                now - self._face_last_event.get(event_key, 0)
                < camera.face_event_cooldown_seconds
            ):
                return
            authorized = result["authorized_for_camera"]
            metadata = {
                "track_id": probe.track_id,
                "face_model_version": result["model_version"],
                "face_model_sha256": result["model_sha256"],
                "face_quality": result["quality"],
                "face_liveness": result["liveness"],
                "authorized_for_camera": authorized,
            }
            event = {
                "event_type": "face_match" if matched else "unknown_face",
                "severity": (
                    "medium" if matched and authorized else "high"
                ),
                "camera_id": camera.camera_id,
                "person_id": candidate["person_id"] if matched else None,
                "title": (
                    "识别到已登记人员" if matched else "检测到未登记人脸"
                ),
                "description": f"{camera.area} · {camera.code}",
                "confidence": (
                    min(max(float(candidate["similarity"]), 0.0), 1.0)
                    if matched
                    else min(
                        max(float(probe.confidence), 0.0),
                        max(float(result["quality"]), 0.0),
                        1.0,
                    )
                ),
                "occurred_at": datetime.fromtimestamp(
                    timestamp, UTC
                ).isoformat(),
                "metadata_json": {
                    **metadata,
                    **(
                        {"similarity": candidate["similarity"]}
                        if matched
                        else {}
                    ),
                },
            }
            idempotency_key = edge_event_idempotency_key(
                self.config.node_code,
                camera.camera_id,
                event["event_type"],
                probe.track_id,
                timestamp,
            )
            await self._enqueue_with_backpressure(
                camera,
                state,
                idempotency_key,
                event,
            )
            self._face_last_event[event_key] = now
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._mark_camera_issue(state, "face_recognition_unavailable")
            logger.warning(
                "edge_face_probe_failed node=%s camera=%s error_type=%s",
                self.config.node_code,
                camera.code,
                type(exc).__name__,
            )

    @staticmethod
    def _encode_snapshot(
        frame, jpeg_quality: int, maximum_bytes: int
    ) -> bytes:
        try:
            import cv2
        except ImportError as exc:
            raise RuntimeError(
                "install mineguard-api[edge] on inference nodes"
            ) from exc
        encoded, buffer = cv2.imencode(
            ".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, jpeg_quality]
        )
        if not encoded:
            raise RuntimeError("OpenCV could not encode the event snapshot")
        snapshot = buffer.tobytes()
        if not 1024 <= len(snapshot) <= maximum_bytes:
            raise ValueError("event snapshot is outside the configured size limit")
        return snapshot

    def _attach_persisted_snapshot(
        self, key: str, event: dict[str, Any], snapshot: bytes
    ) -> None:
        key_match = re.fullmatch(r"edge:([a-f0-9]{64})", key)
        if not key_match:
            raise ValueError("event key cannot identify a snapshot file")
        file_name = f"{key_match.group(1)}.jpg"
        path = self._snapshot_path(file_name)
        digest = hashlib.sha256(snapshot).hexdigest()
        try:
            with path.open("xb") as output:
                output.write(snapshot)
                output.flush()
                os.fsync(output.fileno())
            self._sync_snapshot_directory()
        except FileExistsError:
            existing = path.read_bytes()
            if len(existing) != len(snapshot) or not hmac.compare_digest(
                hashlib.sha256(existing).hexdigest(), digest
            ):
                raise RuntimeError("existing snapshot spool file is inconsistent")
        event["_snapshot"] = {
            "file_name": file_name,
            "content_length": len(snapshot),
            "sha256": digest,
        }

    async def _send_persisted_event(
        self, idempotency_key: str, payload: dict[str, Any]
    ) -> None:
        snapshot = payload.get("_snapshot")
        wire_payload = {
            key: value for key, value in payload.items() if key != "_snapshot"
        }
        if snapshot is not None:
            if not isinstance(snapshot, dict):
                raise PermanentDeliveryError("snapshot_spool_metadata_invalid")
            file_name = snapshot.get("file_name")
            content_length = snapshot.get("content_length")
            digest = snapshot.get("sha256")
            reference = snapshot.get("reference")
            if (
                not isinstance(file_name, str)
                or not re.fullmatch(r"[a-f0-9]{64}\.jpg", file_name)
                or isinstance(content_length, bool)
                or not isinstance(content_length, int)
                or not 1024 <= content_length <= self.config.snapshot_maximum_bytes
                or not isinstance(digest, str)
                or not re.fullmatch(r"[a-f0-9]{64}", digest)
                or reference is not None
                and not isinstance(reference, str)
            ):
                raise PermanentDeliveryError("snapshot_spool_metadata_invalid")
            path = self._snapshot_path(file_name)
            try:
                snapshot_bytes = await asyncio.to_thread(path.read_bytes)
            except OSError as exc:
                raise PermanentDeliveryError("snapshot_spool_file_unavailable") from exc
            if len(snapshot_bytes) != content_length or not hmac.compare_digest(
                hashlib.sha256(snapshot_bytes).hexdigest(), digest
            ):
                raise PermanentDeliveryError("snapshot_spool_checksum_mismatch")
            camera_id = wire_payload.get("camera_id")
            if (
                isinstance(camera_id, bool)
                or not isinstance(camera_id, int)
                or camera_id < 1
            ):
                raise PermanentDeliveryError("snapshot_camera_id_invalid")
            grant = await self.api.create_snapshot_upload(
                camera_id=camera_id,
                content_length=content_length,
                sha256_hex=digest,
                reference=reference,
            )
            if reference is None:
                snapshot["reference"] = grant["reference"]
                if not self.outbox.replace_payload(idempotency_key, payload):
                    raise RuntimeError("snapshot event left the outbox before grant persistence")
                reference = grant["reference"]
            await self.api.upload_snapshot(grant, snapshot_bytes)
            wire_payload["snapshot_url"] = reference
        await self.api.send_event(idempotency_key, wire_payload)

    def _snapshot_path(self, file_name: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{64}\.jpg", file_name):
            raise ValueError("invalid snapshot spool file name")
        path = (self.snapshot_spool_path / file_name).resolve()
        if not path.is_relative_to(self.snapshot_spool_path.resolve()):
            raise ValueError("snapshot spool path escaped its root")
        return path

    def _delete_acknowledged_snapshot(self, item) -> None:
        snapshot = item.payload.get("_snapshot")
        if not isinstance(snapshot, dict) or not isinstance(
            snapshot.get("file_name"), str
        ):
            return
        path = self._snapshot_path(snapshot["file_name"])
        path.unlink(missing_ok=True)
        self._sync_snapshot_directory()

    def _remove_orphaned_snapshots(self) -> None:
        referenced = self.outbox.referenced_snapshot_files()
        removed = 0
        for path in self.snapshot_spool_path.glob("*.jpg"):
            if (
                re.fullmatch(r"[a-f0-9]{64}\.jpg", path.name)
                and path.name not in referenced
            ):
                path.unlink(missing_ok=True)
                removed += 1
        if removed:
            self._sync_snapshot_directory()
            logger.info(
                "edge_orphaned_snapshots_removed node=%s count=%d",
                self.config.node_code,
                removed,
            )

    def _sync_snapshot_directory(self) -> None:
        try:
            descriptor = os.open(self.snapshot_spool_path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    async def _enqueue_with_backpressure(
        self,
        camera: CameraWorkerConfig,
        state: CameraRuntimeState,
        key: str,
        event: dict[str, Any],
    ) -> bool | None:
        delay = 1.0
        capacity_blocked = False
        while not self._stop.is_set():
            try:
                self.outbox.enqueue(key, event)
            except OverflowError:
                if not capacity_blocked:
                    logger.critical(
                        "edge_outbox_capacity_reached node=%s camera=%s size=%d capacity=%d",
                        self.config.node_code,
                        camera.code,
                        self.outbox.size() + self.outbox.dead_letter_size(),
                        self.outbox.maximum_items,
                    )
                capacity_blocked = True
                self._mark_camera_issue(state, "outbox_capacity_reached")
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=delay)
                except TimeoutError:
                    self._record_camera_progress(camera.camera_id)
                    delay = min(delay * 2, 30)
                    continue
                return None
            else:
                if capacity_blocked:
                    self._clear_camera_issue(state, "outbox_capacity_reached")
                    logger.info(
                        "edge_outbox_capacity_recovered node=%s camera=%s",
                        self.config.node_code,
                        camera.code,
                    )
                return capacity_blocked
        return None

    def _record_camera_progress(self, camera_id: int) -> None:
        watchdog = getattr(self, "_stream_watchdog", None)
        if watchdog is not None:
            watchdog.progress(camera_id)

    @staticmethod
    def _refresh_camera_state(state: CameraRuntimeState) -> None:
        if state.stream_status == "offline":
            state.status = "offline"
        elif state.stream_status != "online" or state.degradation_reasons:
            state.status = "degraded"
        else:
            state.status = "online"
        state.last_error = state.stream_error or (
            sorted(state.degradation_reasons)[0]
            if state.degradation_reasons
            else None
        )

    @classmethod
    def _mark_camera_issue(
        cls, state: CameraRuntimeState, reason: str
    ) -> None:
        state.degradation_reasons.add(reason)
        cls._refresh_camera_state(state)

    @classmethod
    def _clear_camera_issue(
        cls, state: CameraRuntimeState, reason: str
    ) -> None:
        state.degradation_reasons.discard(reason)
        cls._refresh_camera_state(state)

    async def _heartbeat_loop(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            if time.monotonic() >= self._next_dead_letter_prune:
                try:
                    pruned = self.outbox.prune_resolved_dead_letters()
                except Exception as exc:
                    self._next_dead_letter_prune = time.monotonic() + 3600
                    logger.warning(
                        "edge_dead_letter_prune_failed node=%s error_type=%s",
                        self.config.node_code,
                        type(exc).__name__,
                    )
                else:
                    prune_batch_full = (
                        pruned
                        >= self.outbox.resolved_dead_letter_prune_batch_size
                    )
                    self._next_dead_letter_prune = time.monotonic() + (
                        60 if prune_batch_full else 6 * 3600
                    )
                    if pruned:
                        logger.info(
                            "edge_dead_letters_pruned node=%s count=%d",
                            self.config.node_code,
                            pruned,
                        )
            try:
                await self.api.heartbeat(self._heartbeat_payload())
                attempt = 0
                delay = self.config.heartbeat_seconds
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                attempt += 1
                self._central_reconnect_attempts_total += 1
                self._central_reconnect_timestamps.append(time.monotonic())
                exponent = min(max(attempt - 1, 0), 6)
                delay = min(2**exponent, 60) * random.uniform(0.8, 1.2)
                logger.warning(
                    "central_heartbeat_failed node=%s attempt=%d error_type=%s",
                    self.config.node_code,
                    attempt,
                    type(exc).__name__,
                )
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except TimeoutError:
                pass

    def _heartbeat_payload(self) -> dict[str, Any]:
        gpu_utilization, gpu_memory_utilization, gpu_healthy = self.gpu.sample()
        stream_reconnects_last_5m = sum(
            self._recent_reconnect_count(state.reconnect_timestamps)
            for state in self.states.values()
        )
        return {
            "software_version": self.config.software_version,
            "gpu_healthy": gpu_healthy,
            "gpu_utilization": gpu_utilization,
            "gpu_memory_utilization": gpu_memory_utilization,
            "queue_depth": self.outbox.size(),
            "dead_letter_depth": self.outbox.dead_letter_size(),
            "outbox_capacity": self.outbox.maximum_items,
            "stream_reconnects_last_5m": stream_reconnects_last_5m,
            "stream_reconnects_total": sum(
                state.reconnect_attempts_total for state in self.states.values()
            ),
            "central_reconnects_last_5m": self._recent_reconnect_count(
                self._central_reconnect_timestamps
            ),
            "central_reconnects_total": self._central_reconnect_attempts_total,
            "area_counts": {
                camera.area: self.states[camera.camera_id].count
                for camera in self.config.cameras
                if camera.counting_authority
            },
            "models": [self.manifest.edge_report(ready=True)],
            "cameras": [
                {
                    "camera_id": camera.camera_id,
                    "status": self.states[camera.camera_id].status,
                    "fps": self.states[camera.camera_id].fps,
                    "latency_ms": self.states[camera.camera_id].latency_ms,
                    "errors": sorted(
                        {
                            *self.states[camera.camera_id].degradation_reasons,
                            *(
                                [self.states[camera.camera_id].stream_error]
                                if self.states[camera.camera_id].stream_error
                                else []
                            ),
                        }
                    )[:10],
                }
                for camera in self.config.cameras
            ],
        }

    @staticmethod
    def _recent_reconnect_count(timestamps: deque[float]) -> int:
        cutoff = time.monotonic() - 300
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
        return len(timestamps)
