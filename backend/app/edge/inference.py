from dataclasses import dataclass
from math import isfinite
from numbers import Real
from threading import Lock

from app.edge.model_manifest import ModelManifest

MAXIMUM_DETECTIONS_PER_FRAME = 100_000


@dataclass(frozen=True)
class Detection:
    left: float
    top: float
    right: float
    bottom: float
    confidence: float
    class_id: int
    class_name: str


@dataclass(frozen=True)
class TrackedDetection(Detection):
    track_id: int


class TritonDetector:
    """Triton HTTP adapter for an approved Nx6 [xyxy, score, class] model."""

    def __init__(
        self,
        server_url: str,
        manifest: ModelManifest,
        confidence: float = 0.5,
        timeout_seconds: float = 10.0,
        verify_artifact: bool = True,
    ) -> None:
        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, Real)
            or not isfinite(confidence)
            or not 0 <= confidence <= 1
        ):
            raise ValueError("confidence must be a finite value between zero and one")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, Real)
            or not isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a finite positive value")
        try:
            import cv2
            import numpy as np
            import tritonclient.http as triton_http
        except ImportError as exc:
            raise RuntimeError("install mineguard-api[edge] on inference nodes") from exc
        if verify_artifact:
            manifest.verify_artifact()
        self.cv2 = cv2
        self.np = np
        self.triton_http = triton_http
        self.manifest = manifest
        self.confidence = confidence
        self.timeout_seconds = timeout_seconds
        self.client = triton_http.InferenceServerClient(
            url=server_url,
            connection_timeout=timeout_seconds,
            network_timeout=timeout_seconds,
        )
        self._client_lock = Lock()
        self._verify_server_model()

    def _verify_server_model(self) -> None:
        config = self.client.get_model_config(self.manifest.model_name)
        parameter = config.get("parameters", {}).get("artifact_sha256", {})
        server_sha256 = parameter.get("string_value") if isinstance(parameter, dict) else None
        if server_sha256 != self.manifest.sha256:
            raise RuntimeError("Triton model artifact_sha256 does not match approved manifest")

    def detect(self, frame) -> list[Detection]:
        image, scale, pad_x, pad_y = self._letterbox(frame)
        tensor = image[:, :, ::-1].transpose(2, 0, 1).astype(self.np.float32) / 255.0
        tensor = self.np.ascontiguousarray(tensor[None, ...])
        request_input = self.triton_http.InferInput(
            self.manifest.input_name,
            tensor.shape,
            "FP32",
        )
        request_input.set_data_from_numpy(tensor)
        with self._client_lock:
            response = self.client.infer(
                self.manifest.model_name,
                [request_input],
                outputs=[self.triton_http.InferRequestedOutput(self.manifest.output_name)],
                client_timeout=self.timeout_seconds,
            )
        rows = self._response_rows(response)
        height, width = frame.shape[:2]
        detections = []
        for left, top, right, bottom, score, class_id_value in rows:
            values = [left, top, right, bottom, score, class_id_value]
            if not all(isfinite(float(value)) for value in values):
                continue
            normalized_score = float(score)
            normalized_class_id = float(class_id_value)
            if (
                normalized_score < self.confidence
                or not 0 <= normalized_score <= 1
                or not normalized_class_id.is_integer()
            ):
                continue
            class_id = int(normalized_class_id)
            if class_id < 0 or class_id >= len(self.manifest.class_names):
                continue
            clipped_left = float(self.np.clip((left - pad_x) / scale, 0, width))
            clipped_top = float(self.np.clip((top - pad_y) / scale, 0, height))
            clipped_right = float(self.np.clip((right - pad_x) / scale, 0, width))
            clipped_bottom = float(self.np.clip((bottom - pad_y) / scale, 0, height))
            if clipped_right <= clipped_left or clipped_bottom <= clipped_top:
                continue
            detections.append(
                Detection(
                    left=clipped_left,
                    top=clipped_top,
                    right=clipped_right,
                    bottom=clipped_bottom,
                    confidence=normalized_score,
                    class_id=class_id,
                    class_name=self.manifest.class_names[class_id],
                )
            )
        return detections

    def _response_rows(self, response):
        output = response.as_numpy(self.manifest.output_name)
        if output is None:
            raise RuntimeError("Triton response is missing the configured output tensor")
        if (
            output.ndim == 2
            and output.shape[1] == 6
            and output.shape[0] <= MAXIMUM_DETECTIONS_PER_FRAME
        ):
            return output
        if (
            output.ndim == 3
            and output.shape[0] == 1
            and output.shape[2] == 6
            and output.shape[1] <= MAXIMUM_DETECTIONS_PER_FRAME
        ):
            return output.reshape(-1, 6)
        raise RuntimeError(
            "Triton output tensor must have a bounded shape [N, 6] or [1, N, 6]"
        )

    def _letterbox(self, frame):
        source_height, source_width = frame.shape[:2]
        target_width, target_height = self.manifest.input_width, self.manifest.input_height
        scale = min(target_width / source_width, target_height / source_height)
        resized_width, resized_height = round(source_width * scale), round(source_height * scale)
        resized = self.cv2.resize(frame, (resized_width, resized_height))
        pad_x, pad_y = (target_width - resized_width) // 2, (target_height - resized_height) // 2
        canvas = self.np.full((target_height, target_width, 3), 114, dtype=self.np.uint8)
        canvas[pad_y : pad_y + resized_height, pad_x : pad_x + resized_width] = resized
        return canvas, scale, pad_x, pad_y


class ByteTrackAdapter:
    def __init__(self, frame_rate: int = 25) -> None:
        try:
            import numpy as np
            import supervision as sv
        except ImportError as exc:
            raise RuntimeError("install mineguard-api[edge] on inference nodes") from exc
        self.np = np
        self.sv = sv
        self.frame_rate = frame_rate
        self.tracker = sv.ByteTrack(frame_rate=frame_rate)

    def reset(self) -> None:
        self.tracker = self.sv.ByteTrack(frame_rate=self.frame_rate)

    def update(self, detections: list[Detection]) -> list[TrackedDetection]:
        source = (
            self.sv.Detections(
                xyxy=self.np.array(
                    [[item.left, item.top, item.right, item.bottom] for item in detections],
                    dtype=self.np.float32,
                ),
                confidence=self.np.array(
                    [item.confidence for item in detections], dtype=self.np.float32
                ),
                class_id=self.np.array(
                    [item.class_id for item in detections], dtype=self.np.int32
                ),
            )
            if detections
            else self.sv.Detections(
                xyxy=self.np.empty((0, 4), dtype=self.np.float32),
                confidence=self.np.empty(0, dtype=self.np.float32),
                class_id=self.np.empty(0, dtype=self.np.int32),
            )
        )
        tracked = self.tracker.update_with_detections(source)
        if tracked.tracker_id is None:
            return []
        results = []
        for index, tracker_id in enumerate(tracked.tracker_id):
            if tracker_id is None:
                continue
            left, top, right, bottom = tracked.xyxy[index]
            class_id = int(tracked.class_id[index])
            results.append(
                TrackedDetection(
                    left=float(left),
                    top=float(top),
                    right=float(right),
                    bottom=float(bottom),
                    confidence=float(tracked.confidence[index]),
                    class_id=class_id,
                    class_name=self._class_name(detections, class_id),
                    track_id=int(tracker_id),
                )
            )
        return results

    @staticmethod
    def _class_name(detections: list[Detection], class_id: int) -> str:
        return next(item.class_name for item in detections if item.class_id == class_id)
