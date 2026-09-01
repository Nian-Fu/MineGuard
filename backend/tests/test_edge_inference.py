from types import SimpleNamespace

import pytest

from app.edge.inference import ByteTrackAdapter, TritonDetector


class FakeTensor:
    def __init__(self, shape):
        self.shape = shape
        self.ndim = len(shape)
        self.reshape_calls = []

    def reshape(self, *shape):
        self.reshape_calls.append(shape)
        return self


class FakeResponse:
    def __init__(self, output):
        self.output = output
        self.requested_name = None

    def as_numpy(self, name):
        self.requested_name = name
        return self.output


def test_triton_response_accepts_unbatched_and_single_batch_nx6_tensors():
    detector = TritonDetector.__new__(TritonDetector)
    detector.manifest = SimpleNamespace(output_name="detections")

    unbatched = FakeTensor((4, 6))
    assert detector._response_rows(FakeResponse(unbatched)) is unbatched

    batched = FakeTensor((1, 4, 6))
    assert detector._response_rows(FakeResponse(batched)) is batched
    assert batched.reshape_calls == [(-1, 6)]


@pytest.mark.parametrize(
    "output",
    [
        None,
        FakeTensor((6,)),
        FakeTensor((2, 3, 2)),
        FakeTensor((2, 4, 6)),
        FakeTensor((100_001, 6)),
        FakeTensor((1, 100_001, 6)),
    ],
)
def test_triton_response_rejects_missing_or_malformed_output(output):
    detector = TritonDetector.__new__(TritonDetector)
    detector.manifest = SimpleNamespace(output_name="detections")
    with pytest.raises(RuntimeError, match="output tensor"):
        detector._response_rows(FakeResponse(output))


def test_byte_track_adapter_passes_empty_detection_frame_and_can_reset():
    class FakeArray:
        def __init__(self, shape):
            self.shape = shape

    class FakeNumpy:
        float32 = "float32"
        int32 = "int32"

        @staticmethod
        def empty(shape, dtype):
            return FakeArray(shape if isinstance(shape, tuple) else (shape,))

    class FakeDetections:
        def __init__(self, *, xyxy, confidence, class_id):
            assert xyxy.shape == (0, 4)
            assert confidence.shape == (0,)
            assert class_id.shape == (0,)
            self.tracker_id = None

    class FakeTracker:
        def __init__(self, frame_rate=25):
            self.frame_rate = frame_rate
            self.frames = 0

        def update_with_detections(self, detections):
            assert isinstance(detections, FakeDetections)
            self.frames += 1
            return detections

    adapter = ByteTrackAdapter.__new__(ByteTrackAdapter)
    adapter.np = FakeNumpy()
    adapter.sv = SimpleNamespace(Detections=FakeDetections, ByteTrack=FakeTracker)
    adapter.frame_rate = 20
    adapter.tracker = FakeTracker(frame_rate=20)

    assert adapter.update([]) == []
    assert adapter.tracker.frames == 1
    previous = adapter.tracker
    adapter.reset()
    assert adapter.tracker is not previous
    assert adapter.tracker.frame_rate == 20
