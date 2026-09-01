from dataclasses import dataclass
from math import isfinite
from typing import Any

from pydantic import BaseModel, Field, field_validator


def strict_finite_float(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("numeric telemetry fields must be JSON numbers")
    try:
        normalized = float(value)
    except OverflowError as exc:
        raise ValueError("numeric telemetry fields must be finite") from exc
    if not isfinite(normalized):
        raise ValueError("numeric telemetry fields must be finite")
    return normalized


class SchedulingState(BaseModel):
    gpu_utilization: float = Field(
        ge=0, le=1, strict=True, allow_inf_nan=False
    )
    queue_depth: int = Field(ge=0, le=1_000_000, strict=True)
    active_streams: int = Field(ge=1, le=1000, strict=True)
    critical_zone_ratio: float = Field(
        ge=0, le=1, strict=True, allow_inf_nan=False
    )
    telemetry_age_seconds: float = Field(
        default=0,
        ge=0,
        le=3600,
        strict=True,
        allow_inf_nan=False,
        validate_default=True,
    )
    healthy_gpu_ratio: float = Field(
        default=1,
        ge=0,
        le=1,
        strict=True,
        allow_inf_nan=False,
        validate_default=True,
    )

    @field_validator(
        "gpu_utilization",
        "critical_zone_ratio",
        "telemetry_age_seconds",
        "healthy_gpu_ratio",
        mode="before",
    )
    @classmethod
    def validate_numeric_telemetry(cls, value):
        return strict_finite_float(value)


@dataclass(frozen=True)
class SchedulingAction:
    frame_stride: int
    face_batch_size: int
    detector_resolution: int
    reason: str


class SafetyConstrainedScheduler:
    """Deterministic safety layer around a future RL policy.

    Critical zones never use a frame stride above 2. This service is deliberately
    deterministic until an offline-trained policy passes shadow-mode acceptance.
    """

    def choose(self, state: SchedulingState) -> SchedulingAction:
        if state.telemetry_age_seconds > 30:
            return SchedulingAction(1, 4, 960, "stale-telemetry safety fallback")
        if state.healthy_gpu_ratio < 1:
            return SchedulingAction(1, 4, 960, "gpu-health safety fallback")
        if state.critical_zone_ratio > 0:
            return SchedulingAction(1, 8, 960, "critical-zone safety constraint")
        if state.gpu_utilization > 0.9 or state.queue_depth > 100:
            return SchedulingAction(3, 16, 640, "overload protection")
        if state.gpu_utilization > 0.75:
            return SchedulingAction(2, 8, 768, "balanced throughput")
        return SchedulingAction(1, 8, 960, "maximum detection quality")
