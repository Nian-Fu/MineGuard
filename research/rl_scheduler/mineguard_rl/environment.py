from dataclasses import dataclass
from math import isfinite
from numbers import Integral, Real

import gymnasium as gym
import numpy as np
from gymnasium import spaces

MAX_QUEUE_DEPTH = 500


@dataclass(frozen=True)
class WorkloadStep:
    active_streams: int
    person_density: float
    critical_zone_ratio: float
    event_rate: float
    base_queue_depth: int = 0
    telemetry_age_seconds: float = 0.0
    healthy_gpu_ratio: float = 1.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.active_streams, bool)
            or not isinstance(self.active_streams, Integral)
            or not 1 <= self.active_streams <= 256
        ):
            raise ValueError("active_streams must be between 1 and 256")
        numeric_values = (
            self.person_density,
            self.critical_zone_ratio,
            self.event_rate,
            self.healthy_gpu_ratio,
            self.telemetry_age_seconds,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, Real)
            or not isfinite(value)
            for value in numeric_values
        ):
            raise ValueError("workload values must be finite")
        if not all(
            0 <= value <= 1
            for value in (
                self.person_density,
                self.critical_zone_ratio,
                self.event_rate,
                self.healthy_gpu_ratio,
            )
        ):
            raise ValueError("workload ratios must be between zero and one")
        if (
            isinstance(self.base_queue_depth, bool)
            or not isinstance(self.base_queue_depth, Integral)
            or not 0 <= self.base_queue_depth <= MAX_QUEUE_DEPTH
            or self.telemetry_age_seconds < 0
        ):
            raise ValueError(
                "queue depth must be an integer from 0 to 500 and telemetry age cannot be negative"
            )


STRIDES = np.array([1, 2, 3, 5], dtype=np.int32)
RESOLUTIONS = np.array([640, 768, 960], dtype=np.int32)
BATCH_SIZES = np.array([4, 8, 16], dtype=np.int32)
SAFE_FALLBACK_ACTION = np.array([0, 2, 3, 0, 0], dtype=np.int64)
MAX_TELEMETRY_AGE_SECONDS = 30.0


class MineSchedulingEnv(gym.Env):
    """Replayable GPU scheduling environment, never connected to live production."""

    metadata = {"render_modes": []}

    def __init__(self, workload: list[WorkloadStep], gpu_capacity: float = 1.0) -> None:
        super().__init__()
        if not workload:
            raise ValueError("workload trace cannot be empty")
        if (
            isinstance(gpu_capacity, bool)
            or not isinstance(gpu_capacity, Real)
            or not isfinite(gpu_capacity)
            or gpu_capacity <= 0
        ):
            raise ValueError("gpu_capacity must be a finite positive value")
        self.workload = workload
        self.gpu_capacity = gpu_capacity
        # critical stride/resolution, ordinary stride/resolution, shared batch size
        self.action_space = spaces.MultiDiscrete(
            [len(STRIDES), len(RESOLUTIONS), len(STRIDES), len(RESOLUTIONS), len(BATCH_SIZES)]
        )
        self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(15,), dtype=np.float32)
        self._index = 0
        self._queue_depth = float(self.workload[0].base_queue_depth)
        initial_action = np.array([0, 2, 0, 2, 1], dtype=np.int64)
        self._previous_action, _, _ = self._apply_safety(initial_action, self.workload[0])
        self._last_metrics = self._simulate(self.workload[0], self._previous_action)

    def reset(self, *, seed: int | None = None, options: dict | None = None):
        super().reset(seed=seed)
        self._index = 0
        self._queue_depth = float(self.workload[0].base_queue_depth)
        initial_action = np.array([0, 2, 0, 2, 1], dtype=np.int64)
        self._previous_action, safety_override, fallback_reason = self._apply_safety(
            initial_action, self.workload[0]
        )
        self._last_metrics = self._simulate(self.workload[0], self._previous_action)
        return self._observation(), {
            "safety_override": safety_override,
            "fallback_reason": fallback_reason,
        }

    def step(self, action):
        try:
            raw_action = np.asarray(action, dtype=np.float64)
            contains_boolean = any(
                isinstance(value, (bool, np.bool_))
                for value in np.asarray(action, dtype=object).flat
            )
        except (OverflowError, TypeError, ValueError) as exc:
            raise ValueError("action must contain five finite values") from exc
        if (
            raw_action.shape != self.action_space.shape
            or not np.all(np.isfinite(raw_action))
            or contains_boolean
        ):
            raise ValueError("action must contain five finite values")
        if not np.array_equal(raw_action, np.floor(raw_action)):
            raise ValueError("action values must be integers")
        requested = raw_action
        applied, safety_override, fallback_reason = self._apply_safety(
            requested, self.workload[self._index]
        )
        metrics = self._simulate(self.workload[self._index], applied)
        workload = self.workload[self._index]
        critical_ratio = workload.critical_zone_ratio
        incoming = workload.active_streams * 25 * (
            critical_ratio / STRIDES[applied[0]]
            + (1 - critical_ratio) / STRIDES[applied[2]]
        )
        processed = incoming * min(
            self.gpu_capacity / max(metrics["load"], 1e-6), 1.0
        )
        self._queue_depth = np.clip(
            self._queue_depth + incoming - processed, 0, MAX_QUEUE_DEPTH
        )

        critical_recall_reward = (
            4.0 * metrics["critical_recall"] if critical_ratio > 0 else 0.0
        )
        recall_reward = 4.0 * metrics["recall_proxy"] + critical_recall_reward
        latency_penalty = 2.0 * min(metrics["latency_ms"] / 1000, 2)
        overload_penalty = 8.0 * max(metrics["load"] - self.gpu_capacity, 0)
        queue_penalty = 3.0 * self._queue_depth / MAX_QUEUE_DEPTH
        compute_penalty = 0.35 * min(metrics["load"], self.gpu_capacity)
        switching_penalty = 0.15 * np.count_nonzero(applied != self._previous_action)
        safety_penalty = 1.0 if safety_override else 0.0
        reward = recall_reward - latency_penalty - overload_penalty - queue_penalty - compute_penalty - switching_penalty - safety_penalty

        self._previous_action = applied
        self._last_metrics = metrics
        self._index += 1
        terminated = self._index >= len(self.workload)
        if not terminated:
            observation = self._observation()
        else:
            observation = np.zeros(15, dtype=np.float32)
        return observation, float(reward), terminated, False, {
            **metrics,
            "critical_zone_ratio": float(critical_ratio),
            "queue_depth": float(self._queue_depth),
            "requested_action": requested.tolist(),
            "applied_action": applied.tolist(),
            "safety_override": safety_override,
            "fallback_reason": fallback_reason,
        }

    def _apply_safety(
        self, action: np.ndarray, workload: WorkloadStep
    ) -> tuple[np.ndarray, bool, str | None]:
        applied = np.asarray(
            np.clip(action, 0, self.action_space.nvec - 1), dtype=np.int64
        )
        reasons = []
        if not np.array_equal(action, applied):
            reasons.append("action_bounds")
        if workload.telemetry_age_seconds > MAX_TELEMETRY_AGE_SECONDS:
            applied = SAFE_FALLBACK_ACTION.copy()
            reasons.append("stale_telemetry")
        elif workload.healthy_gpu_ratio < 1.0:
            applied = SAFE_FALLBACK_ACTION.copy()
            reasons.append("gpu_degraded")
        elif workload.critical_zone_ratio > 0:
            before = applied.copy()
            applied[0] = min(applied[0], 1)
            applied[1] = max(applied[1], 1)
            if not np.array_equal(before, applied):
                reasons.append("critical_guard")
        override = not np.array_equal(action, applied)
        return applied, override, ",".join(reasons) if reasons else None

    def _simulate(self, workload: WorkloadStep, action: np.ndarray) -> dict[str, float]:
        critical_stride = float(STRIDES[action[0]])
        critical_resolution = int(RESOLUTIONS[action[1]])
        ordinary_stride = float(STRIDES[action[2]])
        ordinary_resolution = int(RESOLUTIONS[action[3]])
        batch_efficiency = {4: 1.0, 8: 0.82, 16: 0.72}[int(BATCH_SIZES[action[4]])]
        density_factor = 1 + 0.45 * workload.person_density
        critical_load = workload.critical_zone_ratio * (critical_resolution / 640) ** 2 / critical_stride
        ordinary_load = (1 - workload.critical_zone_ratio) * (ordinary_resolution / 640) ** 2 / ordinary_stride
        available_capacity = max(workload.healthy_gpu_ratio, 0.1)
        load = (
            workload.active_streams
            / 24
            * (critical_load + ordinary_load)
            * batch_efficiency
            * density_factor
            / available_capacity
        )
        latency_ms = 45 + 135 * load**1.7 + 0.35 * self._queue_depth

        def recall(resolution: int, stride: float) -> float:
            resolution_recall = {640: 0.88, 768: 0.93, 960: 0.965}[resolution]
            stride_loss = 0.018 * (stride - 1) * (1 + workload.event_rate)
            density_loss = 0.04 * workload.person_density
            return float(np.clip(resolution_recall - stride_loss - density_loss, 0, 1))

        critical_recall = recall(critical_resolution, critical_stride)
        ordinary_recall = recall(ordinary_resolution, ordinary_stride)
        weighted_recall = (
            workload.critical_zone_ratio * critical_recall
            + (1 - workload.critical_zone_ratio) * ordinary_recall
        )
        return {
            "load": float(load),
            "latency_ms": float(latency_ms),
            "recall_proxy": float(weighted_recall),
            "critical_recall": critical_recall,
            "ordinary_recall": ordinary_recall,
        }

    def _observation(self) -> np.ndarray:
        current = self.workload[self._index]
        operating_state = [
            np.clip(self._last_metrics["load"] / 1.5, 0, 1),
            np.clip(self._queue_depth / MAX_QUEUE_DEPTH, 0, 1),
            np.clip(current.active_streams / 64, 0, 1),
            np.clip(current.person_density, 0, 1),
            np.clip(current.critical_zone_ratio, 0, 1),
            np.clip(current.event_rate, 0, 1),
            np.clip(self._last_metrics["latency_ms"] / 1500, 0, 1),
            np.clip(self._last_metrics["recall_proxy"], 0, 1),
            np.clip(current.telemetry_age_seconds / 60, 0, 1),
            np.clip(current.healthy_gpu_ratio, 0, 1),
        ]
        previous_action = self._previous_action / (self.action_space.nvec - 1)
        return np.array([*operating_state, *previous_action], dtype=np.float32)
