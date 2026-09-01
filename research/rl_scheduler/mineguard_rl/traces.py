import hashlib
import struct

import numpy as np

from mineguard_rl.environment import MAX_QUEUE_DEPTH, WorkloadStep

EVALUATION_PROTOCOL_ID = "mineguard-frozen-traces-v3"
EVALUATION_TRACE_LENGTH = 1000
EVALUATION_SEEDS = tuple(range(20260822, 20260827))
TRACE_STEP = struct.Struct("!qdddqdd")

# Populate this only from an independently reviewed export produced by
# export_protocol_candidate.py. Until then every acceptance attempt fails closed.
FROZEN_PROTOCOL_V3: dict | None = None


def generate_trace(length: int, seed: int) -> list[WorkloadStep]:
    if length < 2:
        raise ValueError("trace length must be at least two")
    rng = np.random.default_rng(seed)
    trace = []
    streams = int(rng.integers(8, 25))
    for index in range(length):
        if index % 60 == 0:
            streams = int(np.clip(streams + rng.integers(-4, 6), 4, 64))
        shift_peak = 0.35 if index % 240 in range(40, 100) else 0.0
        density = float(np.clip(rng.beta(2, 5) + shift_peak, 0, 1))
        critical_ratio = float(
            rng.choice(
                [0.0, 0.2, 0.4, 0.6, 0.8],
                p=[0.15, 0.30, 0.30, 0.15, 0.10],
            )
        )
        event_rate = float(np.clip(0.15 + density * 0.6 + rng.normal(0, 0.08), 0, 1))
        telemetry_age_seconds = (
            45.0 if index % 300 in range(120, 125) else float(rng.uniform(0, 2))
        )
        healthy_gpu_ratio = 0.5 if index % 500 in range(300, 310) else 1.0
        trace.append(
            WorkloadStep(
                streams,
                density,
                critical_ratio,
                event_rate,
                telemetry_age_seconds=telemetry_age_seconds,
                healthy_gpu_ratio=healthy_gpu_ratio,
            )
        )
    return trace


def trace_sha256(trace: list[WorkloadStep]) -> str:
    digest = hashlib.sha256()
    for step in trace:
        digest.update(
            TRACE_STEP.pack(
                int(step.active_streams),
                float(step.person_density),
                float(step.critical_zone_ratio),
                float(step.event_rate),
                int(step.base_queue_depth),
                float(step.telemetry_age_seconds),
                float(step.healthy_gpu_ratio),
            )
        )
    return digest.hexdigest()


def protocol_candidate() -> dict:
    trace_digests = {}
    fallback_counts = {}
    critical_sample_counts = {}
    for seed in EVALUATION_SEEDS:
        trace = generate_trace(EVALUATION_TRACE_LENGTH, seed)
        seed_key = str(seed)
        trace_digests[seed_key] = trace_sha256(trace)
        fallback_counts[seed_key] = {
            "stale_telemetry": sum(
                step.telemetry_age_seconds > 30 for step in trace
            ),
            "gpu_degraded": sum(
                step.telemetry_age_seconds <= 30 and step.healthy_gpu_ratio < 1
                for step in trace
            ),
        }
        critical_sample_counts[seed_key] = sum(
            step.critical_zone_ratio > 0 for step in trace
        )
    return {
        "id": EVALUATION_PROTOCOL_ID,
        "seeds": [str(seed) for seed in EVALUATION_SEEDS],
        "trace_length": EVALUATION_TRACE_LENGTH,
        "queue_capacity": MAX_QUEUE_DEPTH,
        "maximum_latency_ms": 1_000_000,
        "trace_sha256": trace_digests,
        "expected_fallback_counts": fallback_counts,
        "expected_critical_sample_counts": critical_sample_counts,
    }


def evaluation_protocol() -> dict:
    candidate = protocol_candidate()
    return {
        **candidate,
        "sealed": FROZEN_PROTOCOL_V3 is not None and candidate == FROZEN_PROTOCOL_V3,
    }
