from mineguard_rl.traces import (
    EVALUATION_SEEDS,
    evaluation_protocol,
    generate_trace,
    protocol_candidate,
    trace_sha256,
)


def test_trace_generation_is_replayable_and_includes_fault_windows():
    first = generate_trace(1000, 20260822)
    second = generate_trace(1000, 20260822)
    assert first == second
    assert any(step.critical_zone_ratio == 0 for step in first)
    assert any(step.critical_zone_ratio > 0 for step in first)
    assert any(step.telemetry_age_seconds > 30 for step in first)
    assert any(step.healthy_gpu_ratio < 1 for step in first)


def test_trace_fault_windows_remain_short_and_bounded():
    trace = generate_trace(1000, 20260822)
    assert sum(step.telemetry_age_seconds > 30 for step in trace) == 15
    assert sum(step.healthy_gpu_ratio < 1 for step in trace) == 20


def test_protocol_candidate_binds_each_seed_trace_and_fault_coverage():
    protocol = evaluation_protocol()
    assert protocol["sealed"] is False
    assert set(protocol["trace_sha256"]) == {str(seed) for seed in EVALUATION_SEEDS}
    for seed in EVALUATION_SEEDS:
        seed_key = str(seed)
        trace = generate_trace(1000, seed)
        assert protocol["trace_sha256"][seed_key] == trace_sha256(trace)
        assert len(protocol["trace_sha256"][seed_key]) == 64
        assert protocol["expected_fallback_counts"][seed_key] == {
            "stale_telemetry": 15,
            "gpu_degraded": 20,
        }
        assert protocol["expected_critical_sample_counts"][seed_key] == sum(
            step.critical_zone_ratio > 0 for step in trace
        )


def test_protocol_candidate_excludes_runtime_seal_state():
    candidate = protocol_candidate()

    assert "sealed" not in candidate
    assert evaluation_protocol() == {**candidate, "sealed": False}
