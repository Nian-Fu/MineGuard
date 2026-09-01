import pytest

from evaluate_baselines import aggregate_metrics, evaluate, heuristic_policy
from mineguard_rl.traces import EVALUATION_SEEDS, evaluation_protocol


def test_heuristic_evaluation_covers_the_complete_protocol_trace():
    seed = EVALUATION_SEEDS[0]
    result = evaluate(heuristic_policy, seed)
    protocol = evaluation_protocol()

    assert result["step_count"] == protocol["trace_length"]
    assert result["critical_recall_sample_count"] == protocol[
        "expected_critical_sample_counts"
    ][str(seed)]
    assert result["override_stale_telemetry"] == protocol[
        "expected_fallback_counts"
    ][str(seed)]["stale_telemetry"]
    assert result["override_gpu_degraded"] == protocol[
        "expected_fallback_counts"
    ][str(seed)]["gpu_degraded"]
    assert result["override_action_bounds"] == 0
    assert result["override_critical_guard"] == 0


def test_aggregate_metrics_uses_sample_standard_deviation():
    per_seed = {
        str(seed): {"metric": float(index)}
        for index, seed in enumerate(EVALUATION_SEEDS, start=1)
    }

    aggregate = aggregate_metrics(per_seed)["metric"]

    assert aggregate["mean"] == 3.0
    assert aggregate["standard_deviation"] == pytest.approx(1.5811388300841898)
    assert aggregate["ci95_low"] < aggregate["mean"] < aggregate["ci95_high"]
