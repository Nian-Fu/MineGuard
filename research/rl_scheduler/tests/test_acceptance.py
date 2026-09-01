from copy import deepcopy

import pytest

from check_acceptance import check_acceptance as _check_acceptance
from mineguard_rl.traces import EVALUATION_SEEDS, evaluation_protocol

MODEL_SHA256 = "a" * 64


def check_acceptance(results, **options):
    return _check_acceptance(
        results, expected_model_sha256=MODEL_SHA256, **options
    )


def metrics(seed: int, critical_recall: float = 0.95) -> dict:
    protocol = evaluation_protocol()
    return {
        "step_count": float(protocol["trace_length"]),
        "critical_recall_mean": critical_recall,
        "critical_recall_sample_count": float(
            protocol["expected_critical_sample_counts"][str(seed)]
        ),
        "latency_p95_ms": 400.0,
        "latency_p99_ms": 500.0,
        "queue_peak": 20.0,
        "override_action_bounds": 0.0,
        "override_critical_guard": 0.0,
        "override_stale_telemetry": 15.0,
        "override_gpu_degraded": 20.0,
    }


def evaluation_fixture() -> dict:
    seeds = {str(seed): metrics(seed) for seed in EVALUATION_SEEDS}
    return {
        "protocol": evaluation_protocol(),
        "candidate_artifact": {"algorithm": "sha256", "sha256": MODEL_SHA256},
        "heuristic": {"per_seed": deepcopy(seeds)},
        "ppo": {"per_seed": deepcopy(seeds)},
    }


def test_acceptance_blocks_matching_candidate_while_v3_is_unsealed():
    report = check_acceptance(evaluation_fixture())
    assert report["accepted"] is False
    assert report["failures"] == [
        {
            "code": "unsealed_trace_protocol",
            "detail": "v3 trace constants require independent generation and review",
        }
    ]


def test_acceptance_allows_matching_candidate_after_protocol_seal(monkeypatch):
    expected_protocol = _check_acceptance.__globals__["EXPECTED_PROTOCOL"]
    monkeypatch.setitem(expected_protocol, "sealed", True)
    results = evaluation_fixture()
    results["protocol"]["sealed"] = True

    report = check_acceptance(results)

    assert report["accepted"] is True
    assert report["failures"] == []


def test_acceptance_rejects_non_object_report():
    report = check_acceptance([])  # type: ignore[arg-type]
    assert report["accepted"] is False
    assert report["failures"][0]["code"] == "invalid_report"


def test_acceptance_rejects_any_critical_recall_regression():
    results = evaluation_fixture()
    seed = str(EVALUATION_SEEDS[3])
    results["ppo"]["per_seed"][seed]["critical_recall_mean"] = 0.949
    report = check_acceptance(results)
    assert report["accepted"] is False
    assert any(
        failure["code"] == "critical_recall_regression"
        and failure["seed"] == seed
        for failure in report["failures"]
    )


def test_acceptance_rejects_latency_queue_and_invalid_actions():
    results = evaluation_fixture()
    candidate = results["ppo"]["per_seed"][str(EVALUATION_SEEDS[1])]
    candidate["latency_p99_ms"] = 600.0
    candidate["queue_peak"] = 30.0
    candidate["override_action_bounds"] = 1.0
    codes = {
        failure["code"] for failure in check_acceptance(results)["failures"]
    }
    assert {
        "latency_regression",
        "queue_regression",
        "invalid_policy_action",
    }.issubset(codes)


def test_acceptance_rejects_critical_guard_dependency():
    results = evaluation_fixture()
    seed = str(EVALUATION_SEEDS[2])
    results["ppo"]["per_seed"][seed]["override_critical_guard"] = 1.0
    report = check_acceptance(results)
    assert report["accepted"] is False
    assert any(
        failure["code"] == "unsafe_critical_action" and failure["seed"] == seed
        for failure in report["failures"]
    )


def test_acceptance_rejects_non_finite_thresholds():
    report = check_acceptance(
        evaluation_fixture(), maximum_latency_ratio=float("nan")
    )
    assert report["accepted"] is False
    assert report["failures"][0]["code"] == "invalid_threshold"


def test_acceptance_rejects_attempt_to_relax_thresholds():
    report = check_acceptance(evaluation_fixture(), maximum_queue_ratio=1.11)
    assert report["accepted"] is False
    assert report["failures"][0]["code"] == "invalid_threshold"


def test_acceptance_rejects_mismatched_critical_slice_coverage():
    results = evaluation_fixture()
    seed = str(EVALUATION_SEEDS[4])
    results["ppo"]["per_seed"][seed]["critical_recall_sample_count"] -= 1
    report = check_acceptance(results)
    assert report["accepted"] is False
    assert any(
        failure["code"] == "critical_slice_mismatch" and failure["seed"] == seed
        for failure in report["failures"]
    )


def test_acceptance_rejects_matching_but_incomplete_critical_slices():
    results = evaluation_fixture()
    seed = str(EVALUATION_SEEDS[0])
    results["heuristic"]["per_seed"][seed]["critical_recall_sample_count"] -= 1
    results["ppo"]["per_seed"][seed]["critical_recall_sample_count"] -= 1

    report = check_acceptance(results)

    assert any(
        failure["code"] == "critical_slice_mismatch"
        and failure["seed"] == seed
        for failure in report["failures"]
    )


def test_acceptance_rejects_truncated_evaluation():
    results = evaluation_fixture()
    seed = str(EVALUATION_SEEDS[1])
    results["ppo"]["per_seed"][seed]["step_count"] -= 1

    assert any(
        failure["code"] == "invalid_metric_domain"
        and failure["seed"] == seed
        for failure in check_acceptance(results)["failures"]
    )


def test_acceptance_rejects_unfrozen_seed_or_protocol_metadata():
    results = evaluation_fixture()
    results["protocol"]["trace_length"] -= 1
    old_seed = str(EVALUATION_SEEDS[0])
    results["ppo"]["per_seed"]["1"] = results["ppo"]["per_seed"].pop(old_seed)
    codes = {failure["code"] for failure in check_acceptance(results)["failures"]}
    assert {"trace_protocol", "seed_protocol"}.issubset(codes)


def test_acceptance_rejects_model_or_trace_digest_drift():
    results = evaluation_fixture()
    results["candidate_artifact"]["sha256"] = "b" * 64
    first_seed = str(EVALUATION_SEEDS[0])
    results["protocol"]["trace_sha256"][first_seed] = "c" * 64
    codes = {failure["code"] for failure in check_acceptance(results)["failures"]}
    assert {"model_digest_mismatch", "trace_protocol"}.issubset(codes)


def test_acceptance_rejects_fallback_coverage_drift():
    results = evaluation_fixture()
    seed = str(EVALUATION_SEEDS[0])
    results["ppo"]["per_seed"][seed]["override_gpu_degraded"] -= 1
    assert any(
        failure["code"] == "fallback_coverage_mismatch"
        for failure in check_acceptance(results)["failures"]
    )


def test_acceptance_requires_nonnegative_paired_recall_confidence_bound():
    results = evaluation_fixture()
    results["ppo"]["per_seed"][str(EVALUATION_SEEDS[-1])][
        "critical_recall_mean"
    ] = 1.0
    assert any(
        failure["code"] == "critical_recall_ci_regression"
        for failure in check_acceptance(results)["failures"]
    )


def test_acceptance_fails_closed_for_unrepresentable_integer_metric():
    results = evaluation_fixture()
    results["ppo"]["per_seed"][str(EVALUATION_SEEDS[0])][
        "queue_peak"
    ] = 10**10000
    assert any(
        failure["code"] == "non_finite_metric"
        for failure in check_acceptance(results)["failures"]
    )


@pytest.mark.parametrize(
    ("metric_name", "value"),
    [
        ("critical_recall_mean", 1.1),
        ("critical_recall_sample_count", 850.5),
        ("latency_p95_ms", -1.0),
        ("latency_p99_ms", 399.0),
        ("queue_peak", -1.0),
    ],
)
def test_acceptance_rejects_metrics_outside_physical_domains(metric_name, value):
    results = evaluation_fixture()
    results["ppo"]["per_seed"][str(EVALUATION_SEEDS[0])][metric_name] = value
    assert any(
        failure["code"] == "invalid_metric_domain"
        for failure in check_acceptance(results)["failures"]
    )
