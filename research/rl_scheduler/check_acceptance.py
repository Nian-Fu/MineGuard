import argparse
import json
import math
from pathlib import Path
from statistics import mean, stdev
from typing import Any

from mineguard_rl.integrity import resolve_model_path, sha256_file
from mineguard_rl.traces import (
    EVALUATION_SEEDS,
    evaluation_protocol,
)

REQUIRED_METRICS = {
    "step_count",
    "critical_recall_mean",
    "critical_recall_sample_count",
    "latency_p95_ms",
    "latency_p99_ms",
    "queue_peak",
    "override_action_bounds",
    "override_critical_guard",
    "override_stale_telemetry",
    "override_gpu_degraded",
}
EXPECTED_PROTOCOL = evaluation_protocol()
MAXIMUM_METRICS_FILE_BYTES = 10 * 1024 * 1024


def _is_finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _reject_json_constant(value: str):
    raise ValueError(f"invalid JSON constant: {value}")


def _metrics_have_valid_domains(run: dict[str, Any]) -> bool:
    integer_counts = (
        run["step_count"],
        run["critical_recall_sample_count"],
        run["override_action_bounds"],
        run["override_critical_guard"],
        run["override_stale_telemetry"],
        run["override_gpu_degraded"],
    )
    return (
        run["step_count"] == EXPECTED_PROTOCOL["trace_length"]
        and 0 <= run["critical_recall_mean"] <= 1
        and 0 < run["critical_recall_sample_count"] <= EXPECTED_PROTOCOL["trace_length"]
        and 0 <= run["latency_p95_ms"] <= EXPECTED_PROTOCOL["maximum_latency_ms"]
        and run["latency_p99_ms"] >= run["latency_p95_ms"]
        and run["latency_p99_ms"] <= EXPECTED_PROTOCOL["maximum_latency_ms"]
        and 0 <= run["queue_peak"] <= EXPECTED_PROTOCOL["queue_capacity"]
        and all(
            0 <= value <= EXPECTED_PROTOCOL["trace_length"]
            and value == int(value)
            for value in integer_counts
        )
    )


def check_acceptance(
    results: dict[str, Any],
    *,
    expected_model_sha256: str,
    maximum_latency_ratio: float = 1.10,
    maximum_queue_ratio: float = 1.10,
) -> dict[str, Any]:
    if not isinstance(results, dict):
        return {
            "accepted": False,
            "failures": [
                {
                    "code": "invalid_report",
                    "detail": "evaluation report must be a JSON object",
                }
            ],
        }
    thresholds = (maximum_latency_ratio, maximum_queue_ratio)
    if any(
        not _is_finite_number(value)
        or not 1 <= value <= 1.10
        for value in thresholds
    ):
        return {
            "accepted": False,
            "failures": [
                {
                    "code": "invalid_threshold",
                    "detail": (
                        "acceptance ratios must be finite numbers from 1.0 to 1.10"
                    ),
                }
            ],
        }
    failures: list[dict[str, Any]] = []
    if not EXPECTED_PROTOCOL.get("sealed"):
        failures.append(
            {
                "code": "unsealed_trace_protocol",
                "detail": (
                    "v3 trace constants require independent generation and review"
                ),
            }
        )
    normalized_model_sha256 = (
        expected_model_sha256.lower()
        if isinstance(expected_model_sha256, str)
        else ""
    )
    if (
        len(normalized_model_sha256) != 64
        or any(char not in "0123456789abcdef" for char in normalized_model_sha256)
    ):
        return {
            "accepted": False,
            "failures": [
                {
                    "code": "invalid_expected_model_digest",
                    "detail": (
                        "expected model SHA-256 must contain 64 hexadecimal characters"
                    ),
                }
            ],
        }
    candidate_artifact = results.get("candidate_artifact")
    reported_model_sha256 = (
        candidate_artifact.get("sha256", "").lower()
        if isinstance(candidate_artifact, dict)
        and candidate_artifact.get("algorithm") == "sha256"
        and isinstance(candidate_artifact.get("sha256"), str)
        else ""
    )
    if reported_model_sha256 != normalized_model_sha256:
        failures.append(
            {
                "code": "model_digest_mismatch",
                "expected": normalized_model_sha256,
                "reported": reported_model_sha256,
            }
        )
    if results.get("protocol") != EXPECTED_PROTOCOL:
        failures.append(
            {
                "code": "trace_protocol",
                "detail": "evaluation must use the exact frozen trace protocol",
                "expected": EXPECTED_PROTOCOL,
            }
        )
    heuristic_result = results.get("heuristic")
    candidate_result = results.get("ppo")
    heuristic = (
        heuristic_result.get("per_seed")
        if isinstance(heuristic_result, dict)
        else None
    )
    candidate = (
        candidate_result.get("per_seed")
        if isinstance(candidate_result, dict)
        else None
    )
    if not isinstance(heuristic, dict) or not isinstance(candidate, dict):
        return {
            "accepted": False,
            "failures": [
                *failures,
                {
                    "code": "missing_policy",
                    "detail": "heuristic and ppo results are required",
                },
            ],
        }
    expected_seeds = {str(seed) for seed in EVALUATION_SEEDS}
    if set(heuristic) != expected_seeds or set(candidate) != expected_seeds:
        failures.append(
            {
                "code": "seed_protocol",
                "detail": "heuristic and ppo must use the same five frozen seeds",
            }
        )

    evaluated_seeds = sorted(expected_seeds & set(heuristic) & set(candidate))
    critical_recall_differences = []
    for seed in evaluated_seeds:
        baseline = heuristic[seed]
        proposed = candidate[seed]
        if not isinstance(baseline, dict) or not isinstance(proposed, dict):
            failures.append({"code": "invalid_seed_result", "seed": seed})
            continue
        missing = sorted(
            REQUIRED_METRICS - set(baseline) | REQUIRED_METRICS - set(proposed)
        )
        if missing:
            failures.append(
                {"code": "missing_metrics", "seed": seed, "metrics": missing}
            )
            continue
        values = [baseline[name] for name in REQUIRED_METRICS] + [
            proposed[name] for name in REQUIRED_METRICS
        ]
        if any(
            not _is_finite_number(value)
            for value in values
        ):
            failures.append({"code": "non_finite_metric", "seed": seed})
            continue
        if not _metrics_have_valid_domains(baseline) or not _metrics_have_valid_domains(
            proposed
        ):
            failures.append({"code": "invalid_metric_domain", "seed": seed})
            continue
        critical_recall_differences.append(
            proposed["critical_recall_mean"] - baseline["critical_recall_mean"]
        )
        if proposed["critical_recall_mean"] + 1e-9 < baseline["critical_recall_mean"]:
            failures.append(
                {
                    "code": "critical_recall_regression",
                    "seed": seed,
                    "baseline": baseline["critical_recall_mean"],
                    "candidate": proposed["critical_recall_mean"],
                }
            )
        baseline_slice_count = baseline["critical_recall_sample_count"]
        candidate_slice_count = proposed["critical_recall_sample_count"]
        expected_slice_count = EXPECTED_PROTOCOL[
            "expected_critical_sample_counts"
        ][seed]
        if (
            baseline_slice_count != expected_slice_count
            or candidate_slice_count != expected_slice_count
        ):
            failures.append(
                {
                    "code": "critical_slice_mismatch",
                    "seed": seed,
                    "baseline": baseline_slice_count,
                    "candidate": candidate_slice_count,
                    "expected": expected_slice_count,
                }
            )
        for metric in ("latency_p95_ms", "latency_p99_ms"):
            if proposed[metric] > baseline[metric] * maximum_latency_ratio:
                failures.append(
                    {
                        "code": "latency_regression",
                        "seed": seed,
                        "metric": metric,
                        "baseline": baseline[metric],
                        "candidate": proposed[metric],
                    }
                )
        if proposed["queue_peak"] > baseline["queue_peak"] * maximum_queue_ratio:
            failures.append(
                {
                    "code": "queue_regression",
                    "seed": seed,
                    "baseline": baseline["queue_peak"],
                    "candidate": proposed["queue_peak"],
                }
            )
        if baseline["override_action_bounds"] != 0:
            failures.append(
                {
                    "code": "unsafe_baseline_action",
                    "seed": seed,
                    "count": baseline["override_action_bounds"],
                }
            )
        if proposed["override_action_bounds"] != 0:
            failures.append(
                {
                    "code": "invalid_policy_action",
                    "seed": seed,
                    "count": proposed["override_action_bounds"],
                }
            )
        if baseline["override_critical_guard"] != 0:
            failures.append(
                {
                    "code": "unsafe_baseline_critical_action",
                    "seed": seed,
                    "count": baseline["override_critical_guard"],
                }
            )
        if proposed["override_critical_guard"] != 0:
            failures.append(
                {
                    "code": "unsafe_critical_action",
                    "seed": seed,
                    "count": proposed["override_critical_guard"],
                }
            )
        expected_fallbacks = EXPECTED_PROTOCOL["expected_fallback_counts"][seed]
        for reason in ("stale_telemetry", "gpu_degraded"):
            metric = f"override_{reason}"
            expected_count = expected_fallbacks[reason]
            if baseline[metric] != expected_count or proposed[metric] != expected_count:
                failures.append(
                    {
                        "code": "fallback_coverage_mismatch",
                        "seed": seed,
                        "reason": reason,
                        "expected": expected_count,
                        "baseline": baseline[metric],
                        "candidate": proposed[metric],
                    }
                )
    paired_ci95_low = None
    if len(critical_recall_differences) == len(EVALUATION_SEEDS):
        difference_mean = mean(critical_recall_differences)
        difference_stdev = stdev(critical_recall_differences)
        paired_ci95_low = (
            difference_mean
            - 2.776 * difference_stdev / math.sqrt(len(critical_recall_differences))
        )
        if paired_ci95_low < -1e-9:
            failures.append(
                {
                    "code": "critical_recall_ci_regression",
                    "paired_difference_mean": difference_mean,
                    "paired_ci95_low": paired_ci95_low,
                }
            )
    return {
        "accepted": not failures,
        "evaluated_seeds": evaluated_seeds,
        "critical_recall_paired_ci95_low": paired_ci95_low,
        "expected_model_sha256": normalized_model_sha256,
        "maximum_latency_ratio": maximum_latency_ratio,
        "maximum_queue_ratio": maximum_queue_ratio,
        "failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metrics", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--maximum-latency-ratio", type=float, default=1.10)
    parser.add_argument("--maximum-queue-ratio", type=float, default=1.10)
    args = parser.parse_args()
    if (
        not 1 <= args.maximum_latency_ratio <= 1.10
        or not 1 <= args.maximum_queue_ratio <= 1.10
    ):
        raise SystemExit("acceptance ratios must be between 1.0 and 1.10")
    if (
        not args.metrics.is_file()
        or args.metrics.stat().st_size > MAXIMUM_METRICS_FILE_BYTES
    ):
        raise SystemExit("metrics report must be a file no larger than 10 MiB")
    try:
        results = json.loads(
            args.metrics.read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit("metrics report must contain strict UTF-8 JSON") from exc
    model_path = resolve_model_path(args.model)
    report = check_acceptance(
        results,
        expected_model_sha256=sha256_file(model_path),
        maximum_latency_ratio=args.maximum_latency_ratio,
        maximum_queue_ratio=args.maximum_queue_ratio,
    )
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded)
    raise SystemExit(0 if report["accepted"] else 2)


if __name__ == "__main__":
    main()
