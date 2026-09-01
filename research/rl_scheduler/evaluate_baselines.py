import argparse
import io
import json
from collections.abc import Callable
from pathlib import Path

import numpy as np
from stable_baselines3 import PPO

from mineguard_rl.bandit import (
    DEFAULT_FEATURE_INDICES,
    NO_FAULT_FEATURE_INDICES,
    NO_QUEUE_FEATURE_INDICES,
    fit_contextual_bandit,
)
from mineguard_rl.environment import MineSchedulingEnv
from mineguard_rl.integrity import read_verified_artifact, resolve_model_path
from mineguard_rl.traces import (
    EVALUATION_SEEDS,
    EVALUATION_TRACE_LENGTH,
    evaluation_protocol,
    generate_trace,
)

Policy = Callable[[np.ndarray, MineSchedulingEnv], np.ndarray]


def heuristic_policy(observation: np.ndarray, _: MineSchedulingEnv) -> np.ndarray:
    gpu, queue, _, _, critical, _, _, _ = observation[:8]
    if critical >= 0.5:
        return np.array([0, 2, 1, 1, 1])
    if gpu > 0.85 or queue > 0.4:
        return np.array([1, 1, 3, 0, 2])
    if gpu > 0.65:
        return np.array([1, 1, 1, 1, 1])
    return np.array([0, 2, 0, 2, 1])


def random_policy(_: np.ndarray, env: MineSchedulingEnv) -> np.ndarray:
    return env.action_space.sample()


def bandit_policy(feature_indices: tuple[int, ...]) -> Policy:
    bandit = fit_contextual_bandit(feature_indices)

    def policy(observation: np.ndarray, _: MineSchedulingEnv) -> np.ndarray:
        return bandit.select(observation, explore=False)[1]

    return policy


def evaluate(policy: Policy, seed: int) -> dict[str, float]:
    env = MineSchedulingEnv(generate_trace(EVALUATION_TRACE_LENGTH, seed))
    env.action_space.seed(seed)
    observation, _ = env.reset(seed=seed)
    rewards, latencies, recalls = [], [], []
    critical_recalls, queues, loads = [], [], []
    safety_overrides = 0
    override_reasons = {
        "action_bounds": 0,
        "stale_telemetry": 0,
        "gpu_degraded": 0,
        "critical_guard": 0,
    }
    action_switches = 0
    previous_action = None
    terminated = False
    while not terminated:
        observation, reward, terminated, _, info = env.step(policy(observation, env))
        rewards.append(reward)
        latencies.append(info["latency_ms"])
        recalls.append(info["recall_proxy"])
        if info["critical_zone_ratio"] > 0:
            critical_recalls.append(info["critical_recall"])
        queues.append(info["queue_depth"])
        loads.append(info["load"])
        safety_overrides += int(info["safety_override"])
        for reason in (info["fallback_reason"] or "").split(","):
            if reason in override_reasons:
                override_reasons[reason] += 1
        applied_action = np.asarray(info["applied_action"])
        if previous_action is not None:
            action_switches += int(np.any(applied_action != previous_action))
        previous_action = applied_action
    return {
        "step_count": float(len(rewards)),
        "reward_sum": float(np.sum(rewards)),
        "recall_mean": float(np.mean(recalls)),
        "critical_recall_mean": float(np.mean(critical_recalls)),
        "critical_recall_sample_count": float(len(critical_recalls)),
        "latency_p95_ms": float(np.percentile(latencies, 95)),
        "latency_p99_ms": float(np.percentile(latencies, 99)),
        "queue_peak": float(np.max(queues)),
        "gpu_load_mean": float(np.mean(loads)),
        "gpu_load_p95": float(np.percentile(loads, 95)),
        "action_switches": float(action_switches),
        "safety_overrides": float(safety_overrides),
        **{
            f"override_{reason}": float(count)
            for reason, count in override_reasons.items()
        },
    }


def aggregate_metrics(
    per_seed: dict[str, dict[str, float]],
) -> dict[str, dict[str, float]]:
    if len(per_seed) != 5:
        raise ValueError("the frozen evaluation protocol requires exactly five seeds")
    result = {}
    for metric in next(iter(per_seed.values())):
        values = np.array([run[metric] for run in per_seed.values()], dtype=np.float64)
        standard_deviation = float(np.std(values, ddof=1))
        # Student t critical value for the fixed five-seed protocol (df=4).
        half_width = 2.776 * standard_deviation / np.sqrt(len(values))
        result[metric] = {
            "mean": float(np.mean(values)),
            "standard_deviation": standard_deviation,
            "ci95_low": float(np.mean(values) - half_width),
            "ci95_high": float(np.mean(values) + half_width),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path)
    parser.add_argument("--expected-model-sha256")
    parser.add_argument(
        "--output", type=Path, default=Path("artifacts/baseline_metrics.json")
    )
    args = parser.parse_args()
    policies: dict[str, Policy] = {
        "heuristic": heuristic_policy,
        "random": random_policy,
    }
    model_path = None
    model_sha256 = None
    if args.model:
        if not args.expected_model_sha256:
            parser.error("--expected-model-sha256 is required with --model")
        model_path = resolve_model_path(args.model)
        try:
            model_bytes, model_sha256 = read_verified_artifact(
                model_path, args.expected_model_sha256
            )
        except ValueError as exc:
            parser.error(str(exc))
        model = PPO.load(io.BytesIO(model_bytes))
        del model_bytes

        def ppo_policy(observation: np.ndarray, _: MineSchedulingEnv) -> np.ndarray:
            action, _ = model.predict(observation, deterministic=True)
            return action

        policies["ppo"] = ppo_policy
    policies.update(
        {
            "contextual_bandit": bandit_policy(DEFAULT_FEATURE_INDICES),
            "contextual_bandit_no_queue": bandit_policy(NO_QUEUE_FEATURE_INDICES),
            "contextual_bandit_no_fault_state": bandit_policy(
                NO_FAULT_FEATURE_INDICES
            ),
        }
    )
    results = {"protocol": evaluation_protocol()}
    if model_path:
        results["candidate_artifact"] = {
            "algorithm": "sha256",
            "sha256": model_sha256,
        }
    for name, policy in policies.items():
        per_seed = {str(seed): evaluate(policy, seed) for seed in EVALUATION_SEEDS}
        results[name] = {"per_seed": per_seed, "aggregate": aggregate_metrics(per_seed)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
