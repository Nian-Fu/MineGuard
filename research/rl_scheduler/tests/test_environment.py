import numpy as np
import pytest

from mineguard_rl.environment import MineSchedulingEnv, WorkloadStep


def test_critical_zone_overrides_unsafe_action():
    env = MineSchedulingEnv([WorkloadStep(20, 0.5, 0.8, 0.5)] * 2)
    env.reset(seed=1)
    _, _, _, _, info = env.step(np.array([3, 0, 3, 0, 2]))
    assert info["safety_override"] is True
    assert info["applied_action"][:2] == [1, 1]


def test_environment_is_seed_replayable():
    trace = [WorkloadStep(16, 0.3, 0.2, 0.2)] * 3
    first, second = MineSchedulingEnv(trace), MineSchedulingEnv(trace)
    assert np.array_equal(first.reset(seed=42)[0], second.reset(seed=42)[0])
    action = np.array([1, 1, 1, 1, 1])
    first_step, second_step = first.step(action), second.step(action)
    assert np.array_equal(first_step[0], second_step[0])
    assert first_step[1:] == second_step[1:]


def test_observation_contains_normalized_previous_action():
    env = MineSchedulingEnv([WorkloadStep(12, 0.2, 0.2, 0.1)] * 2)
    observation, _ = env.reset(seed=7)
    assert observation.shape == (15,)
    action = np.array([1, 1, 3, 0, 2])
    observation, _, _, _, _ = env.step(action)
    assert np.allclose(observation[-5:], np.array([1 / 3, 1 / 2, 1, 0, 1]))


def test_initial_observation_includes_trace_queue_depth():
    env = MineSchedulingEnv(
        [WorkloadStep(12, 0.2, 0.2, 0.1, base_queue_depth=125)] * 2
    )
    observation, _ = env.reset(seed=7)
    assert observation[1] == pytest.approx(0.25)


@pytest.mark.parametrize("gpu_capacity", [0, -1, float("inf"), float("nan")])
def test_gpu_capacity_must_be_finite_and_positive(gpu_capacity):
    with pytest.raises(ValueError, match="gpu_capacity"):
        MineSchedulingEnv([WorkloadStep(12, 0.2, 0.2, 0.1)], gpu_capacity)


def test_gpu_capacity_changes_queue_dynamics():
    trace = [WorkloadStep(12, 0.8, 0.5, 0.8)] * 2
    constrained = MineSchedulingEnv(trace, gpu_capacity=0.5)
    oversized = MineSchedulingEnv(trace, gpu_capacity=2.0)
    action = np.array([0, 2, 0, 2, 0])
    constrained.reset(seed=1)
    oversized.reset(seed=1)
    constrained_info = constrained.step(action)[4]
    oversized_info = oversized.step(action)[4]
    assert constrained_info["queue_depth"] > oversized_info["queue_depth"]
    assert oversized_info["queue_depth"] == 0


def test_workload_rejects_non_finite_telemetry():
    with pytest.raises(ValueError, match="finite"):
        WorkloadStep(12, 0.2, 0.2, 0.1, telemetry_age_seconds=float("nan"))


@pytest.mark.parametrize("active_streams", [True, 1.5, 0, 257])
def test_workload_requires_bounded_integer_stream_count(active_streams):
    with pytest.raises(ValueError, match="active_streams"):
        WorkloadStep(active_streams, 0.2, 0.2, 0.1)


@pytest.mark.parametrize("base_queue_depth", [True, 1.5, -1, 501])
def test_workload_requires_bounded_integer_queue_depth(base_queue_depth):
    with pytest.raises(ValueError, match="queue depth"):
        WorkloadStep(12, 0.2, 0.2, 0.1, base_queue_depth=base_queue_depth)


def test_stale_telemetry_forces_deterministic_fallback():
    trace = [WorkloadStep(16, 0.3, 0.5, 0.2, telemetry_age_seconds=31)] * 2
    env = MineSchedulingEnv(trace)
    env.reset(seed=4)
    _, _, _, _, info = env.step(np.array([3, 0, 0, 2, 2]))
    assert info["safety_override"] is True
    assert info["fallback_reason"] == "stale_telemetry"
    assert info["applied_action"] == [0, 2, 3, 0, 0]


def test_out_of_range_actions_are_clipped_before_simulation():
    env = MineSchedulingEnv([WorkloadStep(8, 0.1, 0.0, 0.1)] * 2)
    env.reset(seed=5)
    _, _, _, _, info = env.step(np.array([-10, 99, 99, -2, 99]))
    assert info["safety_override"] is True
    assert info["fallback_reason"] == "action_bounds"
    assert info["applied_action"] == [0, 2, 3, 0, 2]


def test_extreme_integer_actions_clip_without_int64_overflow():
    env = MineSchedulingEnv([WorkloadStep(8, 0.1, 0.0, 0.1)] * 2)
    env.reset(seed=5)
    _, _, _, _, info = env.step(np.array([1e300] * 5))
    assert info["fallback_reason"] == "action_bounds"
    assert info["applied_action"] == [3, 2, 3, 2, 2]


def test_boolean_actions_are_rejected():
    env = MineSchedulingEnv([WorkloadStep(8, 0.1, 0.0, 0.1)] * 2)
    env.reset(seed=5)
    with pytest.raises(ValueError, match="finite values"):
        env.step(np.array([True, False, True, False, True]))


def test_absent_critical_streams_do_not_create_free_critical_recall_reward():
    trace = [WorkloadStep(12, 0.2, 0.0, 0.1)] * 2
    first = MineSchedulingEnv(trace)
    second = MineSchedulingEnv(trace)
    first.reset(seed=1)
    second.reset(seed=1)
    first_step = first.step(np.array([1, 1, 0, 2, 1]))
    second_step = second.step(np.array([3, 0, 0, 2, 1]))
    first_reward = first_step[1]
    second_reward = second_step[1]
    assert first_reward == pytest.approx(second_reward)
    assert first_step[4]["critical_zone_ratio"] == 0
