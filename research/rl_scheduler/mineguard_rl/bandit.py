from collections.abc import Sequence
from math import isfinite

import numpy as np

from mineguard_rl.environment import MineSchedulingEnv
from mineguard_rl.traces import generate_trace


DEVELOPMENT_BANDIT_SEEDS = tuple(range(20260807, 20260812))
DEFAULT_FEATURE_INDICES = tuple(range(10))
NO_QUEUE_FEATURE_INDICES = tuple(index for index in range(10) if index != 1)
NO_FAULT_FEATURE_INDICES = tuple(index for index in range(10) if index not in (8, 9))

# The pool keeps critical-stream settings inside the hard guard. The environment
# still applies stale-telemetry and degraded-GPU fallbacks to every policy.
SAFE_ACTION_POOL = np.array(
    [
        [0, 2, 0, 2, 1],
        [0, 2, 1, 1, 1],
        [0, 2, 3, 0, 2],
        [1, 1, 1, 1, 1],
        [1, 1, 3, 0, 2],
        [0, 1, 2, 1, 2],
    ],
    dtype=np.int64,
)


class LinearContextualBandit:
    """Small LinUCB baseline for short-horizon scheduling comparisons."""

    def __init__(
        self,
        *,
        feature_indices: Sequence[int] = DEFAULT_FEATURE_INDICES,
        exploration: float = 0.75,
        ridge: float = 1.0,
    ) -> None:
        normalized_features = tuple(feature_indices)
        if (
            not normalized_features
            or len(set(normalized_features)) != len(normalized_features)
            or any(
                isinstance(index, bool)
                or not isinstance(index, int)
                or index not in range(15)
                for index in normalized_features
            )
        ):
            raise ValueError("feature indices must be unique integers from 0 to 14")
        if not isfinite(exploration) or exploration < 0:
            raise ValueError("exploration must be finite and nonnegative")
        if not isfinite(ridge) or ridge <= 0:
            raise ValueError("ridge must be finite and positive")
        self.feature_indices = normalized_features
        self.exploration = exploration
        dimensions = len(normalized_features) + 1
        action_count = len(SAFE_ACTION_POOL)
        self._covariance = np.repeat(
            (np.eye(dimensions, dtype=np.float64) * ridge)[None, :, :],
            action_count,
            axis=0,
        )
        self._reward = np.zeros((action_count, dimensions), dtype=np.float64)

    def _context(self, observation: np.ndarray) -> np.ndarray:
        values = np.asarray(observation, dtype=np.float64)
        if values.shape != (15,) or not np.all(np.isfinite(values)):
            raise ValueError("bandit observation must contain 15 finite values")
        return np.concatenate(
            (np.array([1.0], dtype=np.float64), values[list(self.feature_indices)])
        )

    def select(
        self, observation: np.ndarray, *, explore: bool
    ) -> tuple[int, np.ndarray]:
        context = self._context(observation)
        scores = []
        for action_index in range(len(SAFE_ACTION_POOL)):
            covariance = self._covariance[action_index]
            parameters = np.linalg.solve(covariance, self._reward[action_index])
            score = float(parameters @ context)
            if explore:
                uncertainty = float(context @ np.linalg.solve(covariance, context))
                score += self.exploration * np.sqrt(max(uncertainty, 0.0))
            scores.append(score)
        selected = int(np.argmax(scores))
        return selected, SAFE_ACTION_POOL[selected].copy()

    def update(self, observation: np.ndarray, action_index: int, reward: float) -> None:
        if (
            isinstance(action_index, bool)
            or not isinstance(action_index, int)
            or action_index not in range(len(SAFE_ACTION_POOL))
        ):
            raise ValueError("action index is outside the bandit action pool")
        if isinstance(reward, bool) or not isfinite(reward):
            raise ValueError("reward must be finite")
        context = self._context(observation)
        self._covariance[action_index] += np.outer(context, context)
        self._reward[action_index] += reward * context


def fit_contextual_bandit(
    feature_indices: Sequence[int] = DEFAULT_FEATURE_INDICES,
) -> LinearContextualBandit:
    bandit = LinearContextualBandit(feature_indices=feature_indices)
    for seed in DEVELOPMENT_BANDIT_SEEDS:
        env = MineSchedulingEnv(generate_trace(1000, seed))
        observation, _ = env.reset(seed=seed)
        terminated = False
        while not terminated:
            action_index, action = bandit.select(observation, explore=True)
            next_observation, reward, terminated, _, _ = env.step(action)
            bandit.update(observation, action_index, reward)
            observation = next_observation
    return bandit
