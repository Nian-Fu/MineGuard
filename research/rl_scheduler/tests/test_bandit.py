import numpy as np
import pytest

from mineguard_rl.bandit import LinearContextualBandit, SAFE_ACTION_POOL


def observation() -> np.ndarray:
    return np.linspace(0.0, 1.0, 15, dtype=np.float32)


def test_bandit_returns_only_pre_guarded_critical_actions():
    bandit = LinearContextualBandit()

    _, action = bandit.select(observation(), explore=True)

    assert any(np.array_equal(action, candidate) for candidate in SAFE_ACTION_POOL)
    assert action[0] <= 1
    assert action[1] >= 1


def test_bandit_update_changes_deterministic_preference():
    bandit = LinearContextualBandit(exploration=0)
    current = observation()
    for _ in range(5):
        bandit.update(current, 3, 10.0)

    selected, action = bandit.select(current, explore=False)

    assert selected == 3
    assert np.array_equal(action, SAFE_ACTION_POOL[3])


@pytest.mark.parametrize(
    "feature_indices",
    [(), (1, 1), (-1,), (15,), (True,)],
)
def test_bandit_rejects_invalid_feature_sets(feature_indices):
    with pytest.raises(ValueError, match="feature indices"):
        LinearContextualBandit(feature_indices=feature_indices)


def test_bandit_rejects_non_finite_observation():
    bandit = LinearContextualBandit()
    current = observation()
    current[4] = np.nan

    with pytest.raises(ValueError, match="15 finite"):
        bandit.select(current, explore=False)
