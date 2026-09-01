import pytest
from pydantic import ValidationError

from app.services.rl_scheduler import SchedulingState


def state_payload(**overrides):
    payload = {
        "gpu_utilization": 0.5,
        "queue_depth": 10,
        "active_streams": 8,
        "critical_zone_ratio": 0.2,
    }
    payload.update(overrides)
    return payload


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("gpu_utilization", "0.5"),
        ("critical_zone_ratio", True),
        ("telemetry_age_seconds", float("nan")),
        ("healthy_gpu_ratio", float("inf")),
        ("queue_depth", "10"),
        ("active_streams", False),
    ],
)
def test_scheduling_state_rejects_coerced_or_non_finite_telemetry(field, value):
    with pytest.raises(ValidationError):
        SchedulingState(**state_payload(**{field: value}))


def test_scheduling_state_accepts_json_integers_for_float_fields():
    state = SchedulingState(
        **state_payload(
            gpu_utilization=0,
            critical_zone_ratio=1,
            telemetry_age_seconds=30,
            healthy_gpu_ratio=1,
        )
    )
    assert state.telemetry_age_seconds == 30.0
    defaults = SchedulingState(**state_payload())
    assert defaults.telemetry_age_seconds == 0.0
    assert defaults.healthy_gpu_ratio == 1.0
