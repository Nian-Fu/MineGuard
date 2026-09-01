import asyncio

from app.services.stream_supervisor import ReconnectPolicy, StreamState, StreamSupervisor


def test_reconnect_policy_exponential_cap_and_jitter():
    policy = ReconnectPolicy(
        initial_delay_seconds=1,
        maximum_delay_seconds=10,
        multiplier=2,
        jitter_ratio=0.2,
    )
    assert policy.delay_for(1, random_value=0.5) == 1
    assert policy.delay_for(3, random_value=0.5) == 4
    assert policy.delay_for(10, random_value=0.5) == 10
    assert policy.delay_for(1, random_value=0) == 0.8
    assert policy.delay_for(1, random_value=1) == 1.2
    assert policy.delay_for(1_000_000, random_value=0.5) == 10


def test_stream_supervisor_reports_only_error_type():
    states = []

    async def connector():
        raise ConnectionError("rtsp://reader:secret@camera.internal/live")

    async def on_frame(_):
        return None

    async def on_state(state, error):
        states.append((state, error))
        if state == StreamState.DEGRADED:
            supervisor._stop.set()

    supervisor = StreamSupervisor(
        connector,
        on_frame,
        on_state,
        ReconnectPolicy(initial_delay_seconds=0, maximum_delay_seconds=0),
    )
    asyncio.run(supervisor.run())

    assert (StreamState.DEGRADED, "ConnectionError") in states
    assert all("secret" not in (error or "") for _, error in states)
