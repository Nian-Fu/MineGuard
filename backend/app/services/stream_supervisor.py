import asyncio
import contextlib
import random
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class StreamState(StrEnum):
    CONNECTING = "connecting"
    ONLINE = "online"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    STOPPED = "stopped"


@dataclass(frozen=True)
class ReconnectPolicy:
    initial_delay_seconds: float = 1.0
    maximum_delay_seconds: float = 30.0
    multiplier: float = 2.0
    jitter_ratio: float = 0.2
    stable_reset_seconds: float = 60.0

    def delay_for(self, attempt: int, random_value: float | None = None) -> float:
        exponent = max(attempt - 1, 0)
        try:
            backoff = self.initial_delay_seconds * self.multiplier**exponent
        except OverflowError:
            backoff = self.maximum_delay_seconds
        base = min(backoff, self.maximum_delay_seconds)
        sample = random.random() if random_value is None else random_value
        jitter = base * self.jitter_ratio * (sample * 2 - 1)
        return max(0.0, base + jitter)


StateCallback = Callable[[StreamState, str | None], Awaitable[None]]
Connector = Callable[[], Awaitable[AsyncIterator[Any]]]
FrameCallback = Callable[[Any], Awaitable[None]]


class StreamSupervisor:
    """Keeps a single stream alive without allowing a reconnect hot loop."""

    def __init__(
        self,
        connector: Connector,
        on_frame: FrameCallback,
        on_state: StateCallback,
        policy: ReconnectPolicy | None = None,
    ) -> None:
        self.connector = connector
        self.on_frame = on_frame
        self.on_state = on_state
        self.policy = policy or ReconnectPolicy()
        self._stop = asyncio.Event()

    async def run(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            await self.on_state(StreamState.CONNECTING, None)
            connected_at = asyncio.get_running_loop().time()
            try:
                frames = await self.connector()
                await self.on_state(StreamState.ONLINE, None)
                async for frame in frames:
                    if self._stop.is_set():
                        break
                    await self.on_frame(frame)
                if not self._stop.is_set():
                    raise ConnectionError("stream ended unexpectedly")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                online_seconds = asyncio.get_running_loop().time() - connected_at
                attempt = 1 if online_seconds >= self.policy.stable_reset_seconds else attempt + 1
                await self.on_state(StreamState.DEGRADED, type(exc).__name__)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.policy.delay_for(attempt))
                except TimeoutError:
                    continue
        await self.on_state(StreamState.STOPPED, None)

    async def stop(self) -> None:
        self._stop.set()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        with contextlib.suppress(Exception):
            await self.stop()
