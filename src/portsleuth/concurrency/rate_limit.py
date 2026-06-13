"""Rate limiting for portsleuth CLI."""

from __future__ import annotations

import asyncio


class AsyncTokenBucket:
    """Small asyncio token bucket used to pace connection attempts."""

    #: Default burst ceiling so that scans smaller than the rate are still paced.
    DEFAULT_MAX_BURST = 10.0

    def __init__(self, rate_per_second: float, capacity: float | None = None) -> None:
        self.rate_per_second = float(rate_per_second)
        if capacity is not None:
            self.capacity = float(capacity)
        else:
            # Without a small cap, capacity == rate lets a whole small scan drain
            # the bucket instantly, defeating the politeness/safety lever.
            self.capacity = float(min(max(1.0, rate_per_second), self.DEFAULT_MAX_BURST))
        self.tokens = self.capacity
        self.updated_at: float | None = None
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self.rate_per_second > 0

    async def wait(self) -> None:
        if not self.enabled:
            return
        while True:
            async with self._lock:
                loop = asyncio.get_running_loop()
                now = loop.time()
                self._refill(now)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                missing = 1.0 - self.tokens
                delay = missing / self.rate_per_second
            await asyncio.sleep(delay)

    def _refill(self, now: float) -> None:
        if self.updated_at is None:
            self.updated_at = now
            return
        elapsed = max(0.0, now - self.updated_at)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_per_second)
        self.updated_at = now

