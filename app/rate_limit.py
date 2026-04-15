"""Simple async token bucket for per-provider rate limiting."""

from __future__ import annotations

import asyncio
import time


class TokenBucket:
    """An async-friendly token bucket.

    Tokens refill continuously at `rate_per_second`. `try_acquire()` returns
    True if a token was available (and consumed), False otherwise. This lets
    the orchestrator skip a provider that's out of quota instead of blocking.
    """

    def __init__(self, capacity: int, rate_per_minute: int) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        self.capacity = float(capacity)
        self.rate_per_second = rate_per_minute / 60.0
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def try_acquire(self, tokens: float = 1.0) -> bool:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_second)
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    @property
    def available(self) -> float:
        """Non-locking peek at the current token count (approximate)."""
        now = time.monotonic()
        elapsed = now - self._last
        return min(self.capacity, self._tokens + elapsed * self.rate_per_second)


class RateLimiter:
    """Registry of TokenBuckets keyed by provider name."""

    def __init__(self, rate_per_minute: int, capacity: int | None = None) -> None:
        self._rate = rate_per_minute
        self._capacity = capacity or rate_per_minute
        self._buckets: dict[str, TokenBucket] = {}

    def _bucket(self, provider: str) -> TokenBucket:
        if provider not in self._buckets:
            self._buckets[provider] = TokenBucket(
                capacity=self._capacity, rate_per_minute=self._rate
            )
        return self._buckets[provider]

    async def try_acquire(self, provider: str) -> bool:
        return await self._bucket(provider).try_acquire()
