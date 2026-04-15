import asyncio

import pytest

from app.rate_limit import RateLimiter, TokenBucket


async def test_token_bucket_allows_up_to_capacity():
    bucket = TokenBucket(capacity=3, rate_per_minute=60)
    assert await bucket.try_acquire()
    assert await bucket.try_acquire()
    assert await bucket.try_acquire()
    assert not await bucket.try_acquire()


async def test_token_bucket_refills_over_time():
    bucket = TokenBucket(capacity=1, rate_per_minute=6000)  # 100/s
    assert await bucket.try_acquire()
    assert not await bucket.try_acquire()
    await asyncio.sleep(0.05)  # ~5 tokens worth
    assert await bucket.try_acquire()


async def test_rate_limiter_per_provider_isolation():
    limiter = RateLimiter(rate_per_minute=60, capacity=1)
    assert await limiter.try_acquire("a")
    assert not await limiter.try_acquire("a")
    assert await limiter.try_acquire("b")


def test_token_bucket_rejects_bad_args():
    with pytest.raises(ValueError):
        TokenBucket(capacity=0, rate_per_minute=60)
    with pytest.raises(ValueError):
        TokenBucket(capacity=1, rate_per_minute=0)
