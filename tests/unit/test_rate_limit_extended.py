"""Unit tests for rate limit extended module in portsleuth CLI."""

import asyncio

from portsleuth.concurrency.rate_limit import AsyncTokenBucket


def test_token_bucket_disabled_returns_immediately():
    async def run():
        bucket = AsyncTokenBucket(0)
        assert bucket.enabled is False
        await bucket.wait()

    asyncio.run(run())
