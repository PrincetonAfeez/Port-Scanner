"""Unit tests for rate limit module in portsleuth CLI."""

from portsleuth.concurrency.rate_limit import AsyncTokenBucket


def test_token_bucket_refills_to_capacity():
    bucket = AsyncTokenBucket(rate_per_second=10, capacity=3)
    bucket.tokens = 0
    bucket.updated_at = 1.0
    bucket._refill(1.5)
    assert bucket.tokens == 3

