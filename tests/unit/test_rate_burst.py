"""Unit tests for rate burst module in portsleuth CLI."""

from portsleuth.concurrency.rate_limit import AsyncTokenBucket


def test_default_capacity_is_capped_for_pacing():
    # A high rate must not give an unbounded initial burst, or small scans would
    # never be paced at all.
    bucket = AsyncTokenBucket(rate_per_second=200)
    assert bucket.capacity == AsyncTokenBucket.DEFAULT_MAX_BURST
    assert bucket.tokens == AsyncTokenBucket.DEFAULT_MAX_BURST


def test_low_rate_keeps_full_rate_as_capacity():
    bucket = AsyncTokenBucket(rate_per_second=3)
    assert bucket.capacity == 3.0


def test_explicit_capacity_is_respected():
    bucket = AsyncTokenBucket(rate_per_second=200, capacity=5)
    assert bucket.capacity == 5.0
