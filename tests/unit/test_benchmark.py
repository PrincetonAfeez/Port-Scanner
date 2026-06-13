"""Unit tests for benchmark module in portsleuth CLI."""

import asyncio

from portsleuth.concurrency.benchmark import BenchmarkResult, run_async_benchmark
from portsleuth.exceptions import ScanInterrupted
from portsleuth.models import PortResult, ScanState, Target


def test_benchmark_result_other_property():
    result = BenchmarkResult(
        technique="sync",
        ports=1,
        concurrency=1,
        timeout=0.5,
        duration_ms=1.0,
        open=0,
        closed=0,
        filtered=0,
        unreachable=1,
        permission_denied=1,
        unknown=1,
        error=1,
    )
    data = result.to_dict()
    assert result.other == 4
    assert data["other"] == 4


def test_run_async_benchmark_partial_on_interrupt(monkeypatch):
    async def fake_scan_many(*_args, **_kwargs):
        raise ScanInterrupted(
            [
                PortResult(
                    target="127.0.0.1",
                    address="127.0.0.1",
                    port=9,
                    state=ScanState.CLOSED,
                )
            ]
        )

    monkeypatch.setattr("portsleuth.concurrency.benchmark.scan_many", fake_scan_many)

    async def run():
        result = await run_async_benchmark(
            [Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)],
            [9],
            timeout=0.2,
            concurrency=1,
            rate_limit=0,
        )
        assert result.technique == "asyncio (partial)"
        assert result.closed == 1

    asyncio.run(run())
