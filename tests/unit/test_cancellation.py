"""Unit tests for cancellation module in portsleuth CLI."""

import asyncio

import pytest

from portsleuth.exceptions import ScanInterrupted
from portsleuth.models import ScanOptions, Target, Technique
from portsleuth.scan.connect import scan_many


def test_scan_many_cancellation_returns_partial_results():
    async def run():
        targets = [Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)]
        ports = list(range(1, 200))
        options = ScanOptions(
            timeout=0.5,
            concurrency=5,
            rate_limit=2.0,
            technique=Technique.TCP_CONNECT,
        )
        task = asyncio.create_task(scan_many(targets, ports, options))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(ScanInterrupted):
            await task

    asyncio.run(run())
