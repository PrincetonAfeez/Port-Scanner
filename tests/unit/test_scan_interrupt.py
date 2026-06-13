"""Unit tests for scan interrupt module in portsleuth CLI."""

import asyncio

import pytest

from portsleuth.exceptions import ScanInterrupted
from portsleuth.models import ScanOptions, Target, Technique
from portsleuth.scan.connect import scan_many


def test_scan_many_interrupt_deduplicates_results():
    async def run():
        targets = [Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)]
        ports = list(range(1, 500))
        options = ScanOptions(
            timeout=0.05,
            concurrency=50,
            rate_limit=0,
            technique=Technique.TCP_CONNECT,
        )
        task = asyncio.create_task(scan_many(targets, ports, options))
        await asyncio.sleep(0.15)
        task.cancel()
        with pytest.raises(ScanInterrupted) as exc_info:
            await task
        keys = [(item.target, item.address, item.port) for item in exc_info.value.results]
        assert len(keys) == len(set(keys))

    asyncio.run(run())
