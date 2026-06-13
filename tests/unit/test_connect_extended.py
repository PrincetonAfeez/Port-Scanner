"""Unit tests for connect extended module in portsleuth CLI."""

import asyncio
import socket

import pytest

from portsleuth.exceptions import ScanInterrupted
from portsleuth.lab.fixture_tcp import tcp_fixture
from portsleuth.models import ScanOptions, ScanState, Target, Technique
from portsleuth.scan.connect import build_dns_error_results, scan_many, scan_port


def test_scan_many_unsupported_technique_stubs():
    async def run():
        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)
        options = ScanOptions(
            timeout=0.5,
            concurrency=1,
            rate_limit=0,
            technique=Technique.TCP_SYN,
        )
        results = await scan_many([target], [80], options)
        assert results[0].state == ScanState.UNSUPPORTED

    asyncio.run(run())


def test_build_dns_error_results_empty():
    assert build_dns_error_results([], [80], Technique.TCP_CONNECT) == []
    assert build_dns_error_results([("bad", "err")], [], Technique.TCP_CONNECT) == []


def test_scan_port_permission_and_unexpected_error(monkeypatch):
    async def run():
        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)

        async def boom(*_args, **_kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr("portsleuth.scan.connect.asyncio.open_connection", boom)
        result = await scan_port(target, 80, timeout=0.2)
        assert result.state == ScanState.ERROR

    asyncio.run(run())


def test_scan_port_https_probe_with_insecure(monkeypatch):
    async def run():
        async with tcp_fixture(banner="not-tls") as fixture:
            target = Target(expression=fixture.host, address=fixture.host, is_loopback=True)
            monkeypatch.setattr("portsleuth.scan.connect.HTTPS_LIKE_PORTS", {fixture.port})
            result = await scan_port(
                target,
                fixture.port,
                timeout=0.5,
                probe=True,
                probe_insecure=True,
            )
        assert result.state == ScanState.OPEN

    asyncio.run(run())


def test_scan_many_with_rate_limiter():
    async def run():
        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)
        closed = _free_port()
        options = ScanOptions(
            timeout=0.2,
            concurrency=2,
            rate_limit=50,
            technique=Technique.TCP_CONNECT,
        )
        results = await scan_many([target], [closed], options)
        assert len(results) == 1

    asyncio.run(run())


def test_scan_many_progress_callback():
    async def run():
        seen = []

        async def progress(result):
            seen.append(result.port)

        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)
        closed = _free_port()
        options = ScanOptions(timeout=0.2, concurrency=1, rate_limit=0, technique=Technique.TCP_CONNECT)
        await scan_many([target], [closed], options, progress)
        assert seen == [closed]

    asyncio.run(run())


def test_scan_many_cancel_raises_scan_interrupted():
    async def run():
        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)
        ports = list(range(1, 100))
        options = ScanOptions(timeout=0.05, concurrency=20, rate_limit=0, technique=Technique.TCP_CONNECT)
        task = asyncio.create_task(scan_many([target], ports, options))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(ScanInterrupted):
            await task

    asyncio.run(run())


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
