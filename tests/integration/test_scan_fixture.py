"""Integration tests for scan fixture in portsleuth CLI."""

import asyncio
import socket

import portsleuth.scan.connect as connect
from portsleuth.lab.fixture_tcp import tcp_fixture
from portsleuth.models import ScanOptions, ScanState, Target, Technique
from portsleuth.scan.connect import scan_many


def test_async_tcp_fixture_scan_open_and_closed():
    async def run():
        closed_port = _free_port()
        async with tcp_fixture(banner="portsleuth integration") as fixture:
            target = Target(
                expression=fixture.host,
                address=fixture.host,
                is_loopback=True,
                is_private=True,
            )
            options = ScanOptions(
                timeout=0.5,
                concurrency=10,
                rate_limit=0,
                technique=Technique.TCP_CONNECT,
                probe=True,
            )
            results = await scan_many(targets=[target], ports=[fixture.port, closed_port], options=options)
        by_port = {result.port: result for result in results}
        assert by_port[fixture.port].state == ScanState.OPEN
        assert by_port[fixture.port].banner == "portsleuth integration"
        assert by_port[closed_port].state in {ScanState.CLOSED, ScanState.FILTERED, ScanState.UNKNOWN}

    asyncio.run(run())


def test_http_like_port_falls_back_to_banner_when_not_http(monkeypatch):
    async def run():
        async with tcp_fixture(banner="RAW-NOT-HTTP") as fixture:
            # Force the fixture's port to be treated as HTTP-like so the HTTP
            # probe runs first, fails to parse, and falls back to a banner grab.
            monkeypatch.setattr(connect, "HTTP_LIKE_PORTS", {fixture.port})
            target = Target(
                expression=fixture.host,
                address=fixture.host,
                is_loopback=True,
                is_private=True,
            )
            options = ScanOptions(
                timeout=0.5,
                concurrency=4,
                rate_limit=0,
                technique=Technique.TCP_CONNECT,
                probe=True,
            )
            results = await scan_many(targets=[target], ports=[fixture.port], options=options)
        result = results[0]
        assert result.state == ScanState.OPEN
        assert result.banner == "RAW-NOT-HTTP"
        assert result.http is None

    asyncio.run(run())


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])

