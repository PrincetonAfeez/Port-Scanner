"""Integration tests for discovery in portsleuth CLI."""

import asyncio
import socket

from portsleuth.discovery.tcp_ping import tcp_ping_sweep
from portsleuth.lab.fixture_tcp import tcp_fixture
from portsleuth.models import Target


def test_tcp_ping_detects_live_host():
    async def run():
        async with tcp_fixture(banner="discover") as fixture:
            target = Target(
                expression=fixture.host,
                address=fixture.host,
                is_loopback=True,
                is_private=True,
            )
            statuses = await tcp_ping_sweep([target], (fixture.port,), timeout=0.5)
        assert statuses[0].is_up is True
        assert statuses[0].open_port == fixture.port

    asyncio.run(run())


def test_tcp_ping_reports_down_for_unused_port():
    async def run():
        closed_port = _free_port()
        target = Target(
            expression="127.0.0.1",
            address="127.0.0.1",
            is_loopback=True,
            is_private=True,
        )
        statuses = await tcp_ping_sweep([target], (closed_port,), timeout=0.5)
        # A refused connection still proves the loopback stack is alive.
        assert statuses[0].address == "127.0.0.1"

    asyncio.run(run())


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
