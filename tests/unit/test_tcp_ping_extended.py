"""Unit tests for tcp ping extended module in portsleuth CLI."""

import asyncio
import socket

import pytest

from portsleuth.discovery.tcp_ping import HostStatus, _dedupe_statuses, tcp_ping_host, tcp_ping_sweep
from portsleuth.exceptions import DiscoverInterrupted
from portsleuth.lab.fixture_tcp import tcp_fixture
from portsleuth.models import Target


def test_tcp_ping_open_and_refused_paths():
    async def run_open():
        async with tcp_fixture(banner="x") as fixture:
            target = Target(expression=fixture.host, address=fixture.host, is_loopback=True)
            status = await tcp_ping_host(target, (fixture.port,), timeout=0.5)
        assert status.is_up is True
        assert status.open_port == fixture.port

    asyncio.run(run_open())

    async def run_refused():
        port = _free_port()
        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)

        async def fake_open_connection(*_args, **_kwargs):
            raise ConnectionRefusedError()

        import portsleuth.discovery.tcp_ping as tcp_ping

        original = tcp_ping.asyncio.open_connection
        tcp_ping.asyncio.open_connection = fake_open_connection
        try:
            status = await tcp_ping_host(target, (port,), timeout=0.5)
        finally:
            tcp_ping.asyncio.open_connection = original
        assert status.is_up is True
        assert status.open_port is None

    asyncio.run(run_refused())


def test_tcp_ping_timeout_returns_down():
    async def run():
        port = _free_port()
        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)
        status = await tcp_ping_host(target, (port,), timeout=0.01)
        assert status.is_up is False

    asyncio.run(run())


def test_tcp_ping_sweep_with_rate_limit_and_interrupt():
    async def run_rate():
        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)
        statuses = await tcp_ping_sweep([target], (9,), timeout=0.2, rate_limit=100)
        assert len(statuses) == 1

    asyncio.run(run_rate())

    async def run_interrupt():
        targets = [Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True) for _ in range(50)]
        task = asyncio.create_task(tcp_ping_sweep(targets, (9,), timeout=0.5, concurrency=5))
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(DiscoverInterrupted):
            await task

    asyncio.run(run_interrupt())


def test_dedupe_statuses():
    a = HostStatus(target="a", address="1.1.1.1", is_up=True)
    b = HostStatus(target="a", address="1.1.1.1", is_up=False)
    c = HostStatus(target="b", address="1.1.1.1", is_up=True)
    deduped = _dedupe_statuses([a, b, c])
    assert len(deduped) == 2


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
