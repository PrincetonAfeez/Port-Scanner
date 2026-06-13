"""TCP fixture for portsleuth CLI."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass


@dataclass
class TCPFixture:
    server: asyncio.AbstractServer
    host: str
    port: int


async def start_tcp_fixture(
    host: str = "127.0.0.1",
    port: int = 0,
    banner: str = "portsleuth fixture",
) -> TCPFixture:
    banner_bytes = banner.encode("utf-8")

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(banner_bytes + b"\r\n")
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(128), timeout=0.2)
        except TimeoutError:
            pass
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, host, port)
    sockname = server.sockets[0].getsockname()
    return TCPFixture(server=server, host=sockname[0], port=int(sockname[1]))


@asynccontextmanager
async def tcp_fixture(
    host: str = "127.0.0.1",
    port: int = 0,
    banner: str = "portsleuth fixture",
):
    fixture = await start_tcp_fixture(host=host, port=port, banner=banner)
    try:
        yield fixture
    finally:
        fixture.server.close()
        await fixture.server.wait_closed()


async def run_tcp_fixture(host: str, port: int, banner: str) -> None:
    fixture = await start_tcp_fixture(host=host, port=port, banner=banner)
    print(f"TCP fixture listening on {fixture.host}:{fixture.port}")
    async with fixture.server:
        await fixture.server.serve_forever()

