"""UDP fixture for portsleuth CLI."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


@dataclass
class UDPFixture:
    transport: asyncio.DatagramTransport
    host: str
    port: int


class _BannerDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, banner: bytes) -> None:
        self._banner = banner
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.transport is not None:
            self.transport.sendto(self._banner, addr)


async def start_udp_fixture(
    host: str = "127.0.0.1",
    port: int = 0,
    banner: str = "portsleuth udp fixture",
) -> UDPFixture:
    loop = asyncio.get_running_loop()
    banner_bytes = (banner + "\n").encode("utf-8")
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: _BannerDatagramProtocol(banner_bytes),
        local_addr=(host, port),
    )
    sockname = transport.get_extra_info("sockname")
    return UDPFixture(transport=transport, host=sockname[0], port=int(sockname[1]))


async def run_udp_fixture(host: str, port: int, banner: str) -> None:
    fixture = await start_udp_fixture(host=host, port=port, banner=banner)
    print(f"UDP fixture listening on {fixture.host}:{fixture.port}")
    try:
        await asyncio.Event().wait()
    finally:
        fixture.transport.close()
