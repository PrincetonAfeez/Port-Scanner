"""Unit tests for banner and HTTP probe modules in portsleuth CLI."""

import asyncio
import socket

from portsleuth.fingerprint.banner import grab_banner_async, grab_banner_sync, read_banner_from_stream
from portsleuth.fingerprint.http_probe import build_http_request, probe_http
from portsleuth.lab.fixture_tcp import tcp_fixture
from portsleuth.models import ProbeState


def test_build_http_request_brackets_ipv6_literal():
    request = build_http_request("2001:db8::1", method="GET", path="/health")
    text = request.decode("ascii")
    assert "Host: [2001:db8::1]" in text
    assert "GET /health HTTP/1.1" in text


def test_probe_http_on_fixture():
    async def run():
        async with tcp_fixture(banner="HTTP/1.0 200 OK\r\n\r\n") as fixture:
            result = probe_http(fixture.host, fixture.port, timeout=0.5)
        assert result.state in {
        ProbeState.HTTP_DETECTED,
        ProbeState.NON_HTTP,
        ProbeState.MALFORMED_HTTP,
        ProbeState.NO_RESPONSE,
    }

    asyncio.run(run())


def test_grab_banner_sync_and_async():
    async def run():
        async with tcp_fixture(banner="SSH-2.0-test") as fixture:
            banner = await grab_banner_async(fixture.host, fixture.port, timeout=0.5)
            assert banner == "SSH-2.0-test"

    asyncio.run(run())

    async def run_stream():
        reader = asyncio.StreamReader()
        reader.feed_data(b"line1\r\n")
        reader.feed_eof()
        banner = await read_banner_from_stream(reader, timeout=0.2)
        assert banner == "line1"

    asyncio.run(run_stream())


def test_grab_banner_sync_on_closed_port():
    port = _free_port()
    assert grab_banner_sync("127.0.0.1", port, timeout=0.2) is None


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
