"""Unit tests for http probe wsgi module in portsleuth CLI."""

import asyncio

from portsleuth.fingerprint.http_probe import probe_http_async
from portsleuth.lab.fixture_wsgiref import wsgi_application, wsgi_fixture_thread
from portsleuth.models import ProbeState


def test_probe_http_async_on_wsgi_fixture():
    async def run():
        with wsgi_fixture_thread() as (host, port):
            result = await probe_http_async(host, port, path="/health", timeout=1.0)
        assert result.state == ProbeState.HTTP_DETECTED
        assert result.status_code == 200
        assert result.http_version is not None

    asyncio.run(run())


def test_wsgi_application_routes():
    captured = {}

    def start_response(status, headers):
        captured["status"] = status
        captured["headers"] = dict(headers)
        return lambda data: None

    environ = {
        "PATH_INFO": "/redirect",
        "REQUEST_METHOD": "GET",
    }
    body = list(wsgi_application(environ, start_response))
    assert captured["status"] == "302 Found"
    assert any(h[0] == "Location" for h in captured["headers"].items() if False or True)

    captured.clear()
    environ = {"PATH_INFO": "/headers", "REQUEST_METHOD": "GET", "HTTP_USER_AGENT": "test", "HTTP_HOST": "localhost"}
    list(wsgi_application(environ, start_response))
    assert captured["status"] == "200 OK"

    captured.clear()
    environ = {"PATH_INFO": "/", "REQUEST_METHOD": "HEAD"}
    body = list(wsgi_application(environ, start_response))
    assert body == [b""]
