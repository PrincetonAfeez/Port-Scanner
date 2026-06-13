"""Integration tests for WSGI probe in portsleuth CLI."""

from portsleuth.fingerprint.http_probe import probe_http
from portsleuth.lab.fixture_wsgiref import wsgi_fixture_thread
from portsleuth.models import ProbeState


def test_wsgi_fixture_responds_to_raw_http_probe():
    with wsgi_fixture_thread() as (host, port):
        result = probe_http(host, port, method="GET", timeout=2.0)
    assert result.state == ProbeState.HTTP_DETECTED
    assert result.status_code == 200
    assert result.headers["x-portsleuth-lab"] == "wsgi"


def test_wsgi_redirect_route_sets_location():
    with wsgi_fixture_thread() as (host, port):
        result = probe_http(host, port, method="GET", path="/redirect", timeout=2.0)
    assert result.status_code == 302
    assert result.location == "/"


def test_wsgi_health_route_returns_ok():
    with wsgi_fixture_thread() as (host, port):
        result = probe_http(host, port, method="GET", path="/health", timeout=2.0)
    assert result.status_code == 200


def test_wsgi_head_returns_no_body():
    import socket

    with wsgi_fixture_thread() as (host, port):
        sock = socket.create_connection((host, port), timeout=2.0)
        sock.sendall(b"HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
    data = b"".join(chunks)
    headers, _, body = data.partition(b"\r\n\r\n")
    assert b"Content-Length" in headers  # length still advertised
    assert body == b""  # but no body on HEAD (RFC 7231)

