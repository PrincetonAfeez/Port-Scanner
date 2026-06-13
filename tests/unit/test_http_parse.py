"""Unit tests for http parse module in portsleuth CLI."""

from portsleuth.fingerprint.http_parse import parse_http_response
from portsleuth.fingerprint.http_probe import build_http_request


def test_parse_status_and_headers():
    parsed = parse_http_response(
        b"HTTP/1.1 302 Found\r\nServer: lab\r\nLocation: /next\r\n\r\n"
    )
    assert parsed.valid is True
    assert parsed.status_code == 302
    assert parsed.headers["server"] == "lab"
    assert parsed.headers["location"] == "/next"


def test_reject_non_http_response():
    parsed = parse_http_response(b"SSH-2.0-test\r\n")
    assert parsed.valid is False
    assert parsed.error == "missing HTTP status line"


def test_request_is_hand_written_http_bytes():
    request = build_http_request("127.0.0.1", method="HEAD", path="/")
    assert request.startswith(b"HEAD / HTTP/1.1\r\n")
    assert b"Connection: close\r\n" in request


def test_parse_empty_response():
    parsed = parse_http_response(b"")
    assert parsed.valid is False
    assert parsed.error == "empty response"


def test_parse_truncated_status_line():
    parsed = parse_http_response(b"HTTP/1.1\r\n\r\n")
    assert parsed.valid is False
    assert parsed.error == "missing HTTP status line"


def test_parse_non_numeric_status_code():
    parsed = parse_http_response(b"HTTP/1.1 OK Fine\r\n\r\n")
    assert parsed.valid is False
    assert parsed.error == "invalid HTTP status code"


def test_parse_handles_lf_only_line_endings():
    parsed = parse_http_response(b"HTTP/1.0 204 No Content\nServer: lab\n\n")
    assert parsed.valid is True
    assert parsed.status_code == 204
    assert parsed.headers["server"] == "lab"


def test_parse_oversized_response_is_truncated_to_preview():
    body = b"HTTP/1.1 200 OK\r\nServer: lab\r\n\r\n" + b"x" * 100_000
    parsed = parse_http_response(body)
    assert parsed.valid is True
    assert parsed.status_code == 200
    assert len(parsed.raw_preview) <= 240  # preview is bounded regardless of body size

