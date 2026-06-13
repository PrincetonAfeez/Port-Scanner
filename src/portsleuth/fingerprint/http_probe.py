"""HTTP probing for portsleuth CLI."""

from __future__ import annotations

import asyncio
import socket

from portsleuth.config import HTTPS_LIKE_PORTS, USER_AGENT
from portsleuth.fingerprint.http_parse import parse_http_response
from portsleuth.models import HTTPProbeResult, ProbeState


def build_http_request(host: str, method: str = "HEAD", path: str = "/") -> bytes:
    target_path = path if path.startswith("/") else f"/{path}"
    host_header = f"[{host}]" if ":" in host and not host.startswith("[") else host
    request = (
        f"{method.upper()} {target_path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return request.encode("ascii")


async def probe_http_async(
    host: str,
    port: int,
    *,
    path: str = "/",
    method: str = "HEAD",
    timeout: float = 1.0,
    host_header: str | None = None,
) -> HTTPProbeResult:
    method = method.upper()
    header = host_header or host
    result = await _probe_once_async(host, port, path=path, method=method, timeout=timeout, host_header=header)
    if result.state == ProbeState.HTTP_DETECTED or method != "HEAD":
        return result
    if result.state in {ProbeState.NO_RESPONSE, ProbeState.MALFORMED_HTTP}:
        fallback = await _probe_once_async(host, port, path=path, method="GET", timeout=timeout, host_header=header)
        if fallback.state == ProbeState.HTTP_DETECTED:
            return fallback
    return result


def probe_http(
    host: str,
    port: int,
    *,
    path: str = "/",
    method: str = "HEAD",
    timeout: float = 1.0,
    host_header: str | None = None,
) -> HTTPProbeResult:
    method = method.upper()
    header = host_header or host
    result = _probe_once(host, port, path=path, method=method, timeout=timeout, host_header=header)
    if result.state == ProbeState.HTTP_DETECTED or method != "HEAD":
        return result
    if result.state in {ProbeState.NO_RESPONSE, ProbeState.MALFORMED_HTTP}:
        fallback = _probe_once(host, port, path=path, method="GET", timeout=timeout, host_header=header)
        if fallback.state == ProbeState.HTTP_DETECTED:
            return fallback
    return result


async def probe_http_async_on_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
    *,
    path: str = "/",
    method: str = "HEAD",
    timeout: float = 1.0,
    host_header: str,
) -> HTTPProbeResult:
    method = method.upper()
    result = await _probe_stream_once(
        reader,
        writer,
        port=port,
        path=path,
        method=method,
        timeout=timeout,
        host_header=host_header,
    )
    if result.state == ProbeState.HTTP_DETECTED or method != "HEAD":
        return result
    return result


async def _probe_once_async(
    host: str,
    port: int,
    *,
    path: str,
    method: str,
    timeout: float,
    host_header: str,
) -> HTTPProbeResult:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except TimeoutError:
        return _no_response(method, path, port)
    except OSError as exc:
        return HTTPProbeResult(state=ProbeState.ERROR, method=method, path=path, error=str(exc))

    try:
        return await _probe_stream_once(
            reader,
            writer,
            port=port,
            path=path,
            method=method,
            timeout=timeout,
            host_header=host_header,
        )
    finally:
        writer.close()
        await writer.wait_closed()


async def _probe_stream_once(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    port: int,
    path: str,
    method: str,
    timeout: float,
    host_header: str,
) -> HTTPProbeResult:
    try:
        writer.write(build_http_request(host_header, method=method, path=path))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        chunks: list[bytes] = []
        total = 0
        while total < 8192:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
    except TimeoutError:
        return _no_response(method, path, port)
    except OSError as exc:
        return HTTPProbeResult(state=ProbeState.ERROR, method=method, path=path, error=str(exc))

    return _result_from_response(data, method=method, path=path, port=port)


def _probe_once(
    host: str,
    port: int,
    *,
    path: str,
    method: str,
    timeout: float,
    host_header: str,
) -> HTTPProbeResult:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(build_http_request(host_header, method=method, path=path))
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except TimeoutError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(item) for item in chunks) >= 8192:
                    break
            data = b"".join(chunks)
    except TimeoutError:
        return _no_response(method, path, port)
    except OSError as exc:
        return HTTPProbeResult(state=ProbeState.ERROR, method=method, path=path, error=str(exc))

    return _result_from_response(data, method=method, path=path, port=port)


def _result_from_response(data: bytes, *, method: str, path: str, port: int) -> HTTPProbeResult:
    parsed = parse_http_response(data)
    if not data:
        return _no_response(method, path, port)
    if parsed.valid:
        return HTTPProbeResult(
            state=ProbeState.HTTP_DETECTED,
            method=method,
            path=path,
            http_version=parsed.http_version,
            status_code=parsed.status_code,
            reason=parsed.reason,
            headers=parsed.headers,
            server=parsed.headers.get("server"),
            location=parsed.headers.get("location"),
            raw_preview=parsed.raw_preview,
        )
    if port in HTTPS_LIKE_PORTS:
        return HTTPProbeResult(
            state=ProbeState.POSSIBLE_HTTPS,
            method=method,
            path=path,
            raw_preview=parsed.raw_preview,
            error=parsed.error,
        )
    return HTTPProbeResult(
        state=ProbeState.NON_HTTP if data else ProbeState.NO_RESPONSE,
        method=method,
        path=path,
        raw_preview=parsed.raw_preview,
        error=parsed.error,
    )


def _no_response(method: str, path: str, port: int) -> HTTPProbeResult:
    state = ProbeState.POSSIBLE_HTTPS if port in HTTPS_LIKE_PORTS else ProbeState.NO_RESPONSE
    return HTTPProbeResult(state=state, method=method, path=path)
