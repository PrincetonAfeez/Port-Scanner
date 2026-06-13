"""TCP connect scanning for portsleuth CLI."""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from collections.abc import Awaitable, Callable

from portsleuth.concurrency.rate_limit import AsyncTokenBucket
from portsleuth.config import HTTP_LIKE_PORTS, HTTPS_LIKE_PORTS
from portsleuth.exceptions import ScanInterrupted
from portsleuth.fingerprint.banner import read_banner_from_stream
from portsleuth.fingerprint.http_probe import probe_http_async_on_stream
from portsleuth.fingerprint.services import confidence_for_service, guess_service
from portsleuth.fingerprint.tls import _valid_sni, probe_tls
from portsleuth.models import PortResult, ProbeState, ScanOptions, ScanState, Target, Technique
from portsleuth.scan.classify import classify_os_error
from portsleuth.scan.fd_limit import cap_concurrency
from portsleuth.targets.sort import address_sort_key

logger = logging.getLogger("portsleuth")

ProgressCallback = Callable[[PortResult], Awaitable[None] | None]


async def scan_many(
    targets: list[Target],
    ports: list[int],
    options: ScanOptions,
    progress: ProgressCallback | None = None,
) -> list[PortResult]:
    if options.technique != Technique.TCP_CONNECT:
        return [
            PortResult(
                target=target.label,
                address=target.address,
                port=port,
                state=ScanState.UNSUPPORTED,
                technique=options.technique,
                service=guess_service(port),
                service_confidence=confidence_for_service(port, guess_service(port)),
                reason="only TCP connect scan is implemented in the portable core",
            )
            for target in targets
            for port in ports
        ]

    concurrency = cap_concurrency(
        max(1, options.concurrency),
        targets=len(targets),
        ports=len(ports),
    )
    semaphore = asyncio.Semaphore(concurrency)
    limiter = AsyncTokenBucket(options.rate_limit) if options.rate_limit > 0 else None

    async def worker(target: Target, port: int) -> PortResult:
        async with semaphore:
            if limiter is not None:
                await limiter.wait()
            result = await scan_port(
                target,
                port,
                timeout=options.timeout,
                probe=options.probe,
                probe_insecure=options.probe_insecure,
            )
            if progress is not None:
                maybe_awaitable = progress(result)
                if maybe_awaitable is not None:
                    await maybe_awaitable
            return result

    tasks = [asyncio.create_task(worker(target, port)) for target in targets for port in ports]
    results: list[PortResult] = []
    try:
        for task in asyncio.as_completed(tasks):
            results.append(await task)
    except (KeyboardInterrupt, asyncio.CancelledError):
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        results = _dedupe_results(results)
        results.sort(key=lambda item: (address_sort_key(item.address), item.target, item.port))
        raise ScanInterrupted(results) from None

    results.sort(key=lambda item: (address_sort_key(item.address), item.target, item.port))
    return results


def _dedupe_results(results: list[PortResult]) -> list[PortResult]:
    seen: set[tuple[str, str, int]] = set()
    unique: list[PortResult] = []
    for result in results:
        key = (result.target, result.address, result.port)
        if key in seen:
            continue
        seen.add(key)
        unique.append(result)
    return unique


def build_dns_error_results(
    failures: list[tuple[str, str]],
    ports: list[int],
    technique: Technique,
) -> list[PortResult]:
    if not failures or not ports:
        return []
    port = ports[0]
    return [
        PortResult(
            target=expression,
            address=expression,
            port=port,
            state=ScanState.DNS_ERROR,
            technique=technique,
            reason=error,
            error=error,
        )
        for expression, error in failures
    ]


async def scan_port(
    target: Target,
    port: int,
    *,
    timeout: float,
    probe: bool = False,
    probe_insecure: bool = False,
) -> PortResult:
    started = time.perf_counter()
    service = guess_service(port)
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target.address, port), timeout=timeout)
        latency_ms = (time.perf_counter() - started) * 1000
        result = PortResult(
            target=target.label,
            address=target.address,
            port=port,
            state=ScanState.OPEN,
            service=service,
            service_confidence=confidence_for_service(port, service),
            latency_ms=latency_ms,
            reason="TCP connection succeeded",
        )
        if probe:
            await _attach_probe(
                result,
                target,
                timeout=timeout,
                reader=reader,
                writer=writer,
                probe_insecure=probe_insecure,
            )
        return result
    except TimeoutError:
        return _result_from_failure(target, port, ScanState.FILTERED, "connection timed out", started, service)
    except PermissionError as exc:
        return _result_from_failure(target, port, ScanState.PERMISSION_DENIED, str(exc), started, service, error=str(exc))
    except OSError as exc:
        return _result_from_os_error(target, port, exc, started, service)
    except Exception as exc:  # noqa: BLE001 - last-resort guard so one bad port can't abort the scan
        return _result_from_failure(target, port, ScanState.ERROR, f"unexpected error: {exc}", started, service, error=str(exc))
    finally:
        if writer is not None and not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


def scan_port_sync(host: str, port: int, timeout: float) -> ScanState:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return ScanState.OPEN
    except TimeoutError:
        return ScanState.FILTERED
    except PermissionError:
        return ScanState.PERMISSION_DENIED
    except OSError as exc:
        state, _reason, _error = classify_os_error(exc)
        return state
    except Exception:  # noqa: BLE001 - keep benchmark lanes from aborting on one bad port
        return ScanState.ERROR


async def _attach_probe(
    result: PortResult,
    target: Target,
    *,
    timeout: float,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    probe_insecure: bool,
) -> None:
    host_header = target.hostname or target.address
    if result.port in HTTP_LIKE_PORTS:
        http = await probe_http_async_on_stream(
            reader,
            writer,
            result.port,
            timeout=max(timeout, 1.0),
            host_header=host_header,
        )
        result.http = http
        if http.state == ProbeState.HTTP_DETECTED:
            result.service_confidence = "high"
        elif http.state != ProbeState.POSSIBLE_HTTPS:
            banner = _banner_from_http_fallback(http)
            if not banner:
                banner = await read_banner_from_stream(reader, timeout=min(timeout, 0.75))
            if banner:
                result.banner = banner
                result.http = None
                result.service_confidence = "high"
    elif result.port in HTTPS_LIKE_PORTS:
        verify = _tls_verify_for_probe(target, probe_insecure=probe_insecure, port=result.port)
        sock = writer.get_extra_info("socket")
        if sock is None:
            result.tls = await asyncio.to_thread(
                probe_tls,
                result.address,
                result.port,
                max(timeout, 2.0),
                target.hostname,
                verify=verify,
            )
        else:
            dup = sock.dup()
            try:
                result.tls = await asyncio.to_thread(
                    probe_tls,
                    result.address,
                    result.port,
                    max(timeout, 2.0),
                    target.hostname,
                    verify=verify,
                    sock=dup,
                    close_sock=True,
                )
            finally:
                if result.tls is None:
                    try:
                        dup.close()
                    except OSError:
                        pass
        if result.tls is not None and result.tls.ok:
            result.service_confidence = "high"
    else:
        result.banner = await read_banner_from_stream(reader, timeout=min(timeout, 0.75))
        if result.banner:
            result.service_confidence = "high"


def _tls_verify_for_probe(target: Target, *, probe_insecure: bool, port: int) -> bool:
    if probe_insecure:
        return False
    if target.hostname and _valid_sni(target.hostname):
        return True
    logger.info(
        "TLS probe on %s:%s skipping certificate verification (no hostname for SNI)",
        target.address,
        port,
    )
    return False


def _banner_from_http_fallback(http) -> str | None:
    preview = (http.raw_preview or "").strip()
    if not preview or preview.startswith("HTTP/"):
        return None
    return preview[:512]


def _result_from_os_error(
    target: Target,
    port: int,
    exc: OSError,
    started: float,
    service: str | None,
) -> PortResult:
    state, reason, error = classify_os_error(exc)
    return PortResult(
        target=target.label,
        address=target.address,
        port=port,
        state=state,
        service=service,
        service_confidence=confidence_for_service(port, service),
        latency_ms=(time.perf_counter() - started) * 1000,
        reason=reason,
        error=error,
    )


def _result_from_failure(
    target: Target,
    port: int,
    state: ScanState,
    reason: str,
    started: float,
    service: str | None,
    error: str | None = None,
) -> PortResult:
    return PortResult(
        target=target.label,
        address=target.address,
        port=port,
        state=state,
        service=service,
        service_confidence=confidence_for_service(port, service),
        latency_ms=(time.perf_counter() - started) * 1000,
        reason=reason,
        error=error,
    )
