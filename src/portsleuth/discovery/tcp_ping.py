"""TCP ping discovery for portsleuth CLI."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from portsleuth.concurrency.rate_limit import AsyncTokenBucket
from portsleuth.config import DEFAULT_TIMEOUT
from portsleuth.exceptions import DiscoverInterrupted
from portsleuth.models import Target
from portsleuth.scan.classify import is_connection_refused
from portsleuth.scan.fd_limit import cap_concurrency
from portsleuth.targets.sort import address_sort_key

# Ports that are commonly reachable on live hosts even when ICMP echo is filtered.
DEFAULT_PING_PORTS = (80, 443, 22, 445, 3389)


@dataclass
class HostStatus:
    target: str
    address: str
    is_up: bool
    open_port: int | None = None
    latency_ms: float | None = None
    reason: str = "no probed port responded"


async def tcp_ping_host(
    target: Target,
    ports: tuple[int, ...] = DEFAULT_PING_PORTS,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> HostStatus:
    """Treat a host as up if any probed TCP port completes a handshake.

    A refused connection still proves the host is alive (the stack answered),
    so both "open" and "connection refused" count as up. The probed ports run
    concurrently, so a fully-down host only waits one timeout, not one per port.
    """
    probes = await asyncio.gather(*(_probe_port(target, port, timeout) for port in ports))
    alive = [status for status in probes if status is not None]
    if not alive:
        return HostStatus(target=target.label, address=target.address, is_up=False)
    open_ports = [status for status in alive if status.open_port is not None]
    if open_ports:
        return min(open_ports, key=lambda status: status.open_port)
    return alive[0]


async def _probe_port(target: Target, port: int, timeout: float) -> HostStatus | None:
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.address, port), timeout=timeout
        )
    except TimeoutError:
        return None
    except OSError as exc:
        if is_connection_refused(exc):
            return HostStatus(
                target=target.label,
                address=target.address,
                is_up=True,
                open_port=None,
                latency_ms=(loop.time() - started) * 1000,
                reason=f"host replied (connection refused on {port})",
            )
        return None
    latency_ms = (loop.time() - started) * 1000
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return HostStatus(
        target=target.label,
        address=target.address,
        is_up=True,
        open_port=port,
        latency_ms=latency_ms,
        reason=f"open port {port}",
    )


async def tcp_ping_sweep(
    targets: list[Target],
    ports: tuple[int, ...] = DEFAULT_PING_PORTS,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = 100,
    rate_limit: float = 0.0,
) -> list[HostStatus]:
    concurrency = cap_concurrency(max(1, concurrency), targets=len(targets), ports=1)
    semaphore = asyncio.Semaphore(concurrency)
    limiter = AsyncTokenBucket(rate_limit) if rate_limit > 0 else None

    async def worker(target: Target) -> HostStatus:
        async with semaphore:
            if limiter is not None:
                await limiter.wait()
            return await tcp_ping_host(target, ports, timeout=timeout)

    tasks = [asyncio.create_task(worker(target)) for target in targets]
    statuses: list[HostStatus] = []
    try:
        for task in asyncio.as_completed(tasks):
            statuses.append(await task)
    except (KeyboardInterrupt, asyncio.CancelledError):
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        statuses = _dedupe_statuses(statuses)
        statuses.sort(key=lambda item: address_sort_key(item.address))
        raise DiscoverInterrupted(statuses) from None

    statuses.sort(key=lambda item: address_sort_key(item.address))
    return statuses


def _dedupe_statuses(statuses: list[HostStatus]) -> list[HostStatus]:
    seen: set[tuple[str, str]] = set()
    unique: list[HostStatus] = []
    for status in statuses:
        key = (status.target, status.address)
        if key in seen:
            continue
        seen.add(key)
        unique.append(status)
    return unique
