"""Benchmarking for portsleuth CLI."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass

from portsleuth.exceptions import ScanInterrupted
from portsleuth.models import ScanOptions, ScanState, Target, Technique
from portsleuth.scan.connect import scan_many, scan_port_sync
from portsleuth.scan.fd_limit import cap_concurrency


@dataclass
class BenchmarkResult:
    technique: str
    ports: int
    concurrency: int
    timeout: float
    duration_ms: float
    open: int
    closed: int
    filtered: int
    unreachable: int
    permission_denied: int
    unknown: int
    error: int

    @property
    def other(self) -> int:
        return self.unreachable + self.permission_denied + self.unknown + self.error

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["other"] = self.other
        return data


def run_sync_benchmark(targets: list[Target], ports: list[int], timeout: float) -> BenchmarkResult:
    started = time.perf_counter()
    states = [scan_port_sync(target.address, port, timeout) for target in targets for port in ports]
    return _result("sync", len(states), 1, timeout, started, states)


def run_threaded_benchmark(
    targets: list[Target],
    ports: list[int],
    timeout: float,
    max_workers: int,
) -> BenchmarkResult:
    started = time.perf_counter()
    workers = cap_concurrency(max(1, max_workers), targets=len(targets), ports=len(ports))
    states: list[ScanState] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_port_sync, target.address, port, timeout)
            for target in targets
            for port in ports
        ]
        for future in as_completed(futures):
            states.append(future.result())
    return _result("threaded", len(states), workers, timeout, started, states)


async def run_async_benchmark(
    targets: list[Target],
    ports: list[int],
    timeout: float,
    concurrency: int,
    rate_limit: float,
) -> BenchmarkResult:
    started = time.perf_counter()
    options = ScanOptions(
        timeout=timeout,
        concurrency=concurrency,
        rate_limit=rate_limit,
        technique=Technique.TCP_CONNECT,
        probe=False,
    )
    partial = False
    try:
        results = await scan_many(targets, ports, options)
    except ScanInterrupted as exc:
        results = exc.results
        partial = True
    states = [result.state for result in results]
    label = "asyncio (partial)" if partial else "asyncio"
    return _result(label, len(states), concurrency, timeout, started, states)


def _result(
    technique: str,
    port_count: int,
    concurrency: int,
    timeout: float,
    started: float,
    states: list[ScanState],
) -> BenchmarkResult:
    duration_ms = (time.perf_counter() - started) * 1000
    return BenchmarkResult(
        technique=technique,
        ports=port_count,
        concurrency=concurrency,
        timeout=timeout,
        duration_ms=duration_ms,
        open=states.count(ScanState.OPEN),
        closed=states.count(ScanState.CLOSED),
        filtered=states.count(ScanState.FILTERED),
        unreachable=states.count(ScanState.UNREACHABLE),
        permission_denied=states.count(ScanState.PERMISSION_DENIED),
        unknown=states.count(ScanState.UNKNOWN),
        error=states.count(ScanState.ERROR),
    )
