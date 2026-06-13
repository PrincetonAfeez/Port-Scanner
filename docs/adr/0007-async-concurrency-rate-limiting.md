# ADR 0007 — Async Concurrency and Rate Limiting

## Status

Accepted

## Context

portsleuth scans many target/port pairs. A fully sequential scanner would be simple but slow. An unbounded concurrent scanner could exhaust file descriptors, overload the local machine, or generate traffic too quickly for a safe educational tool.

The portable scan engine lives in `src/portsleuth/scan/connect.py`. Benchmark comparison of sync, threaded, and async lanes is documented separately in [ADR 0004](0004-sync-threaded-async.md).

## Decision

Use asyncio for the TCP connect scan engine.

The scanner limits concurrency with an `asyncio.Semaphore` and applies an optional token-bucket rate limiter (`AsyncTokenBucket` in `src/portsleuth/concurrency/rate_limit.py`) before connection attempts. `cap_concurrency()` in `src/portsleuth/scan/fd_limit.py` further lowers the effective semaphore limit when the requested `--concurrency` would exceed a safe file-descriptor budget for the workload.

Results are collected from `asyncio.as_completed`, then sorted before output. On cancellation, outstanding tasks are cancelled, partial results are gathered, deduplicated, sorted, and returned through a typed `ScanInterrupted` exception.

## Risks Considered

### File descriptor exhaustion

**Risk:** Too many simultaneous sockets can exhaust OS file descriptors.

**Mitigation:** Concurrency is capped with `cap_concurrency()` before creating scan workers, and user-facing `--concurrency` is validated in the CLI.

### Starvation

**Risk:** A very high concurrency setting or slow targets could delay some tasks.

**Mitigation:** The semaphore bounds active work and `asyncio.as_completed` collects completed tasks without waiting for original ordering. Rate limiting is optional and explicit.

### Deadlock

**Risk:** Improper shared locks could deadlock the scan path.

**Mitigation:** The scan engine avoids shared mutable locks in the hot path. The token bucket uses a single `asyncio.Lock` and releases it before awaiting `asyncio.sleep`. Audit logging is performed after scanning, not inside each scan worker.

### Cancellation loss

**Risk:** Interrupting a scan could lose all completed work.

**Mitigation:** Cancellation cancels pending tasks, gathers finished work, deduplicates partial results, sorts them, and emits partial output via `ScanInterrupted`.

## Consequences

This design keeps the scanner portable, safe for local educational use, and fast enough for loopback and lab scans. It does not attempt stealth scanning, packet spoofing, or production distributed scanning.
