# ADR 0004 - Sync vs Threaded vs Async

## Decision

The scanner includes a benchmark command that compares synchronous, threaded, and asyncio TCP connect scans under the same timeout and port set.

## Rationale

Port scanning is I/O-bound. Most time is spent waiting for network responses or timeouts. `asyncio` lets the scanner keep many connection attempts in flight while a semaphore and rate limiter keep the behavior controlled.

## Consequences

The benchmark is useful capstone evidence, not a microbenchmark of Python itself. Results vary by OS, firewall behavior, and target.

To keep the comparison fair, the benchmark runs the asyncio lane with rate
limiting disabled, matching the sync and threaded lanes (which have no pacing).
Measuring a throttled async lane against unthrottled sync/threaded lanes would
understate asyncio and invert the conclusion. Rate limiting remains on by default
for real `scan` runs, where politeness and safety matter more than raw speed.

## Concurrency safety

The async engine is deliberately simple, and the failure modes are bounded:

- **Shared state.** The only mutable shared state is the token bucket's token
  count, guarded by an `asyncio.Lock`. Per-port `PortResult`s are produced
  independently and collected once via `as_completed`; the result list is sorted
  a single time after all tasks finish, so there is no concurrent mutation.
- **Deadlock.** There is no nested lock acquisition and no lock ordering to get
  wrong. The token bucket releases its lock *before* awaiting `asyncio.sleep`, so
  a waiting task never holds the lock while suspended. A bounded `Semaphore`
  caps in-flight sockets; acquiring it cannot deadlock because every holder
  releases it in a `finally`/`async with` scope.
- **Starvation.** Throughput is bounded by the semaphore and the token bucket.
  When several tasks wait on the bucket they may wake together (a benign
  thundering-herd); one wins the token and the rest re-queue. This is acceptable
  for an I/O-bound scan and is not unfair in practice, but it is the reason the
  bucket is not presented as a strict-FIFO scheduler.
- **Cancellation.** `Ctrl-C` (or task cancellation) propagates as
  `CancelledError`; `scan_many` cancels the remaining tasks and drains them with
  `gather(..., return_exceptions=True)` before re-raising, so the event loop
  shuts down without "task was destroyed but it is pending" warnings. The CLI
  maps the interrupt to exit code 130. A last-resort `except Exception` in
  `scan_port` converts an unexpected per-port failure into a `ScanState.ERROR`
  result (surfaced as exit code 7) rather than aborting the whole scan;
  `CancelledError` is a `BaseException` and is intentionally *not* caught there.

A production scanner would likely need a more sophisticated scheduler (fair
queueing, per-host concurrency caps); that is out of scope for the portable core.

