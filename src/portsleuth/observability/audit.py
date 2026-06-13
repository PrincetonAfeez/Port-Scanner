"""Audit trail for portsleuth CLI."""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

from portsleuth.models import ScanOptions, Target

_process_locks: dict[str, threading.Lock] = {}


def _lock_for(path: Path) -> threading.Lock:
    key = str(path.resolve())
    lock = _process_locks.get(key)
    if lock is None:
        lock = threading.Lock()
        _process_locks[key] = lock
    return lock


def write_audit_record(
    path: str,
    *,
    target_expression: str,
    targets: list[Target],
    ports: list[int],
    options: ScanOptions,
    authorized: bool,
    reason: str | None,
    technique: str | None = None,
) -> Path:
    audit_path = Path(path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target_expression": target_expression,
        "resolved_targets": [
            {
                "expression": target.expression,
                "address": target.address,
                "hostname": target.hostname,
                "family": target.family,
            }
            for target in targets
        ],
        "ports": ports,
        "technique": technique or options.technique.value,
        "authorized": authorized,
        "reason": reason,
        "rate_limit": options.rate_limit,
        "concurrency": options.concurrency,
        "timeout": options.timeout,
    }
    if options.probe:
        record["probe"] = True
        record["probe_insecure"] = options.probe_insecure
    line = json.dumps(record, sort_keys=True) + "\n"
    with _lock_for(audit_path):
        with audit_path.open("a", encoding="utf-8") as handle:
            _lock_file(handle)
            try:
                handle.write(line)
                handle.flush()
            finally:
                _unlock_file(handle)
    return audit_path


def _lock_file(handle) -> None:
    if os.name == "nt":
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_file(handle) -> None:
    if os.name == "nt":
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
