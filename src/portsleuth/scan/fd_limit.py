"""File descriptor limit for portsleuth CLI."""

from __future__ import annotations

import logging
import sys

logger = logging.getLogger("portsleuth")

_RESERVE_FDS = 32
_DEFAULT_SOFT_LIMIT = 512


def soft_fd_limit() -> int:
    if sys.platform == "win32":
        return _DEFAULT_SOFT_LIMIT
    try:
        import resource

        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft <= 0:
            return _DEFAULT_SOFT_LIMIT
        return int(soft)
    except (ImportError, OSError, ValueError):
        return _DEFAULT_SOFT_LIMIT


def cap_concurrency(requested: int, *, targets: int, ports: int) -> int:
    """Cap concurrency so a large scan is less likely to exhaust file descriptors."""
    safe = max(1, soft_fd_limit() - _RESERVE_FDS)
    workload = max(1, targets * ports)
    cap = min(safe, workload)
    if requested > cap:
        logger.warning(
            "concurrency %s exceeds safe limit %s for this workload; using %s",
            requested,
            safe,
            cap,
        )
        return cap
    return requested
