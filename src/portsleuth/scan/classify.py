"""Classification for portsleuth CLI."""

from __future__ import annotations

import errno

from portsleuth.models import ScanState

REFUSED_ERRNOS = {
    errno.ECONNREFUSED,
    getattr(errno, "WSAECONNREFUSED", 10061),
    10061,
    61,
}
UNREACHABLE_ERRNOS = {
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    getattr(errno, "WSAENETUNREACH", 10051),
    getattr(errno, "WSAEHOSTUNREACH", 10065),
    10051,
    10065,
}
TIMEOUT_ERRNOS = {
    errno.ETIMEDOUT,
    getattr(errno, "WSAETIMEDOUT", 10060),
    10060,
}


def errno_code(exc: OSError) -> int | None:
    return exc.errno or getattr(exc, "winerror", None)


def is_connection_refused(exc: BaseException) -> bool:
    if isinstance(exc, ConnectionRefusedError):
        return True
    if isinstance(exc, OSError):
        return errno_code(exc) in REFUSED_ERRNOS
    return False


def classify_errno(code: int | None) -> tuple[ScanState, str]:
    if code in REFUSED_ERRNOS:
        return ScanState.CLOSED, "connection refused"
    if code in UNREACHABLE_ERRNOS:
        return ScanState.UNREACHABLE, "network or host unreachable"
    if code in TIMEOUT_ERRNOS:
        return ScanState.FILTERED, "connection timed out"
    reason = f"socket error {code}" if code is not None else "socket error"
    return ScanState.UNKNOWN, reason


def classify_os_error(exc: OSError) -> tuple[ScanState, str, str | None]:
    if isinstance(exc, PermissionError):
        message = str(exc)
        return ScanState.PERMISSION_DENIED, message, message
    state, reason = classify_errno(errno_code(exc))
    error = str(exc) if state in {ScanState.UNKNOWN, ScanState.ERROR} else None
    return state, reason, error
