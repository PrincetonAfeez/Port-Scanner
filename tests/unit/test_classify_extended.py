"""Unit tests for classify extended module in portsleuth CLI."""

import errno

from portsleuth.models import ScanState
from portsleuth.scan.classify import (
    classify_errno,
    classify_os_error,
    errno_code,
    is_connection_refused,
)


def test_errno_code_uses_winerror():
    exc = OSError("win")
    exc.errno = None
    exc.winerror = 10061
    assert errno_code(exc) == 10061


def test_is_connection_refused_variants():
    assert is_connection_refused(ConnectionRefusedError()) is True
    assert is_connection_refused(OSError(errno.ECONNREFUSED, "refused")) is True
    assert is_connection_refused(OSError("other")) is False
    assert is_connection_refused(ValueError("nope")) is False


def test_classify_errno_all_branches():
    assert classify_errno(errno.ECONNREFUSED)[0] == ScanState.CLOSED
    assert classify_errno(errno.EHOSTUNREACH)[0] == ScanState.UNREACHABLE
    assert classify_errno(errno.ETIMEDOUT)[0] == ScanState.FILTERED
    assert classify_errno(99999)[0] == ScanState.UNKNOWN
    assert classify_errno(None)[0] == ScanState.UNKNOWN


def test_classify_os_error_permission_and_unknown():
    state, reason, error = classify_os_error(PermissionError("denied"))
    assert state == ScanState.PERMISSION_DENIED
    state, reason, error = classify_os_error(OSError(99999, "weird"))
    assert state == ScanState.UNKNOWN
    assert error is not None
