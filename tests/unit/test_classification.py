"""Unit tests for classification module in portsleuth CLI."""

import errno
import time

from portsleuth.models import ScanState, Target
from portsleuth.scan.classify import errno_code
from portsleuth.scan.connect import _result_from_os_error


def _target() -> Target:
    return Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)


def test_refused_errno_maps_to_closed():
    exc = OSError(errno.ECONNREFUSED, "refused")
    result = _result_from_os_error(_target(), 80, exc, time.perf_counter(), "http")
    assert result.state == ScanState.CLOSED
    assert result.error is None


def test_unreachable_errno_maps_to_unreachable():
    exc = OSError(errno.EHOSTUNREACH, "no route to host")
    result = _result_from_os_error(_target(), 80, exc, time.perf_counter(), None)
    assert result.state == ScanState.UNREACHABLE


def test_unknown_errno_maps_to_unknown_and_keeps_error():
    exc = OSError(4242, "unexpected")
    result = _result_from_os_error(_target(), 80, exc, time.perf_counter(), None)
    assert result.state == ScanState.UNKNOWN
    assert result.error is not None


def test_errno_falls_back_to_winerror():
    exc = OSError()
    exc.winerror = 10061
    assert errno_code(exc) == 10061


def test_address_sort_key_is_numeric_not_lexical():
    from portsleuth.targets.sort import address_sort_key

    addresses = ["127.0.0.10", "127.0.0.2", "127.0.0.1"]
    assert sorted(addresses, key=address_sort_key) == ["127.0.0.1", "127.0.0.2", "127.0.0.10"]
