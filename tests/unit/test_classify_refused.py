"""Unit tests for classify refused module in portsleuth CLI."""

import errno

from portsleuth.scan.classify import is_connection_refused


def test_is_connection_refused_accepts_connection_refused_error():
    assert is_connection_refused(ConnectionRefusedError()) is True


def test_is_connection_refused_accepts_errno():
    exc = OSError(errno.ECONNREFUSED, "refused")
    assert is_connection_refused(exc) is True


def test_is_connection_refused_rejects_timeout():
    assert is_connection_refused(TimeoutError()) is False
