"""Unit tests for fd limit module in portsleuth CLI."""

from portsleuth.scan.fd_limit import cap_concurrency, soft_fd_limit

def test_soft_fd_limit_on_windows():
    assert soft_fd_limit() >= 1


def test_cap_concurrency_reduces_when_requested_too_high(monkeypatch):
    monkeypatch.setattr("portsleuth.scan.fd_limit.soft_fd_limit", lambda: 40)
    assert cap_concurrency(1000, targets=1, ports=1000) == 8


def test_cap_concurrency_keeps_requested_when_safe():
    assert cap_concurrency(3, targets=1, ports=3) == 3


def test_cap_concurrency_warns_when_capped(monkeypatch, caplog):
    import logging

    monkeypatch.setattr("portsleuth.scan.fd_limit.soft_fd_limit", lambda: 40)
    with caplog.at_level(logging.WARNING, logger="portsleuth"):
        cap_concurrency(100, targets=10, ports=10)
    assert "safe limit" in caplog.text
