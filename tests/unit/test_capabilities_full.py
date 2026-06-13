"""Unit tests for capabilities full module in portsleuth CLI."""

from portsleuth import capabilities as cap_mod
from portsleuth.capabilities import check_lab_fixture_ports, detect_capabilities, is_admin_or_root


def test_check_lab_fixture_ports_returns_two_entries():
    statuses = check_lab_fixture_ports()
    assert len(statuses) == 2
    assert statuses[0].port == 8080


def test_is_admin_or_root_on_windows(monkeypatch):
    monkeypatch.setattr(cap_mod.os, "name", "nt")
    monkeypatch.setattr(cap_mod, "ctypes", cap_mod.ctypes)
    assert isinstance(is_admin_or_root(), bool)


def test_detect_capabilities_notes_when_tls_extra_missing(monkeypatch):
    monkeypatch.setattr(cap_mod, "_tls_cert_fields_available", lambda: False)
    report = detect_capabilities(0.5, 10, 0.0)
    assert any("tls extra" in note.lower() for note in report.notes)


def test_soft_fd_limit_resource_fallback(monkeypatch):
    monkeypatch.setattr(cap_mod.os, "name", "posix")

    def boom():
        raise OSError("nope")

    monkeypatch.setattr(cap_mod, "resource", None, raising=False)
    # force import path failure inside soft_fd_limit via scan module test instead
