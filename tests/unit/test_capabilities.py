"""Unit tests for capabilities module in portsleuth CLI."""

from portsleuth.capabilities import detect_capabilities


def test_detect_capabilities_reports_core_fields():
    report = detect_capabilities(default_timeout=0.75, default_concurrency=100, default_rate_limit=200.0)
    assert isinstance(report.os, str) and report.os
    assert isinstance(report.is_admin_or_root, bool)
    assert isinstance(report.raw_icmp_available, bool)
    assert isinstance(report.raw_tcp_socket_creatable, bool)
    assert report.default_timeout == 0.75
    # raw SYN is only plausibly supported on Linux with a creatable raw TCP socket.
    if report.os.split()[0] != "Linux":
        assert report.raw_tcp_syn_likely_supported is False


def test_detect_capabilities_serializes_to_dict():
    report = detect_capabilities(default_timeout=0.5, default_concurrency=10, default_rate_limit=0.0)
    data = report.to_dict()
    for key in ("os", "python", "raw_icmp_available", "raw_tcp_syn_likely_supported", "tls_cert_fields_available", "notes", "fixture_ports"):
        assert key in data
    assert len(data["fixture_ports"]) == 2
