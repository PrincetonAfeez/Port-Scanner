"""Unit tests for tls module in portsleuth CLI."""

import socket

import portsleuth.fingerprint.tls as tls
from portsleuth.fingerprint.tls import _certificate_fields, _normalize_cert_datetime, _valid_sni, probe_tls


def test_valid_sni_rejects_ip_literals_and_empty():
    assert _valid_sni("example.com") is True
    assert _valid_sni("127.0.0.1") is False
    assert _valid_sni("::1") is False
    assert _valid_sni(None) is False
    assert _valid_sni("") is False


def test_probe_tls_handles_closed_port_without_raising():
    result = probe_tls("127.0.0.1", _free_port(), timeout=0.5, verify=False)
    assert result.ok is False
    assert result.error


def test_certificate_fields_degrades_without_cryptography(monkeypatch):
    # When the optional extra is absent, the unverified path returns no cert
    # fields rather than crashing (protocol/cipher are still reported by probe_tls).
    monkeypatch.setattr(tls, "_HAVE_CRYPTOGRAPHY", False)
    assert _certificate_fields({}, b"\x30\x82fake-der") == {}


def test_certificate_fields_normalizes_getpeercert_dates():
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Example CA"),),),
        "subjectAltName": (("DNS", "example.com"),),
        "notBefore": "Aug 29 21:41:26 2026 GMT",
        "notAfter": "Aug 29 21:41:26 2027 GMT",
    }
    fields = _certificate_fields(cert, None)
    assert fields["subject"] == "CN=example.com"  # short RDN names
    assert fields["not_after"] == _normalize_cert_datetime("Aug 29 21:41:26 2027 GMT")
    assert fields["not_after"].startswith("2027-08-29T")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
