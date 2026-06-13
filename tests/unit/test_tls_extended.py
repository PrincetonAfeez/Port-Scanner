"""Unit tests for tls extended module in portsleuth CLI."""

import ssl

import portsleuth.fingerprint.tls as tls_mod
from portsleuth.fingerprint.tls import _format_name, _normalize_cert_datetime, _ssl_error_message, probe_tls


def test_normalize_cert_datetime_passthrough_iso():
    iso = "2027-08-29T21:41:26+00:00"
    assert _normalize_cert_datetime(iso) == iso


def test_format_name_uses_short_rdn():
    name = ((("commonName", "example.com"),),)
    assert _format_name(name) == "CN=example.com"


def test_ssl_error_message_adds_insecure_hint():
    err = ssl.SSLCertVerificationError("bad cert")
    msg = _ssl_error_message(err, verify=True)
    assert "--insecure" in msg


def test_probe_tls_verify_without_hostname_fails_fast():
    result = probe_tls("127.0.0.1", 443, timeout=0.2, verify=True, server_hostname=None)
    assert result.ok is False
    assert "hostname" in (result.error or "")


def test_fields_from_der_malformed_returns_empty(monkeypatch):
    monkeypatch.setattr(tls_mod, "_HAVE_CRYPTOGRAPHY", True)
    assert tls_mod._fields_from_der(b"not-a-cert") == {}
