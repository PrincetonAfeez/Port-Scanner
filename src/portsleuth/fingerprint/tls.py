"""TLS fingerprinting for portsleuth CLI."""

from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

from portsleuth.models import TLSProbeResult

# Map getpeercert()'s long RDN attribute names to the short forms used by
# cryptography's rfc4514_string(), so verified and --insecure output match.
_RDN_SHORT = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "countryName": "C",
    "stateOrProvinceName": "ST",
    "localityName": "L",
    "emailAddress": "emailAddress",
}

try:  # optional: enables certificate field extraction when verification is off
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover - exercised only when the extra is absent
    _HAVE_CRYPTOGRAPHY = False


def probe_tls(
    host: str,
    port: int,
    timeout: float = 2.0,
    server_hostname: str | None = None,
    *,
    verify: bool = True,
    sock: socket.socket | None = None,
    close_sock: bool = False,
) -> TLSProbeResult:
    context = _build_context(verify)
    sni = server_hostname if _valid_sni(server_hostname) else None
    if verify and sni is None:
        return TLSProbeResult(
            ok=False,
            error="certificate verification needs a hostname; pass --server-name or use --insecure",
        )
    owns_socket = sock is None
    raw_sock: socket.socket | None = None
    try:
        raw_sock = sock if sock is not None else socket.create_connection((host, port), timeout=timeout)
        raw_sock.settimeout(timeout)
        with context.wrap_socket(raw_sock, server_hostname=sni) as tls_sock:
            cert = tls_sock.getpeercert()
            der = tls_sock.getpeercert(binary_form=True)
            cipher = tls_sock.cipher()
            fields = _certificate_fields(cert, der)
            return TLSProbeResult(
                ok=True,
                protocol=tls_sock.version(),
                cipher=cipher[0] if cipher else None,
                verified=verify,
                **fields,
            )
    except ssl.SSLError as exc:
        return TLSProbeResult(ok=False, error=_ssl_error_message(exc, verify))
    except OSError as exc:
        return TLSProbeResult(ok=False, error=str(exc))
    finally:
        if raw_sock is not None and (owns_socket or close_sock):
            try:
                raw_sock.close()
            except OSError:
                pass


def _build_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _valid_sni(server_hostname: str | None) -> bool:
    # RFC 6066 forbids IP literals (and empty values) in the SNI extension.
    if not server_hostname:
        return False
    try:
        import ipaddress

        ipaddress.ip_address(server_hostname)
    except ValueError:
        return True
    return False


def _certificate_fields(cert: dict | None, der: bytes | None) -> dict:
    # A verifying handshake populates getpeercert(); an unverified one returns {}.
    if cert:
        return {
            "subject": _format_name(cert.get("subject", ())),
            "issuer": _format_name(cert.get("issuer", ())),
            "san": [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"],
            "not_before": _normalize_cert_datetime(cert.get("notBefore")),
            "not_after": _normalize_cert_datetime(cert.get("notAfter")),
        }
    if der and _HAVE_CRYPTOGRAPHY:
        return _fields_from_der(der)
    return {}


def _normalize_cert_datetime(value: str | None) -> str | None:
    """Convert getpeercert()'s 'Aug 29 21:41:26 2026 GMT' form to ISO 8601.

    Values already in ISO form (the cryptography path) are returned unchanged.
    """
    if not value:
        return value
    text = value.strip()
    for suffix in (" GMT", " UTC"):
        if text.endswith(suffix):
            text = text[: -len(suffix)]
            break
    try:
        parsed = datetime.strptime(text, "%b %d %H:%M:%S %Y")
    except ValueError:
        return value
    return parsed.replace(tzinfo=UTC).isoformat()


def _fields_from_der(der: bytes) -> dict:
    try:
        parsed = x509.load_der_x509_certificate(der, default_backend())
    except Exception:  # pragma: no cover - malformed certificate
        return {}
    try:
        san = list(parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san = []
    not_before = getattr(parsed, "not_valid_before_utc", None) or parsed.not_valid_before
    not_after = getattr(parsed, "not_valid_after_utc", None) or parsed.not_valid_after
    return {
        "subject": parsed.subject.rfc4514_string(),
        "issuer": parsed.issuer.rfc4514_string(),
        "san": san,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
    }


def _ssl_error_message(exc: ssl.SSLError, verify: bool) -> str:
    message = str(exc)
    if verify and isinstance(exc, ssl.SSLCertVerificationError):
        return f"{message} (retry with --insecure for self-signed lab certificates)"
    return message


def _format_name(name: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    parts: list[str] = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{_RDN_SHORT.get(key, key)}={value}")
    return ", ".join(parts)
