"""Capabilities for portsleuth CLI."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import shutil
import socket
import sys
from dataclasses import asdict, dataclass

DEFAULT_LAB_PORTS: tuple[tuple[int, str], ...] = (
    (8080, "WSGI HTTP lab"),
    (9090, "TCP banner lab"),
)


@dataclass
class FixturePortStatus:
    port: int
    label: str
    status: str


@dataclass
class CapabilityReport:
    os: str
    python: str
    is_admin_or_root: bool
    raw_icmp_available: bool
    raw_tcp_socket_creatable: bool
    raw_tcp_syn_likely_supported: bool
    packet_capture_tools: list[str]
    fixture_ports: list[FixturePortStatus]
    default_timeout: float
    default_concurrency: int
    default_rate_limit: float
    tls_cert_fields_available: bool
    notes: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def is_admin_or_root() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _can_create_raw_socket(protocol: int) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
    except OSError:
        return False
    else:
        sock.close()
        return True


def check_lab_fixture_ports(host: str = "127.0.0.1") -> list[FixturePortStatus]:
    statuses: list[FixturePortStatus] = []
    for port, label in DEFAULT_LAB_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, port))
        except OSError as exc:
            if exc.errno in {errno.EADDRINUSE, 10048}:
                statuses.append(FixturePortStatus(port=port, label=label, status="in_use"))
            else:
                statuses.append(FixturePortStatus(port=port, label=label, status=f"error: {exc}"))
        else:
            statuses.append(FixturePortStatus(port=port, label=label, status="available"))
    return statuses


def detect_capabilities(
    default_timeout: float,
    default_concurrency: int,
    default_rate_limit: float,
) -> CapabilityReport:
    system = platform.system()
    notes: list[str] = []
    admin = is_admin_or_root()
    raw_icmp = _can_create_raw_socket(socket.IPPROTO_ICMP)
    raw_tcp = _can_create_raw_socket(socket.IPPROTO_TCP)

    raw_syn_likely = raw_tcp and system == "Linux"
    if system == "Windows":
        notes.append("Native Windows restricts raw TCP behavior; use TCP connect scan as the portable core.")
    if not admin and (not raw_icmp or not raw_tcp):
        notes.append("Raw packet features generally require administrator/root privileges.")
    if system == "Linux" and raw_tcp:
        notes.append("Raw TCP sockets are creatable; SYN scan may be available when run with suitable privileges.")

    tools = [name for name in ("tcpdump", "tshark", "wireshark") if shutil.which(name)]
    tls_fields = _tls_cert_fields_available()
    fixture_ports = check_lab_fixture_ports()
    if not tls_fields:
        notes.append(
            "Install the optional tls extra (pip install -e \".[tls]\") to extract "
            "certificate subject/issuer fields from probe tls --insecure."
        )
    return CapabilityReport(
        os=f"{system} {platform.release()}",
        python=sys.version.split()[0],
        is_admin_or_root=admin,
        raw_icmp_available=raw_icmp,
        raw_tcp_socket_creatable=raw_tcp,
        raw_tcp_syn_likely_supported=raw_syn_likely,
        packet_capture_tools=tools,
        fixture_ports=fixture_ports,
        default_timeout=default_timeout,
        default_concurrency=default_concurrency,
        default_rate_limit=default_rate_limit,
        tls_cert_fields_available=tls_fields,
        notes=notes,
    )


def _tls_cert_fields_available() -> bool:
    try:
        from portsleuth.fingerprint import tls as tls_module

        return bool(tls_module._HAVE_CRYPTOGRAPHY)
    except ImportError:
        return False

