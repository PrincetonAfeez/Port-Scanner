"""Service guessing for portsleuth CLI."""

from __future__ import annotations

import socket

from portsleuth.config import COMMON_PORTS


def guess_service(port: int) -> str | None:
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def confidence_for_service(port: int, service: str | None) -> str | None:
    if service is None:
        return None
    if port in COMMON_PORTS:
        return "medium"
    return "low"

