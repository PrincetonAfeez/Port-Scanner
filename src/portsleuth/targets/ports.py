"""Port parsing for portsleuth CLI."""

from __future__ import annotations

import socket

from portsleuth.config import TOP_PORTS


def parse_ports(spec: str | None, top: int | None = None) -> list[int]:
    if top is not None:
        if top < 1:
            raise ValueError("--top must be greater than zero")
        return sorted(TOP_PORTS[:top])
    if not spec:
        return sorted(TOP_PORTS[:100])

    ports: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ValueError(f"invalid port range: {part}") from exc
            if start > end:
                raise ValueError(f"invalid port range: {part}")
            validate_port(start)
            validate_port(end)
            ports.update(range(start, end + 1))
            continue
        if part.isdigit():
            port = int(part)
        else:
            port = _service_to_port(part)
        validate_port(port)
        ports.add(port)

    if not ports:
        raise ValueError("no ports were parsed")
    return sorted(ports)


def _service_to_port(name: str) -> int:
    try:
        return socket.getservbyname(name.lower(), "tcp")
    except OSError as exc:
        raise ValueError(f"unknown service name: {name}") from exc


def validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise ValueError(f"port out of range: {port}")

