"""Validation for portsleuth CLI."""

from __future__ import annotations


def validate_timeout(value: float, *, name: str = "timeout") -> float:
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return float(value)


def validate_concurrency(value: int) -> int:
    if value < 1:
        raise ValueError("concurrency must be at least 1")
    return int(value)


def validate_rate(value: float) -> float:
    if value < 0:
        raise ValueError("rate must be zero or greater")
    return float(value)


def validate_max_hosts(value: int) -> int:
    if value < 1:
        raise ValueError("max-hosts must be at least 1")
    return int(value)


def validate_scan_tuning(*, timeout: float, concurrency: int, rate: float, max_hosts: int | None = None) -> None:
    validate_timeout(timeout)
    validate_concurrency(concurrency)
    validate_rate(rate)
    if max_hosts is not None:
        validate_max_hosts(max_hosts)


def validate_probe_port(port: int) -> None:
    from portsleuth.targets.ports import validate_port

    validate_port(port)
