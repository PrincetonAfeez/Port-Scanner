"""Exceptions for portsleuth CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from portsleuth.models import PortResult


class PortsleuthError(Exception):
    """Base exception for portsleuth."""


class AuthorizationError(PortsleuthError):
    """Raised when a scan is blocked by the authorization gate."""


class TargetResolutionError(PortsleuthError):
    """Raised when a target cannot be resolved."""


class ScanInterrupted(PortsleuthError):
    """Raised when a scan is cancelled but partial results are available."""

    def __init__(self, results: list[PortResult], message: str = "scan interrupted") -> None:
        super().__init__(message)
        self.results = results


class DiscoverInterrupted(PortsleuthError):
    """Raised when host discovery is cancelled but partial statuses are available."""

    def __init__(self, statuses: list[object], message: str = "discovery interrupted") -> None:
        super().__init__(message)
        self.statuses = statuses
