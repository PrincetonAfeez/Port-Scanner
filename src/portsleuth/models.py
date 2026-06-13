"""Models for portsleuth CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class ScanState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"
    UNREACHABLE = "unreachable"
    # Reserved: DNS failures currently raise TargetResolutionError before scanning.
    DNS_ERROR = "dns_error"
    PERMISSION_DENIED = "permission_denied"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    # Reserved for the UDP scanner (not yet implemented in the portable core).
    OPEN_FILTERED = "open_filtered"


class ProbeState(str, Enum):
    HTTP_DETECTED = "http_detected"
    POSSIBLE_HTTPS = "possible_https"
    NON_HTTP = "non_http"
    NO_RESPONSE = "no_response"
    MALFORMED_HTTP = "malformed_http"
    ERROR = "error"


class Technique(str, Enum):
    TCP_CONNECT = "connect"
    TCP_SYN = "syn"
    UDP = "udp"


# Results in these states produce output but exit with code 7 (partial).
PARTIAL_EXIT_STATES = frozenset(
    {
        ScanState.ERROR,
        ScanState.DNS_ERROR,
        ScanState.PERMISSION_DENIED,
        ScanState.UNKNOWN,
        ScanState.UNREACHABLE,
    }
)


@dataclass(frozen=True)
class Target:
    expression: str
    address: str
    hostname: str | None = None
    family: str = "IPv4"
    is_loopback: bool = False
    is_private: bool = False

    @property
    def label(self) -> str:
        return self.hostname or self.expression


@dataclass(frozen=True)
class AuthorizationSummary:
    authorized: bool
    reason: str | None
    requires_audit: bool
    categories: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorized": self.authorized,
            "reason": self.reason,
            "requires_audit": self.requires_audit,
            "categories": self.categories,
        }


@dataclass
class HTTPProbeResult:
    state: ProbeState
    method: str
    path: str
    http_version: str | None = None
    status_code: int | None = None
    reason: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    server: str | None = None
    location: str | None = None
    raw_preview: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


@dataclass
class TLSProbeResult:
    ok: bool
    protocol: str | None = None
    cipher: str | None = None
    subject: str | None = None
    issuer: str | None = None
    san: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    verified: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortResult:
    target: str
    address: str
    port: int
    state: ScanState
    technique: Technique = Technique.TCP_CONNECT
    service: str | None = None
    service_confidence: str | None = None
    latency_ms: float | None = None
    reason: str | None = None
    banner: str | None = None
    http: HTTPProbeResult | None = None
    tls: TLSProbeResult | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        data["technique"] = self.technique.value
        if self.http is not None:
            data["http"] = self.http.to_dict()
        if self.tls is not None:
            data["tls"] = self.tls.to_dict()
        return data


@dataclass
class ScanOptions:
    timeout: float
    concurrency: int
    rate_limit: float
    technique: Technique = Technique.TCP_CONNECT
    probe: bool = False
    probe_insecure: bool = False


@dataclass
class ScanReport:
    target_expression: str
    ports: list[int]
    options: ScanOptions
    results: list[PortResult] = field(default_factory=list)
    authorization_summary: AuthorizationSummary | None = None
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    finished_at: str | None = None
    duration_ms: float | None = None

    def finish(self, duration_ms: float) -> None:
        self.finished_at = datetime.now(UTC).isoformat()
        self.duration_ms = duration_ms

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target_expression": self.target_expression,
            "ports": self.ports,
            "options": {
                "timeout": self.options.timeout,
                "concurrency": self.options.concurrency,
                "rate_limit": self.options.rate_limit,
                "technique": self.options.technique.value,
                "probe": self.options.probe,
                "probe_insecure": self.options.probe_insecure,
            },
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "results": [result.to_dict() for result in self.results],
        }
        if self.authorization_summary is not None:
            payload["authorization_summary"] = self.authorization_summary.to_dict()
        return payload

