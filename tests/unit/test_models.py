"""Unit tests for models module in portsleuth CLI."""

from portsleuth.models import (
    AuthorizationSummary,
    HTTPProbeResult,
    PortResult,
    ProbeState,
    ScanOptions,
    ScanReport,
    ScanState,
    Target,
    TLSProbeResult,
)


def test_target_label_prefers_hostname():
    target = Target(expression="127.0.0.1", address="127.0.0.1", hostname="localhost")
    assert target.label == "localhost"


def test_http_probe_result_to_dict_serializes_state():
    result = HTTPProbeResult(state=ProbeState.HTTP_DETECTED, method="GET", path="/", http_version="HTTP/1.1")
    data = result.to_dict()
    assert data["state"] == "http_detected"
    assert data["http_version"] == "HTTP/1.1"


def test_port_result_to_dict_includes_nested_probes():
    result = PortResult(
        target="127.0.0.1",
        address="127.0.0.1",
        port=443,
        state=ScanState.OPEN,
        http=HTTPProbeResult(state=ProbeState.NON_HTTP, method="HEAD", path="/"),
        tls=TLSProbeResult(ok=True, protocol="TLSv1.2"),
    )
    data = result.to_dict()
    assert data["technique"] == "connect"
    assert data["http"]["method"] == "HEAD"
    assert data["tls"]["protocol"] == "TLSv1.2"


def test_scan_report_to_dict_includes_authorization_summary():
    report = ScanReport(
        target_expression="127.0.0.1",
        ports=[80],
        options=ScanOptions(timeout=1.0, concurrency=1, rate_limit=0.0),
        authorization_summary=AuthorizationSummary(
            authorized=True,
            reason="lab",
            requires_audit=True,
            categories=["private"],
        ),
    )
    report.finish(10.0)
    data = report.to_dict()
    assert data["authorization_summary"]["reason"] == "lab"
    assert data["options"]["probe_insecure"] is False
