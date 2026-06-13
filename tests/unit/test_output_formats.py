"""Unit tests for output formats module in portsleuth CLI."""

import json

from portsleuth.capabilities import CapabilityReport, FixturePortStatus
from portsleuth.cli.output import (
    format_banner_probe_batch,
    format_benchmarks,
    format_capabilities,
    format_discovery,
    format_http_probe,
    format_http_probe_batch,
    format_report,
    format_results_table,
    format_saved_report,
    format_tls_probe,
    format_tls_probe_batch,
)
from portsleuth.concurrency.benchmark import BenchmarkResult
from portsleuth.discovery.tcp_ping import HostStatus
from portsleuth.models import (
    AuthorizationSummary,
    HTTPProbeResult,
    PortResult,
    ProbeState,
    ScanOptions,
    ScanReport,
    ScanState,
    Technique,
    TLSProbeResult,
)


def _capability_report() -> CapabilityReport:
    return CapabilityReport(
        os="TestOS 1.0",
        python="3.12.0",
        is_admin_or_root=False,
        raw_icmp_available=False,
        raw_tcp_socket_creatable=False,
        raw_tcp_syn_likely_supported=False,
        packet_capture_tools=["tcpdump"],
        fixture_ports=[
            FixturePortStatus(port=8080, label="WSGI", status="available"),
            FixturePortStatus(port=9090, label="TCP", status="in_use"),
        ],
        default_timeout=0.75,
        default_concurrency=100,
        default_rate_limit=200.0,
        tls_cert_fields_available=True,
        notes=["note one"],
    )


def test_format_capabilities_table_and_json():
    report = _capability_report()
    table = format_capabilities(report, "table")
    assert "Lab fixture ports" in table
    assert "8080" in table
    data = json.loads(format_capabilities(report, "json"))
    assert data["fixture_ports"][0]["status"] == "available"


def test_format_discovery_all_formats():
    statuses = [
        HostStatus(
            target="host",
            address="127.0.0.1",
            is_up=True,
            open_port=80,
            latency_ms=1.5,
            reason="open port 80",
        ),
        HostStatus(target="down", address="10.0.0.1", is_up=False),
    ]
    assert "up" in format_discovery(statuses, "table")
    assert "down" in format_discovery(statuses, "grepable")
    payload = json.loads(format_discovery(statuses, "json"))
    assert payload[0]["open_port"] == 80
    assert format_discovery([], "grepable") == "# no results"
    assert format_discovery([], "table") == "No results."


def test_format_benchmarks_table_and_json():
    results = [
        BenchmarkResult(
            technique="sync",
            ports=10,
            concurrency=1,
            timeout=0.5,
            duration_ms=100.0,
            open=1,
            closed=2,
            filtered=3,
            unreachable=1,
            permission_denied=0,
            unknown=1,
            error=2,
        )
    ]
    table = format_benchmarks(results, "table")
    assert "UNREACH" in table
    data = json.loads(format_benchmarks(results, "json"))
    assert data[0]["other"] == 4


def test_format_http_and_tls_probes():
    http = HTTPProbeResult(
        state=ProbeState.HTTP_DETECTED,
        method="HEAD",
        path="/",
        http_version="HTTP/1.1",
        status_code=200,
        reason="OK",
        headers={"server": "test"},
        server="test",
        location="/next",
        raw_preview="HTTP/1.1 200 OK",
        error=None,
    )
    assert "version: HTTP/1.1" in format_http_probe(http, "text")
    assert json.loads(format_http_probe(http, "json"))["http_version"] == "HTTP/1.1"

    batch = format_http_probe_batch([("t", "127.0.0.1", http)], "json")
    assert "127.0.0.1" in batch
    assert "HTTP probe" in format_http_probe_batch([("t", "127.0.0.1", http)], "text")
    assert format_http_probe_batch([], "text") == "No results."

    tls_ok = TLSProbeResult(ok=True, protocol="TLSv1.3", cipher="AES", verified=True, san=["a.com"])
    assert "TLSv1.3" in format_tls_probe(tls_ok, "text")
    tls_fail = TLSProbeResult(ok=False, error="handshake failed")
    assert "failed" in format_tls_probe(tls_fail, "text")
    assert json.loads(format_tls_probe_batch([("t", "1.2.3.4", tls_ok)], "json"))[0]["cipher"] == "AES"


def test_format_banner_probe_batch():
    assert "(no banner received)" in format_banner_probe_batch([("t", "127.0.0.1", 22, None)], "text")
    payload = json.loads(format_banner_probe_batch([("t", "127.0.0.1", 22, "SSH-2.0")], "json"))
    assert payload[0]["banner"] == "SSH-2.0"


def test_format_report_and_saved_report_detail_paths():
    options = ScanOptions(
        timeout=0.75,
        concurrency=100,
        rate_limit=0.0,
        technique=Technique.TCP_CONNECT,
        probe=True,
    )
    report = ScanReport(
        target_expression="127.0.0.1",
        ports=[80, 443, 9090],
        options=options,
        authorization_summary=AuthorizationSummary(
            authorized=False,
            reason=None,
            requires_audit=False,
            categories=["loopback"],
        ),
    )
    report.results = [
        PortResult(
            target="127.0.0.1",
            address="127.0.0.1",
            port=80,
            state=ScanState.OPEN,
            http=HTTPProbeResult(
                state=ProbeState.HTTP_DETECTED,
                method="HEAD",
                path="/",
                status_code=200,
                reason="OK",
            ),
        ),
        PortResult(
            target="127.0.0.1",
            address="127.0.0.1",
            port=443,
            state=ScanState.OPEN,
            tls=TLSProbeResult(ok=True, protocol="TLSv1.2"),
        ),
        PortResult(
            target="127.0.0.1",
            address="127.0.0.1",
            port=9090,
            state=ScanState.OPEN,
            banner="hello banner",
        ),
    ]
    report.finish(5.0)
    data = json.loads(format_report(report, "json"))
    assert data["authorization_summary"]["categories"] == ["loopback"]
    table = format_results_table(report.results)
    assert "http 200" in table
    assert "tls TLSv1.2" in table
    assert "hello banner" in table

    saved = format_saved_report(data, "table")
    assert "PORT" in saved
    assert format_saved_report(data, "grepable").startswith("127.0.0.1")
    assert json.loads(format_saved_report(data, "json"))["ports"] == [80, 443, 9090]
