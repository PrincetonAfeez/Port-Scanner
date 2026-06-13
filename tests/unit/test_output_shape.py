"""Unit tests for output shape module in portsleuth CLI."""

import json

from portsleuth.cli.output import format_grepable, format_report
from portsleuth.models import (
    PortResult,
    ScanOptions,
    ScanReport,
    ScanState,
    Technique,
)


def _report() -> ScanReport:
    options = ScanOptions(timeout=0.75, concurrency=100, rate_limit=200.0, technique=Technique.TCP_CONNECT)
    report = ScanReport(target_expression="127.0.0.1", ports=[80], options=options)
    report.results = [
        PortResult(
            target="127.0.0.1",
            address="127.0.0.1",
            port=80,
            state=ScanState.OPEN,
            service="http",
            service_confidence="high",
            latency_ms=1.2,
            reason="TCP connection succeeded",
        )
    ]
    report.finish(12.3)
    return report


def test_json_report_shape():
    data = json.loads(format_report(_report(), "json"))
    assert set(["target_expression", "ports", "options", "results", "started_at", "finished_at"]).issubset(data)
    result = data["results"][0]
    # enums must serialize to their string values, not enum reprs.
    assert result["state"] == "open"
    assert result["technique"] == "connect"
    assert result["service_confidence"] == "high"
    assert isinstance(data["options"]["timeout"], float)


def test_grepable_includes_confidence_and_handles_empty():
    line = format_grepable(_report().results)
    assert "http (high)" in line
    assert format_grepable([]) == "# no results"
