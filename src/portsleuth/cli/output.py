"""Output formatting for portsleuth CLI."""

from __future__ import annotations

import json
from collections.abc import Iterable

from portsleuth.capabilities import CapabilityReport
from portsleuth.concurrency.benchmark import BenchmarkResult
from portsleuth.models import HTTPProbeResult, PortResult, ScanReport, TLSProbeResult


def _normalize_format(output_format: str) -> str:
    return "grepable" if output_format == "grep" else output_format


def format_report(report: ScanReport, output_format: str) -> str:
    output_format = _normalize_format(output_format)
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    if output_format == "grepable":
        return format_grepable(report.results)
    return format_results_table(report.results)


def format_saved_report(data: dict, output_format: str) -> str:
    """Render a previously saved JSON scan report (dict form) for the report command.

    Routes through the same view/renderers as a live scan so the table columns
    and grepable schema match exactly (including service confidence).
    """
    output_format = _normalize_format(output_format)
    if output_format == "json":
        return json.dumps(data, indent=2, sort_keys=True)
    views = [_view_from_dict(item) for item in data.get("results", [])]
    return _render_result_views(views, output_format)


def format_discovery(statuses: list, output_format: str) -> str:
    output_format = _normalize_format(output_format)
    if output_format == "json":
        return json.dumps(
            [
                {
                    "target": status.target,
                    "address": status.address,
                    "is_up": status.is_up,
                    "open_port": status.open_port,
                    "latency_ms": status.latency_ms,
                    "reason": status.reason,
                }
                for status in statuses
            ],
            indent=2,
            sort_keys=True,
        )
    rows = [
        [
            status.target,
            status.address,
            "up" if status.is_up else "down",
            str(status.open_port) if status.open_port else "-",
            _latency(status.latency_ms),
            status.reason,
        ]
        for status in statuses
    ]
    if output_format == "grepable":
        if not rows:
            return "# no results"
        return "\n".join("\t".join(row) for row in rows)
    return _table(["TARGET", "ADDRESS", "STATUS", "PORT", "LATENCY", "REASON"], rows)


# Live scans and re-rendered saved reports both go through a single normalized
# "view" so the table columns and grepable schema are identical for either source.
_RESULT_TABLE_HEADERS = ["TARGET", "ADDRESS", "PORT", "SERVICE", "STATE", "LATENCY", "DETAIL"]


def _service_label(service: str | None, confidence: str | None) -> str:
    if not service:
        return "-"
    if confidence:
        return f"{service} ({confidence})"
    return service


def _view_from_result(result: PortResult) -> dict:
    return {
        "target": result.target,
        "address": result.address,
        "port": result.port,
        "service": _service_label(result.service, result.service_confidence),
        "state": result.state.value,
        "latency_ms": result.latency_ms,
        "detail": _detail(result),
    }


def _view_from_dict(item: dict) -> dict:
    return {
        "target": item.get("target", "-"),
        "address": item.get("address", "-"),
        "port": item.get("port", "-"),
        "service": _service_label(item.get("service"), item.get("service_confidence")),
        "state": item.get("state", "-"),
        "latency_ms": item.get("latency_ms"),
        "detail": _detail_from_dict(item),
    }


def _render_result_views(views: list[dict], output_format: str) -> str:
    if output_format == "grepable":
        if not views:
            return "# no results"
        return "\n".join(_result_grep_line(view) for view in views)
    return _table(_RESULT_TABLE_HEADERS, [_result_table_row(view) for view in views])


def _result_table_row(view: dict) -> list[str]:
    return [
        str(view["target"]),
        str(view["address"]),
        str(view["port"]),
        view["service"],
        str(view["state"]),
        _latency(view["latency_ms"]),
        view["detail"],
    ]


def _result_grep_line(view: dict) -> str:
    detail = view["detail"].replace("\t", " ")
    return f"{view['address']}\t{view['port']}\t{view['state']}\t{view['service']}\t{detail}"


def format_results_table(results: list[PortResult]) -> str:
    return _render_result_views([_view_from_result(r) for r in results], "table")


def format_grepable(results: Iterable[PortResult]) -> str:
    return _render_result_views([_view_from_result(r) for r in results], "grepable")


def format_http_probe(result: HTTPProbeResult, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)
    return _format_http_probe_body(result)


def format_http_probe_batch(
    entries: list[tuple[str, str, HTTPProbeResult]],
    output_format: str,
) -> str:
    if output_format == "json":
        payload = [
            {"target": label, "address": address, **result.to_dict()}
            for label, address, result in entries
        ]
        return json.dumps(payload, indent=2, sort_keys=True)
    if not entries:
        return "No results."
    blocks = [f"target: {label} ({address})\n{_format_http_probe_body(result)}" for label, address, result in entries]
    return "\n\n".join(blocks)


def _format_http_probe_body(result: HTTPProbeResult) -> str:
    lines = [f"HTTP probe: {result.state.value}"]
    if result.http_version:
        lines.append(f"version: {result.http_version}")
    if result.status_code is not None:
        lines.append(f"status: {result.status_code} {result.reason or ''}".rstrip())
    if result.server:
        lines.append(f"server: {result.server}")
    if result.location:
        lines.append(f"location: {result.location}")
    if result.error:
        lines.append(f"note: {result.error}")
    if result.headers:
        lines.append("headers:")
        for name, value in sorted(result.headers.items()):
            lines.append(f"  {name}: {value}")
    if result.raw_preview:
        lines.append("preview:")
        lines.append(result.raw_preview.rstrip())
    return "\n".join(lines)


def format_tls_probe(result: TLSProbeResult, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2, sort_keys=True)
    return _format_tls_probe_body(result)


def format_tls_probe_batch(
    entries: list[tuple[str, str, TLSProbeResult]],
    output_format: str,
) -> str:
    if output_format == "json":
        payload = [
            {"target": label, "address": address, **result.to_dict()}
            for label, address, result in entries
        ]
        return json.dumps(payload, indent=2, sort_keys=True)
    if not entries:
        return "No results."
    blocks = [f"target: {label} ({address})\n{_format_tls_probe_body(result)}" for label, address, result in entries]
    return "\n\n".join(blocks)


def _format_tls_probe_body(result: TLSProbeResult) -> str:
    if not result.ok:
        return f"TLS probe failed: {result.error}"
    rows = [
        ["protocol", result.protocol or "-"],
        ["cipher", result.cipher or "-"],
        ["verified", str(result.verified)],
        ["subject", result.subject or "-"],
        ["issuer", result.issuer or "-"],
        ["not before", result.not_before or "-"],
        ["expires", result.not_after or "-"],
        ["SANs", ", ".join(result.san) if result.san else "-"],
    ]
    return _table(["FIELD", "VALUE"], rows)


def format_banner_probe_batch(
    entries: list[tuple[str, str, int, str | None]],
    output_format: str,
) -> str:
    if output_format == "json":
        payload = [
            {"target": label, "address": address, "port": port, "banner": banner}
            for label, address, port, banner in entries
        ]
        return json.dumps(payload, indent=2, sort_keys=True)
    if not entries:
        return "No results."
    blocks: list[str] = []
    for label, address, port, banner in entries:
        body = banner if banner else "(no banner received)"
        blocks.append(f"target: {label} ({address}:{port})\n{body}")
    return "\n\n".join(blocks)


def format_capabilities(report: CapabilityReport, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)
    rows = [
        ["OS", report.os],
        ["Python", report.python],
        ["Admin/root", str(report.is_admin_or_root)],
        ["Raw ICMP", str(report.raw_icmp_available)],
        ["Raw TCP socket", str(report.raw_tcp_socket_creatable)],
        ["Raw SYN likely", str(report.raw_tcp_syn_likely_supported)],
        ["Capture tools", ", ".join(report.packet_capture_tools) if report.packet_capture_tools else "-"],
        ["Default timeout", str(report.default_timeout)],
        ["Default concurrency", str(report.default_concurrency)],
        ["Default rate limit", str(report.default_rate_limit)],
        ["TLS cert fields extra", str(report.tls_cert_fields_available)],
    ]
    text = _table(["CHECK", "VALUE"], rows)
    if report.fixture_ports:
        fixture_rows = [
            [str(item.port), item.label, item.status]
            for item in report.fixture_ports
        ]
        text += "\n\nLab fixture ports:\n" + _table(["PORT", "LABEL", "STATUS"], fixture_rows)
    if report.notes:
        text += "\n\nNotes:\n" + "\n".join(f"- {note}" for note in report.notes)
    return text


def format_benchmarks(results: list[BenchmarkResult], output_format: str) -> str:
    if output_format == "json":
        return json.dumps([result.to_dict() for result in results], indent=2, sort_keys=True)
    rows = [
        [
            result.technique,
            str(result.ports),
            str(result.concurrency),
            str(result.timeout),
            f"{result.duration_ms:.1f}",
            str(result.open),
            str(result.closed),
            str(result.filtered),
            str(result.unreachable),
            str(result.permission_denied),
            str(result.unknown),
            str(result.error),
        ]
        for result in results
    ]
    return _table(
        [
            "TECHNIQUE",
            "PORTS",
            "CONCURRENCY",
            "TIMEOUT",
            "DURATION_MS",
            "OPEN",
            "CLOSED",
            "FILTERED",
            "UNREACH",
            "DENIED",
            "UNKNOWN",
            "ERROR",
        ],
        rows,
    )


def _detail(result: PortResult) -> str:
    if result.http:
        if result.http.status_code is not None:
            return f"http {result.http.status_code} {result.http.reason or ''}".strip()
        return f"http {result.http.state.value}"
    if result.tls:
        return f"tls {result.tls.protocol or result.tls.error or '-'}"
    if result.banner:
        return result.banner[:80]
    return result.reason or result.error or "-"


def _detail_from_dict(item: dict) -> str:
    # Mirror _detail() for a saved report dict so re-rendering matches a live scan.
    http = item.get("http")
    if http:
        status_code = http.get("status_code")
        if status_code is not None:
            return f"http {status_code} {http.get('reason') or ''}".strip()
        return f"http {http.get('state', '-')}"
    tls = item.get("tls")
    if tls:
        return f"tls {tls.get('protocol') or tls.get('error') or '-'}"
    banner = item.get("banner")
    if banner:
        return banner[:80]
    return item.get("reason") or item.get("error") or "-"


def _latency(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f}ms"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "No results."
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    header_line = "  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    rule = "  ".join("-" * width for width in widths)
    body = [
        "  ".join(row[index].ljust(widths[index]) for index in range(len(headers)))
        for row in rows
    ]
    return "\n".join([header_line, rule, *body])

