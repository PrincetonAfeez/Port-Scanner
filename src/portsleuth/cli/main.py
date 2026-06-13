"""Main entry point for portsleuth CLI."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from pathlib import Path

from portsleuth import __version__
from portsleuth.capabilities import detect_capabilities
from portsleuth.cli.exit_codes import (
    AUTHORIZATION_DENIED,
    ERROR,
    FIXTURE,
    INTERRUPTED,
    OK,
    PARTIAL,
    PRIVILEGE,
    TARGET_ERROR,
    UNSUPPORTED,
    USAGE,
)
from portsleuth.cli.output import (
    format_banner_probe_batch,
    format_benchmarks,
    format_capabilities,
    format_discovery,
    format_http_probe_batch,
    format_report,
    format_saved_report,
    format_tls_probe_batch,
)
from portsleuth.cli.packet_demo import format_packet_demo
from portsleuth.cli.report_schema import validate_report_data
from portsleuth.cli.validation import validate_probe_port, validate_scan_tuning
from portsleuth.concurrency.benchmark import (
    run_async_benchmark,
    run_sync_benchmark,
    run_threaded_benchmark,
)
from portsleuth.config import TOP_PORTS, Settings, load_settings
from portsleuth.discovery.tcp_ping import DEFAULT_PING_PORTS, tcp_ping_sweep
from portsleuth.exceptions import (
    AuthorizationError,
    DiscoverInterrupted,
    PortsleuthError,
    ScanInterrupted,
    TargetResolutionError,
)
from portsleuth.fingerprint.banner import grab_banner_sync
from portsleuth.fingerprint.http_probe import probe_http
from portsleuth.fingerprint.tls import probe_tls
from portsleuth.lab.fixture_tcp import run_tcp_fixture
from portsleuth.lab.fixture_udp import run_udp_fixture
from portsleuth.lab.fixture_wsgiref import run_wsgi_server
from portsleuth.models import PARTIAL_EXIT_STATES, ScanOptions, ScanReport, Technique
from portsleuth.observability.audit import write_audit_record
from portsleuth.scan.connect import build_dns_error_results, scan_many
from portsleuth.targets.parse import authorization_summary_from_plan, build_target_plan
from portsleuth.targets.ports import parse_ports
from portsleuth.targets.sort import address_sort_key

logger = logging.getLogger("portsleuth")


def _configure_logging(verbose: bool = False) -> None:
    # Diagnostics (warnings/errors) go through logging to stderr; scan results
    # stay on stdout via print. force=True rebinds the handler to the current
    # sys.stderr on each invocation (and keeps pytest's capture working).
    logging.basicConfig(
        stream=sys.stderr,
        format="%(message)s",
        level=logging.INFO if verbose else logging.WARNING,
        force=True,
    )


def main(argv: list[str] | None = None) -> int:
    _configure_logging()
    try:
        settings = load_settings()
    except ValueError as exc:
        logger.error("Input error: %s", exc)
        return USAGE
    parser = build_parser(settings)
    args = parser.parse_args(argv)
    if getattr(args, "verbose", False):
        _configure_logging(verbose=True)
    try:
        return args.func(args)
    except AuthorizationError as exc:
        logger.error("Authorization denied: %s", exc)
        return AUTHORIZATION_DENIED
    except TargetResolutionError as exc:
        logger.error("Target error: %s", exc)
        return TARGET_ERROR
    except ValueError as exc:
        logger.error("Input error: %s", exc)
        return USAGE
    except KeyboardInterrupt:
        logger.warning("Interrupted.")
        return INTERRUPTED
    except OSError as exc:
        # e.g. an unwritable --output path or audit directory.
        logger.error("Error: %s", exc)
        return ERROR
    except PortsleuthError as exc:
        # Catch-all for the project's exception hierarchy (keeps it meaningful
        # without per-type handlers for exceptions no current path raises).
        logger.error("Error: %s", exc)
        return ERROR


def build_parser(settings: Settings | None = None) -> argparse.ArgumentParser:
    if settings is None:
        settings = Settings()
    parser = argparse.ArgumentParser(
        prog="portsleuth",
        description="Safe educational TCP port scanner with local protocol labs.",
    )
    parser.add_argument("--version", action="version", version=f"portsleuth {__version__}")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="enable INFO-level diagnostics on stderr",
    )
    # Make the resolved settings available to every command's handler.
    parser.set_defaults(settings=settings)
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="scan TCP ports")
    add_target_args(scan, settings, default=settings.target)
    add_scan_tuning_args(scan, settings)
    scan.add_argument("--ports", help="ports such as 22,80,8000-8010")
    scan.add_argument("--top", type=int, help="scan the first N curated common ports (static list, not nmap frequency rank)")
    scan.add_argument("--format", choices=["table", "json", "grepable", "grep"], default="table")
    scan.add_argument("--output", help="write report output to a file")
    scan.add_argument(
        "--probe-insecure",
        action="store_true",
        help="skip TLS certificate verification during --probe on HTTPS ports",
    )
    scan.add_argument(
        "--technique",
        choices=[item.value for item in Technique],
        default=Technique.TCP_CONNECT.value,
        help="scan technique; 'syn' and 'udp' report as unsupported in the portable core (see doctor)",
    )
    scan.add_argument(
        "--probe",
        "--banner",
        dest="probe",
        action="store_true",
        help="probe open ports for HTTP, TLS, or banners",
    )
    scan.add_argument("--progress", action="store_true", help="print scan progress to stderr")
    scan.set_defaults(func=cmd_scan)

    probe = subcommands.add_parser("probe", help="send a protocol probe")
    probe_subcommands = probe.add_subparsers(dest="probe_command", required=True)

    probe_http_parser = probe_subcommands.add_parser("http", help="send hand-written HTTP bytes")
    add_target_args(probe_http_parser, settings, positional_name="target", default=None)
    probe_http_parser.add_argument("--port", type=int, default=80)
    probe_http_parser.add_argument("--path", default="/")
    probe_http_parser.add_argument("--method", choices=["HEAD", "GET"], default="HEAD")
    probe_http_parser.add_argument("--timeout", type=float, default=1.0)
    probe_http_parser.add_argument("--format", choices=["text", "json"], default="text")
    probe_http_parser.add_argument("--show-preview", action="store_true", help="show raw HTTP response preview")
    probe_http_parser.set_defaults(func=cmd_probe_http)

    probe_tls_parser = probe_subcommands.add_parser("tls", help="perform a TLS handshake and summarize the certificate")
    add_target_args(probe_tls_parser, settings, positional_name="target", default=None)
    probe_tls_parser.add_argument("--port", type=int, default=443)
    probe_tls_parser.add_argument("--timeout", type=float, default=2.0)
    probe_tls_parser.add_argument("--server-name", help="SNI hostname")
    probe_tls_parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip certificate verification (for self-signed lab targets)",
    )
    probe_tls_parser.add_argument("--format", choices=["text", "json"], default="text")
    probe_tls_parser.set_defaults(func=cmd_probe_tls)

    probe_banner_parser = probe_subcommands.add_parser("banner", help="read a service banner from an open TCP port")
    add_target_args(probe_banner_parser, settings, positional_name="target", default=None)
    probe_banner_parser.add_argument("--port", type=int, required=True)
    probe_banner_parser.add_argument("--timeout", type=float, default=1.0)
    probe_banner_parser.add_argument("--format", choices=["text", "json"], default="text")
    probe_banner_parser.set_defaults(func=cmd_probe_banner)

    discover = subcommands.add_parser("discover", help="TCP-ping host discovery sweep")
    add_target_args(discover, settings, default=settings.target)
    add_scan_tuning_args(discover, settings)
    discover.add_argument("--ports", help="probe ports for liveness (default: common service ports)")
    discover.add_argument("--format", choices=["table", "json", "grepable", "grep"], default="table")
    discover.add_argument("--output", help="write discovery output to a file")
    discover.set_defaults(func=cmd_discover)

    lab = subcommands.add_parser("lab", help="run local lab fixture servers")
    lab_subcommands = lab.add_subparsers(dest="lab_command", required=True)

    serve_tcp = lab_subcommands.add_parser("serve-tcp", help="serve a banner over TCP")
    serve_tcp.add_argument("--host", default="127.0.0.1")
    serve_tcp.add_argument("--port", type=int, default=9090)
    serve_tcp.add_argument("--banner", default="portsleuth fixture")
    serve_tcp.set_defaults(func=cmd_lab_tcp)

    serve_wsgi = lab_subcommands.add_parser("serve-wsgi", help="serve the WSGI HTTP lab")
    serve_wsgi.add_argument("--host", default="127.0.0.1")
    serve_wsgi.add_argument("--port", type=int, default=8080)
    serve_wsgi.set_defaults(func=cmd_lab_wsgi)

    serve_udp = lab_subcommands.add_parser("serve-udp", help="serve a banner over UDP")
    serve_udp.add_argument("--host", default="127.0.0.1")
    serve_udp.add_argument("--port", type=int, default=5353)
    serve_udp.add_argument("--banner", default="portsleuth udp fixture")
    serve_udp.set_defaults(func=cmd_lab_udp)

    doctor = subcommands.add_parser("doctor", help="show platform and raw socket capability checks")
    doctor.add_argument("--format", choices=["table", "json"], default="table")
    doctor.add_argument(
        "--require-raw",
        action="store_true",
        help="exit with code 6 when raw packet sockets are unavailable",
    )
    doctor.set_defaults(func=cmd_doctor)

    packet = subcommands.add_parser("packet", help="show hand-packed protocol header evidence")
    packet_subcommands = packet.add_subparsers(dest="packet_command", required=True)
    packet_demo = packet_subcommands.add_parser("demo", help="display example IPv4/TCP/UDP/ICMP header bytes")
    packet_demo.add_argument(
        "--protocol",
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="which protocol examples to show (default: all)",
    )
    packet_demo.set_defaults(func=cmd_packet_demo)

    report = subcommands.add_parser("report", help="re-render a saved JSON scan report")
    report.add_argument("path", help="path to a JSON report written by scan --output")
    report.add_argument("--format", choices=["table", "json", "grepable", "grep"], default="table")
    report.set_defaults(func=cmd_report)

    config = subcommands.add_parser("config", help="show effective default settings")
    config.add_argument("--format", choices=["table", "json"], default="table")
    config.set_defaults(func=cmd_config)

    benchmark = subcommands.add_parser("benchmark", help="compare sync, threaded, and asyncio connect scans")
    add_target_args(benchmark, settings, default=settings.target)
    # Benchmark only needs timeout and concurrency; rate limiting and audit are
    # deliberately omitted (the async lane runs unthrottled for a fair comparison).
    benchmark.add_argument("--timeout", type=float, default=settings.timeout)
    benchmark.add_argument("--concurrency", type=int, default=settings.concurrency)
    benchmark.add_argument("--ports", default="1-1024")
    benchmark.add_argument("--top", type=int, help="scan the first N curated common ports")
    benchmark.add_argument("--format", choices=["table", "json"], default="table")
    benchmark.set_defaults(func=cmd_benchmark)

    return parser


def add_target_args(parser: argparse.ArgumentParser, settings: Settings, positional_name: str = "target", default: str | None = None) -> None:
    if default is None:
        parser.add_argument(positional_name, help="target host, IP, comma-list, or CIDR")
    else:
        parser.add_argument(positional_name, nargs="?", default=default, help=f"target host, IP, comma-list, or CIDR (default: {default})")
    parser.add_argument("--authorized", action="store_true", help="confirm you are authorized to scan this non-local target")
    parser.add_argument("--reason", help="required reason for public or CIDR targets")
    parser.add_argument("--max-hosts", type=int, default=settings.max_cidr_hosts, help="maximum hosts expanded from CIDR input")
    parser.add_argument(
        "--family",
        choices=["ipv4", "ipv6", "auto"],
        default="ipv4",
        help="address family for hostnames that resolve to both (default: ipv4)",
    )


def add_scan_tuning_args(parser: argparse.ArgumentParser, settings: Settings) -> None:
    parser.add_argument("--timeout", type=float, default=settings.timeout)
    parser.add_argument("--concurrency", type=int, default=settings.concurrency)
    parser.add_argument("--rate", type=float, default=settings.rate_limit, help="connection attempts per second; 0 disables pacing")
    parser.add_argument("--audit-file", default=settings.audit_file)


def _warn_top(top: int | None, ports: str | None = None) -> None:
    if top is None:
        return
    if ports:
        logger.warning("--top overrides --ports; --ports is ignored.")
    if top > len(TOP_PORTS):
        logger.warning(
            "--top %s exceeds the %s curated common ports; scanning %s.",
            top,
            len(TOP_PORTS),
            len(TOP_PORTS),
        )


def _emit_warnings(warnings: list[str]) -> None:
    for warning in warnings:
        logger.warning("%s", warning)


def _validate_tuning_args(args: argparse.Namespace) -> None:
    validate_scan_tuning(
        timeout=args.timeout,
        concurrency=args.concurrency,
        rate=args.rate,
        max_hosts=args.max_hosts,
    )


def _write_output(output: str, path: str | None) -> None:
    if path:
        Path(path).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


def _maybe_write_audit(
    plan,
    args: argparse.Namespace,
    ports: list[int],
    options: ScanOptions,
    *,
    technique: str | None = None,
) -> None:
    if plan.requires_audit:
        audit_file = getattr(args, "audit_file", args.settings.audit_file)
        write_audit_record(
            audit_file,
            target_expression=args.target,
            targets=plan.targets,
            ports=ports,
            options=options,
            authorized=args.authorized,
            reason=args.reason,
            technique=technique,
        )


def _scan_exit_code(report: ScanReport, technique: Technique) -> int:
    if technique != Technique.TCP_CONNECT:
        return UNSUPPORTED
    if any(result.state in PARTIAL_EXIT_STATES for result in report.results):
        return PARTIAL
    return OK


def _interrupt_exit_code(report: ScanReport) -> int:
    if not report.results:
        return INTERRUPTED
    if any(result.state in PARTIAL_EXIT_STATES for result in report.results):
        return PARTIAL
    return INTERRUPTED


def cmd_scan(args: argparse.Namespace) -> int:
    _validate_tuning_args(args)
    _warn_top(args.top, args.ports)
    ports = parse_ports(args.ports, top=args.top)
    plan = build_target_plan(
        args.target,
        authorized=args.authorized,
        reason=args.reason,
        max_hosts=args.max_hosts,
        family=args.family,
    )
    options = ScanOptions(
        timeout=args.timeout,
        concurrency=args.concurrency,
        rate_limit=args.rate,
        technique=Technique(args.technique),
        probe=args.probe,
        probe_insecure=args.probe_insecure,
    )
    report = ScanReport(
        target_expression=args.target,
        ports=ports,
        options=options,
        authorization_summary=authorization_summary_from_plan(
            plan,
            authorized=args.authorized,
            reason=args.reason,
        ),
    )
    logger.info(
        "scanning %d port(s) across %d target(s) (technique=%s)",
        len(ports),
        len(plan.targets),
        options.technique.value,
    )
    progress = _make_progress(len(plan.targets) * len(ports)) if args.progress else None
    started = time.perf_counter()
    scan_interrupted = False
    try:
        report.results = asyncio.run(scan_many(plan.targets, ports, options, progress))
    except ScanInterrupted as exc:
        report.results = exc.results
        scan_interrupted = True
        logger.warning("Scan interrupted; writing partial results for %d finished port(s).", len(exc.results))
    except KeyboardInterrupt:
        scan_interrupted = True
        logger.warning("Scan interrupted during scan.")
    report.finish((time.perf_counter() - started) * 1000)
    report.results.extend(build_dns_error_results(plan.dns_failures, ports, options.technique))
    report.results.sort(key=lambda item: (address_sort_key(item.address), item.target, item.port))

    try:
        _maybe_write_audit(plan, args, ports, options)
    except KeyboardInterrupt:
        logger.warning("Interrupted during audit; continuing to write scan output.")
    output = format_report(report, args.format)
    _emit_warnings(plan.warnings)
    _write_output(output, args.output)

    if scan_interrupted:
        return _interrupt_exit_code(report)
    return _scan_exit_code(report, options.technique)


def _make_progress(total: int):
    done = 0

    def progress(_result) -> None:
        nonlocal done
        done += 1
        print(f"\rprogress: {done}/{total}", end="", file=sys.stderr, flush=True)
        if done == total:
            print("", file=sys.stderr)

    return progress


def cmd_discover(args: argparse.Namespace) -> int:
    _validate_tuning_args(args)
    plan = build_target_plan(
        args.target,
        authorized=args.authorized,
        reason=args.reason,
        max_hosts=args.max_hosts,
        family=args.family,
    )
    if args.ports:
        ports = tuple(parse_ports(args.ports))
    else:
        ports = DEFAULT_PING_PORTS

    discover_interrupted = False
    statuses = []
    try:
        statuses = asyncio.run(
            tcp_ping_sweep(
                plan.targets,
                ports,
                timeout=args.timeout,
                concurrency=args.concurrency,
                rate_limit=args.rate,
            )
        )
    except DiscoverInterrupted as exc:
        statuses = exc.statuses
        discover_interrupted = True
        logger.warning("Discovery interrupted; writing partial results for %d host(s).", len(statuses))
    except KeyboardInterrupt:
        discover_interrupted = True
        logger.warning("Discovery interrupted.")

    options = ScanOptions(
        timeout=args.timeout,
        concurrency=args.concurrency,
        rate_limit=args.rate,
        technique=Technique.TCP_CONNECT,
    )
    try:
        _maybe_write_audit(plan, args, list(ports), options, technique="tcp-ping")
    except KeyboardInterrupt:
        logger.warning("Interrupted during audit; continuing to write discovery output.")

    _emit_warnings(plan.warnings)
    output = format_discovery(statuses, args.format)
    _write_output(output, args.output)
    if discover_interrupted:
        return INTERRUPTED if not statuses else OK
    return OK


def cmd_probe_http(args: argparse.Namespace) -> int:
    validate_scan_tuning(timeout=args.timeout, concurrency=1, rate=0, max_hosts=args.max_hosts)
    validate_probe_port(args.port)
    plan = build_target_plan(
        args.target,
        authorized=args.authorized,
        reason=args.reason,
        max_hosts=args.max_hosts,
        family=args.family,
    )
    _emit_warnings(plan.warnings)
    options = ScanOptions(timeout=args.timeout, concurrency=1, rate_limit=0, technique=Technique.TCP_CONNECT)
    _maybe_write_audit(plan, args, [args.port], options, technique="probe-http")

    entries: list = []
    for target in plan.targets:
        host_header = target.hostname or target.address
        result = probe_http(
            target.address,
            args.port,
            path=args.path,
            method=args.method,
            timeout=args.timeout,
            host_header=host_header,
        )
        if not args.show_preview:
            result.raw_preview = None
        entries.append((target.label, target.address, result))
    print(format_http_probe_batch(entries, args.format))
    return OK


def cmd_probe_tls(args: argparse.Namespace) -> int:
    validate_scan_tuning(timeout=args.timeout, concurrency=1, rate=0, max_hosts=args.max_hosts)
    validate_probe_port(args.port)
    plan = build_target_plan(
        args.target,
        authorized=args.authorized,
        reason=args.reason,
        max_hosts=args.max_hosts,
        family=args.family,
    )
    _emit_warnings(plan.warnings)
    options = ScanOptions(timeout=args.timeout, concurrency=1, rate_limit=0, technique=Technique.TCP_CONNECT)
    _maybe_write_audit(plan, args, [args.port], options, technique="probe-tls")

    entries: list = []
    for target in plan.targets:
        result = probe_tls(
            target.address,
            args.port,
            timeout=args.timeout,
            server_hostname=args.server_name or target.hostname,
            verify=not args.insecure,
        )
        entries.append((target.label, target.address, result))
    print(format_tls_probe_batch(entries, args.format))
    return OK


def cmd_probe_banner(args: argparse.Namespace) -> int:
    validate_scan_tuning(timeout=args.timeout, concurrency=1, rate=0, max_hosts=args.max_hosts)
    validate_probe_port(args.port)
    plan = build_target_plan(
        args.target,
        authorized=args.authorized,
        reason=args.reason,
        max_hosts=args.max_hosts,
        family=args.family,
    )
    _emit_warnings(plan.warnings)
    options = ScanOptions(timeout=args.timeout, concurrency=1, rate_limit=0, technique=Technique.TCP_CONNECT)
    _maybe_write_audit(plan, args, [args.port], options, technique="probe-banner")

    entries: list[tuple[str, str, int, str | None]] = []
    for target in plan.targets:
        banner = grab_banner_sync(target.address, args.port, timeout=args.timeout)
        entries.append((target.label, target.address, args.port, banner))
    print(format_banner_probe_batch(entries, args.format))
    return OK


def cmd_lab_tcp(args: argparse.Namespace) -> int:
    try:
        asyncio.run(run_tcp_fixture(args.host, args.port, args.banner))
    except OSError as exc:
        logger.error("Lab startup failed: %s", exc)
        return FIXTURE
    return OK


def cmd_lab_wsgi(args: argparse.Namespace) -> int:
    try:
        run_wsgi_server(args.host, args.port)
    except OSError as exc:
        logger.error("Lab startup failed: %s", exc)
        return FIXTURE
    return OK


def cmd_lab_udp(args: argparse.Namespace) -> int:
    try:
        asyncio.run(run_udp_fixture(args.host, args.port, args.banner))
    except OSError as exc:
        logger.error("Lab startup failed: %s", exc)
        return FIXTURE
    return OK


def cmd_doctor(args: argparse.Namespace) -> int:
    report = detect_capabilities(
        default_timeout=args.settings.timeout,
        default_concurrency=args.settings.concurrency,
        default_rate_limit=args.settings.rate_limit,
    )
    print(format_capabilities(report, args.format))
    if args.require_raw and not (report.raw_icmp_available and report.raw_tcp_socket_creatable):
        return PRIVILEGE
    return OK


def cmd_packet_demo(args: argparse.Namespace) -> int:
    print(format_packet_demo(args.protocol))
    return OK


def cmd_report(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.is_file():
        logger.error("Report not found: %s", args.path)
        return TARGET_ERROR
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.error("Invalid report file: %s", exc)
        return ERROR
    try:
        validate_report_data(data)
    except ValueError as exc:
        logger.error("Invalid report file: %s", exc)
        return ERROR
    print(format_saved_report(data, args.format))
    return OK


def cmd_config(args: argparse.Namespace) -> int:
    settings = args.settings
    values = {
        "config_source": settings.source or "(built-in defaults; no scan.toml found)",
        "target": settings.target,
        "timeout": settings.timeout,
        "concurrency": settings.concurrency,
        "rate_limit": settings.rate_limit,
        "audit_file": settings.audit_file,
        "max_cidr_hosts": settings.max_cidr_hosts,
        "curated_common_ports": len(TOP_PORTS),
    }
    if args.format == "json":
        print(json.dumps(values, indent=2, sort_keys=True))
    else:
        width = max(len(key) for key in values)
        for key, value in values.items():
            print(f"{key.ljust(width)}  {value}")
    return OK


def cmd_benchmark(args: argparse.Namespace) -> int:
    validate_scan_tuning(
        timeout=args.timeout,
        concurrency=args.concurrency,
        rate=0,
        max_hosts=args.max_hosts,
    )
    _warn_top(args.top)
    ports = parse_ports(args.ports, top=args.top)
    plan = build_target_plan(
        args.target,
        authorized=args.authorized,
        reason=args.reason,
        max_hosts=args.max_hosts,
        family=args.family,
    )
    benchmark_interrupted = False
    results = []
    try:
        results.append(run_sync_benchmark(plan.targets, ports, args.timeout))
        results.append(run_threaded_benchmark(plan.targets, ports, args.timeout, args.concurrency))
        try:
            results.append(
                asyncio.run(
                    run_async_benchmark(plan.targets, ports, args.timeout, args.concurrency, 0.0)
                )
            )
        except KeyboardInterrupt:
            benchmark_interrupted = True
            logger.warning("Benchmark interrupted during async phase.")
    except KeyboardInterrupt:
        benchmark_interrupted = True
        logger.warning("Benchmark interrupted.")

    options = ScanOptions(
        timeout=args.timeout,
        concurrency=args.concurrency,
        rate_limit=0,
        technique=Technique.TCP_CONNECT,
    )
    try:
        _maybe_write_audit(plan, args, ports, options, technique="benchmark")
    except KeyboardInterrupt:
        logger.warning("Interrupted during audit; continuing to write benchmark output.")
    _emit_warnings(plan.warnings)
    if results:
        print(format_benchmarks(results, args.format))
    if benchmark_interrupted:
        return INTERRUPTED if not results else OK
    return OK
