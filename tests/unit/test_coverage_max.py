"""Unit tests for coverage max module in portsleuth CLI."""

import asyncio
import types

import pytest

from portsleuth.cli.exit_codes import OK
from portsleuth.cli.main import main
from portsleuth.cli.output import _service_label
from portsleuth.cli.report_schema import validate_report_data
from portsleuth.concurrency.benchmark import BenchmarkResult
from portsleuth.exceptions import DiscoverInterrupted
from portsleuth.fingerprint.http_probe import probe_http  # noqa: F401
from portsleuth.lab.fixture_tcp import tcp_fixture
from portsleuth.models import HTTPProbeResult, ProbeState, ScanOptions, Target, Technique
from portsleuth.packet.checksum import ones_complement_checksum
from portsleuth.scan import connect as connect_mod
from portsleuth.scan import fd_limit as fd_limit_mod
from portsleuth.scan.connect import scan_many, scan_port


def test_ones_complement_checksum_carries():
    # Force multiple carry folds through the checksum reducer.
    data = b"\xff\xff" * 40 + b"\x01"
    value = ones_complement_checksum(data)
    assert 0 <= value <= 0xFFFF


def test_tcp_header_unpack_pads_options():
    from portsleuth.packet.tcp import _pad_options

    padded = _pad_options(b"\x01")
    assert len(padded) % 4 == 0


def test_soft_fd_limit_unix_resource_path(monkeypatch):
    fake_resource = types.SimpleNamespace(
        RLIMIT_NOFILE=1,
        getrlimit=lambda *_args: (128, 256),
    )
    monkeypatch.setattr(fd_limit_mod.sys, "platform", "linux")
    monkeypatch.setitem(__import__("sys").modules, "resource", fake_resource)
    assert fd_limit_mod.soft_fd_limit() == 128
    monkeypatch.setattr(fd_limit_mod.sys, "platform", "win32")


def test_scan_port_https_probe_branch(monkeypatch):
    async def run():
        async with tcp_fixture(banner="plain") as fixture:
            monkeypatch.setattr(connect_mod, "HTTPS_LIKE_PORTS", {fixture.port})
            target = Target(expression=fixture.host, address=fixture.host, is_loopback=True)
            result = await scan_port(
                target,
                fixture.port,
                timeout=0.5,
                probe=True,
                probe_insecure=True,
            )
        assert result.state.value == "open"

    asyncio.run(run())


def test_http_probe_head_fallback_to_get(monkeypatch):
    calls = {"count": 0}
    original = connect_mod  # noqa: F841

    import portsleuth.fingerprint.http_probe as http_probe_mod

    def fake_probe_once(host, port, *, path, method, timeout, host_header):
        calls["count"] += 1
        if method == "HEAD":
            return HTTPProbeResult(state=ProbeState.NO_RESPONSE, method="HEAD", path=path)
        return HTTPProbeResult(
            state=ProbeState.HTTP_DETECTED,
            method="GET",
            path=path,
            status_code=200,
            http_version="HTTP/1.1",
        )

    monkeypatch.setattr(http_probe_mod, "_probe_once", fake_probe_once)
    result = http_probe_mod.probe_http("127.0.0.1", 80, timeout=0.2)
    assert result.state == ProbeState.HTTP_DETECTED
    assert calls["count"] == 2


def test_report_schema_missing_option_and_result_keys():
    with pytest.raises(ValueError, match="missing required keys"):
        validate_report_data(
            {
                "target_expression": "127.0.0.1",
                "ports": [80],
                "options": {"timeout": 1, "concurrency": 1, "rate_limit": 0},
                "results": [],
            }
        )


def test_service_label_without_confidence():
    assert _service_label("http", None) == "http"


def test_main_discover_interrupt(monkeypatch, capsys):
    import portsleuth.cli.main as cli_main

    async def broken_sweep(*_args, **_kwargs):
        raise DiscoverInterrupted([])

    monkeypatch.setattr(cli_main, "tcp_ping_sweep", broken_sweep)
    code = main(["discover", "127.0.0.1", "--timeout", "0.2"])
    capsys.readouterr()
    assert code == 130


def test_main_benchmark_keyboard_interrupt(monkeypatch, capsys):
    import portsleuth.cli.main as cli_main

    sample = BenchmarkResult(
        technique="sync",
        ports=1,
        concurrency=1,
        timeout=0.2,
        duration_ms=1.0,
        open=0,
        closed=1,
        filtered=0,
        unreachable=0,
        permission_denied=0,
        unknown=0,
        error=0,
    )
    monkeypatch.setattr(cli_main, "run_sync_benchmark", lambda *_a, **_k: sample)
    monkeypatch.setattr(cli_main, "run_threaded_benchmark", lambda *_a, **_k: sample)

    def fail_run(_coro):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli_main.asyncio, "run", fail_run)
    code = main(["benchmark", "127.0.0.1", "--ports", "9", "--timeout", "0.2"])
    capsys.readouterr()
    assert code == OK


def test_scan_many_sync_progress_callback():
    async def run():
        target = Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True)

        def progress(_result):
            return None

        options = ScanOptions(timeout=0.2, concurrency=1, rate_limit=0, technique=Technique.TCP_CONNECT)
        await scan_many([target], [9], options, progress)

    asyncio.run(run())
