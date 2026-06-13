"""Integration tests for extended commands in portsleuth CLI."""

import asyncio

from portsleuth.cli.exit_codes import FIXTURE, INTERRUPTED, OK, TARGET_ERROR
from portsleuth.cli.main import main
from portsleuth.lab.fixture_udp import start_udp_fixture


def test_probe_banner_command(capsys):
    code = main(["probe", "banner", "127.0.0.1", "--port", "9", "--timeout", "0.2"])
    out = capsys.readouterr().out
    assert code == OK
    assert "127.0.0.1" in out or "no banner" in out.lower()


def test_probe_http_json_multi_target(capsys):
    code = main(["probe", "http", "127.0.0.1", "--port", "9", "--timeout", "0.2", "--format", "json"])
    out = capsys.readouterr().out
    assert code == OK
    assert "[" in out


def test_probe_tls_insecure(capsys):
    code = main(["probe", "tls", "127.0.0.1", "--port", "9", "--timeout", "0.2", "--insecure"])
    capsys.readouterr()
    assert code == OK


def test_discover_command(capsys):
    code = main(["discover", "127.0.0.1", "--timeout", "0.2"])
    out = capsys.readouterr().out
    assert code == OK
    assert "127.0.0.1" in out


def test_packet_demo_protocols(capsys):
    code = main(["packet", "demo", "--protocol", "udp"])
    out = capsys.readouterr().out
    assert code == OK
    assert "UDP" in out


def test_report_missing_file(capsys):
    code = main(["report", "missing-report.json"])
    err = capsys.readouterr().err
    assert code == TARGET_ERROR
    assert "not found" in err.lower()


def test_scan_with_dns_partial_comma_list(capsys):
    code = main(["scan", "127.0.0.1,invalid.invalid", "--ports", "9", "--timeout", "0.2"])
    out = capsys.readouterr()
    assert code in {OK, 7}  # partial if dns_error triggers exit 7
    assert "dns_error" in out.out.lower() or "skipped" in out.err.lower()


def test_lab_fixture_port_in_use_returns_fixture(monkeypatch, capsys):
    import portsleuth.cli.main as main_mod

    def boom(*_args, **_kwargs):
        raise OSError("address in use")

    monkeypatch.setattr(main_mod, "run_tcp_fixture", boom)
    code = main(["lab", "serve-tcp", "--port", "9090"])
    err = capsys.readouterr().err
    assert code == FIXTURE
    assert "Lab startup failed" in err


def test_udp_fixture_responds():
    class CollectingProtocol(asyncio.DatagramProtocol):
        def __init__(self):
            self.queue: asyncio.Queue[bytes] = asyncio.Queue()

        def datagram_received(self, data: bytes, addr) -> None:
            self.queue.put_nowait(data)

    async def run():
        fixture = await start_udp_fixture(host="127.0.0.1", port=0, banner="udp-ok")
        await asyncio.sleep(0.05)
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: CollectingProtocol(),
            remote_addr=("127.0.0.1", fixture.port),
        )
        transport.sendto(b"ping")
        try:
            data = await asyncio.wait_for(protocol.queue.get(), timeout=1.0)
        finally:
            transport.close()
            fixture.transport.close()
        assert b"udp-ok" in data

    asyncio.run(run())


def test_main_keyboard_interrupt(monkeypatch):
    import portsleuth.cli.main as main_mod

    def interrupt(_args):
        raise KeyboardInterrupt

    monkeypatch.setattr(main_mod, "cmd_doctor", interrupt)
    assert main(["doctor"]) == INTERRUPTED


def test_main_portsleuth_error(monkeypatch, capsys):
    import portsleuth.cli.main as main_mod
    from portsleuth.exceptions import PortsleuthError

    def boom(_args):
        raise PortsleuthError("boom")

    monkeypatch.setattr(main_mod, "cmd_doctor", boom)
    code = main(["doctor"])
    assert code == 1
    assert "boom" in capsys.readouterr().err


def test_main_os_error(monkeypatch, capsys):
    import portsleuth.cli.main as main_mod

    def boom(_args):
        raise OSError("disk full")

    monkeypatch.setattr(main_mod, "cmd_doctor", boom)
    code = main(["doctor"])
    assert code == 1
