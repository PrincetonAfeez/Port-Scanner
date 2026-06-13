"""Integration tests for main entry point in portsleuth CLI."""

import json

from portsleuth.cli.exit_codes import AUTHORIZATION_DENIED, OK
from portsleuth.cli.main import main


def test_scan_json_with_authorization_summary(tmp_path, capsys):
    report = tmp_path / "out.json"
    code = main(
        [
            "scan",
            "127.0.0.1",
            "--ports",
            "9",
            "--timeout",
            "0.2",
            "--format",
            "json",
            "--output",
            str(report),
        ]
    )
    capsys.readouterr()
    assert code == OK
    data = json.loads(report.read_text(encoding="utf-8"))
    assert "authorization_summary" in data


def test_scan_with_progress_flag(capsys):
    code = main(["scan", "127.0.0.1", "--ports", "9", "--timeout", "0.2", "--progress"])
    err = capsys.readouterr().err
    assert code == OK
    assert "progress" in err.lower()


def test_authorized_private_scan_writes_audit(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    code = main(
        [
            "scan",
            "192.168.1.10",
            "--ports",
            "9",
            "--timeout",
            "0.2",
            "--authorized",
            "--audit-file",
            str(audit),
        ]
    )
    capsys.readouterr()
    assert code == OK
    assert audit.exists()


def test_public_without_reason_denied(capsys):
    code = main(["scan", "8.8.8.8", "--ports", "80", "--authorized"])
    err = capsys.readouterr().err
    assert code == AUTHORIZATION_DENIED
    assert "reason" in err.lower()


def test_doctor_require_raw_exit_code(capsys, monkeypatch):
    import portsleuth.cli.main as main_mod
    from portsleuth.capabilities import CapabilityReport

    def fake_detect(*_args, **_kwargs):
        return CapabilityReport(
            os="Test",
            python="3.12",
            is_admin_or_root=False,
            raw_icmp_available=False,
            raw_tcp_socket_creatable=False,
            raw_tcp_syn_likely_supported=False,
            packet_capture_tools=[],
            fixture_ports=[],
            default_timeout=0.75,
            default_concurrency=100,
            default_rate_limit=200.0,
            tls_cert_fields_available=True,
            notes=[],
        )

    monkeypatch.setattr(main_mod, "detect_capabilities", fake_detect)
    code = main(["doctor", "--require-raw"])
    capsys.readouterr()
    assert code == 6
