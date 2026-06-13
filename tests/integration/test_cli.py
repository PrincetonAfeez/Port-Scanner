"""Integration tests for portsleuth CLI."""

from portsleuth.cli import main as main_mod
from portsleuth.cli.exit_codes import AUTHORIZATION_DENIED, ERROR, OK, PARTIAL, UNSUPPORTED, USAGE
from portsleuth.cli.main import main


def test_doctor_command_runs(capsys):
    code = main(["doctor"])
    out = capsys.readouterr().out
    assert code == OK
    assert "Python" in out
    assert "Raw" in out


def test_cli_blocks_public_target_without_authorization(capsys):
    code = main(["scan", "8.8.8.8", "--ports", "80"])
    err = capsys.readouterr().err
    assert code == AUTHORIZATION_DENIED
    assert "Authorization denied" in err


def test_unsupported_technique_returns_unsupported_code(capsys):
    code = main(["scan", "127.0.0.1", "--ports", "80", "--technique", "syn"])
    out = capsys.readouterr().out
    assert code == UNSUPPORTED
    assert "unsupported" in out.lower()


def test_config_command_outputs_defaults(capsys):
    code = main(["config", "--format", "json"])
    out = capsys.readouterr().out
    assert code == OK
    assert "timeout" in out
    assert "config_source" in out


def test_report_command_renders_saved_json(tmp_path, capsys):
    report_file = tmp_path / "scan.json"
    code = main(["scan", "127.0.0.1", "--ports", "9", "--output", str(report_file), "--format", "json"])
    assert code == OK
    capsys.readouterr()

    code = main(["report", str(report_file), "--format", "table"])
    out = capsys.readouterr().out
    assert code == OK
    assert "PORT" in out


def test_scan_output_to_unwritable_path_returns_error(capsys):
    bad = "this_dir_does_not_exist_psl/nested/report.json"
    code = main(["scan", "127.0.0.1", "--ports", "9", "--timeout", "0.2", "--output", bad])
    err = capsys.readouterr().err
    assert code == ERROR  # clean error, not a traceback
    assert "Error" in err


def test_top_and_ports_together_warns(capsys):
    code = main(["scan", "127.0.0.1", "--top", "5", "--ports", "80", "--timeout", "0.2"])
    err = capsys.readouterr().err
    assert code == OK
    assert "--ports is ignored" in err


def test_malformed_config_returns_usage(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "scan.toml"
    bad.write_text("not = = valid\n", encoding="utf-8")
    monkeypatch.setenv("PORTSLEUTH_CONFIG", str(bad))
    code = main(["doctor"])
    err = capsys.readouterr().err
    assert code == USAGE
    assert "Input error" in err


def test_benchmark_command_reports_three_techniques(capsys):
    code = main(["benchmark", "127.0.0.1", "--ports", "9-11", "--timeout", "0.2"])
    out = capsys.readouterr().out
    assert code == OK
    for technique in ("sync", "threaded", "asyncio"):
        assert technique in out
    assert "UNREACH" in out


def test_scan_with_error_result_returns_partial(monkeypatch, capsys):
    # A ScanState.ERROR result (unexpected failure) must surface as PARTIAL (exit 7).
    from portsleuth.models import PortResult, ScanState

    async def fake_scan_many(targets, ports, options, progress=None):
        return [
            PortResult(
                target="127.0.0.1",
                address="127.0.0.1",
                port=80,
                state=ScanState.ERROR,
                reason="unexpected error: boom",
                error="boom",
            )
        ]

    monkeypatch.setattr(main_mod, "scan_many", fake_scan_many)
    code = main(["scan", "127.0.0.1", "--ports", "80"])
    capsys.readouterr()
    assert code == PARTIAL


def test_report_grep_matches_live_scan_grep_schema(tmp_path, capsys):
    report_file = tmp_path / "scan.json"
    main(["scan", "127.0.0.1", "--ports", "9", "--timeout", "0.2", "--output", str(report_file), "--format", "json"])
    capsys.readouterr()

    main(["scan", "127.0.0.1", "--ports", "9", "--timeout", "0.2", "--format", "grep"])
    live = capsys.readouterr().out.strip()

    main(["report", str(report_file), "--format", "grep"])
    rerendered = capsys.readouterr().out.strip()

    # Same column count for both renderings (schema parity).
    assert len(live.split("\t")) == len(rerendered.split("\t"))

