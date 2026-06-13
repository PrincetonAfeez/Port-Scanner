"""Integration tests for portsleuth CLI."""

import json

from portsleuth.cli.exit_codes import OK, PRIVILEGE
from portsleuth.cli.main import main
from portsleuth.cli.output import format_http_probe_batch
from portsleuth.models import HTTPProbeResult, ProbeState


def test_packet_demo_command(capsys):
    code = main(["packet", "demo"])
    out = capsys.readouterr().out
    assert code == OK
    assert "IPv4 header" in out
    assert "TCP SYN header" in out


def test_doctor_require_raw_returns_privilege_when_unavailable(capsys):
    code = main(["doctor", "--require-raw"])
    capsys.readouterr()
    assert code in {OK, PRIVILEGE}


def test_probe_http_json_batch_is_valid_json(capsys):
    result = HTTPProbeResult(state=ProbeState.NO_RESPONSE, method="HEAD", path="/")
    text = format_http_probe_batch([("127.0.0.1", "127.0.0.1", result)], "json")
    data = json.loads(text)
    assert isinstance(data, list)
    assert data[0]["target"] == "127.0.0.1"
    assert data[0]["address"] == "127.0.0.1"


def test_probe_http_rejects_invalid_port(capsys):
    code = main(["probe", "http", "127.0.0.1", "--port", "0", "--timeout", "0.2"])
    err = capsys.readouterr().err
    assert code == 2  # USAGE
    assert "Input error" in err


def test_report_rejects_invalid_state_in_file(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "target_expression": "127.0.0.1",
                "ports": [80],
                "options": {
                    "timeout": 0.75,
                    "concurrency": 100,
                    "rate_limit": 200.0,
                    "technique": "connect",
                },
                "results": [
                    {
                        "target": "127.0.0.1",
                        "address": "127.0.0.1",
                        "port": 80,
                        "state": "bogus",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    from portsleuth.cli.exit_codes import ERROR

    code = main(["report", str(bad)])
    err = capsys.readouterr().err
    assert code == ERROR
    assert "Invalid report file" in err
