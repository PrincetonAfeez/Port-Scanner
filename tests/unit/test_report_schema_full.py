"""Unit tests for report schema full module in portsleuth CLI."""

import pytest

from portsleuth.cli.report_schema import validate_report_data


def _minimal(**overrides):
    base = {
        "target_expression": "127.0.0.1",
        "ports": [80],
        "options": {
            "timeout": 0.75,
            "concurrency": 100,
            "rate_limit": 0,
            "technique": "connect",
            "probe": False,
            "probe_insecure": False,
        },
        "results": [
            {
                "target": "127.0.0.1",
                "address": "127.0.0.1",
                "port": 80,
                "state": "closed",
            }
        ],
    }
    base.update(overrides)
    return base


def test_rejects_non_object_root():
    with pytest.raises(ValueError, match="report root must be a JSON object"):
        validate_report_data([])


def test_rejects_bad_ports_list_and_entries():
    with pytest.raises(ValueError, match="'ports' must be a list"):
        validate_report_data(_minimal(ports="80"))
    with pytest.raises(ValueError, match="ports\\[0\\]"):
        validate_report_data(_minimal(ports=[0]))


def test_rejects_bad_options():
    data = _minimal()
    data["options"] = "bad"
    with pytest.raises(ValueError, match="'options' must be an object"):
        validate_report_data(data)

    data = _minimal()
    data["options"]["timeout"] = 0
    with pytest.raises(ValueError, match="options.timeout"):
        validate_report_data(data)

    data = _minimal()
    data["options"]["rate_limit"] = -1
    with pytest.raises(ValueError, match="options.rate_limit"):
        validate_report_data(data)

    data = _minimal()
    data["options"]["concurrency"] = 0
    with pytest.raises(ValueError, match="options.concurrency"):
        validate_report_data(data)

    data = _minimal()
    data["options"]["technique"] = "nmap"
    with pytest.raises(ValueError, match="options.technique"):
        validate_report_data(data)

    data = _minimal()
    data["options"]["probe"] = "yes"
    with pytest.raises(ValueError, match="options.probe"):
        validate_report_data(data)


def test_rejects_bad_authorization_summary():
    data = _minimal(authorization_summary={"authorized": "no"})
    with pytest.raises(ValueError, match="authorization_summary.authorized"):
        validate_report_data(data)


def test_rejects_bad_results_and_nested_probes():
    data = _minimal(results=["bad"])
    with pytest.raises(ValueError, match="results\\[0\\] must be an object"):
        validate_report_data(data)

    data = _minimal()
    data["results"][0]["port"] = 70000
    with pytest.raises(ValueError, match="results\\[0\\].port"):
        validate_report_data(data)

    data = _minimal()
    data["results"][0]["state"] = "bogus"
    with pytest.raises(ValueError, match="state must be a known scan state"):
        validate_report_data(data)

    data = _minimal()
    data["results"][0]["http"] = {"state": "bad", "method": "HEAD", "path": "/"}
    with pytest.raises(ValueError, match="http.state"):
        validate_report_data(data)

    data = _minimal()
    data["results"][0]["http"] = {
        "state": "http_detected",
        "method": "HEAD",
        "path": "/",
        "http_version": 1,
    }
    with pytest.raises(ValueError, match="http_version"):
        validate_report_data(data)

    data = _minimal()
    data["results"][0]["tls"] = {"ok": "maybe"}
    with pytest.raises(ValueError, match="tls.ok"):
        validate_report_data(data)


def test_accepts_valid_nested_probes():
    data = _minimal()
    data["results"][0]["http"] = {
        "state": "http_detected",
        "method": "HEAD",
        "path": "/",
        "http_version": "HTTP/1.1",
    }
    data["results"][0]["tls"] = {"ok": False, "error": "nope"}
    validate_report_data(data)
