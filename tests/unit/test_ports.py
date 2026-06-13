"""Unit tests for ports module in portsleuth CLI."""

from portsleuth.targets.ports import parse_ports


def test_parse_single_ranges_and_services():
    assert parse_ports("22,80,8000-8002,http") == [22, 80, 8000, 8001, 8002]


def test_parse_invalid_port_rejected():
    try:
        parse_ports("0")
    except ValueError as exc:
        assert "out of range" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_parse_malformed_range_gives_clear_error():
    try:
        parse_ports("80-")
    except ValueError as exc:
        assert "invalid port range" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_parse_out_of_range_end_rejected_before_expansion():
    try:
        parse_ports("1-99999")
    except ValueError as exc:
        assert "out of range" in str(exc)
    else:
        raise AssertionError("expected ValueError")

