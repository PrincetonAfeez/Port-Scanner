"""Unit tests for ports validation extended module in portsleuth CLI."""

import pytest

from portsleuth.cli.validation import (
    validate_concurrency,
    validate_max_hosts,
    validate_probe_port,
    validate_rate,
    validate_scan_tuning,
    validate_timeout,
)
from portsleuth.targets.ports import parse_ports


def test_validation_helpers_reject_bad_values():
    with pytest.raises(ValueError):
        validate_timeout(0)
    with pytest.raises(ValueError):
        validate_concurrency(0)
    with pytest.raises(ValueError):
        validate_rate(-1)
    with pytest.raises(ValueError):
        validate_max_hosts(0)
    with pytest.raises(ValueError):
        validate_probe_port(0)


def test_validate_scan_tuning_accepts_zero_rate():
    validate_scan_tuning(timeout=0.5, concurrency=1, rate=0, max_hosts=10)


def test_parse_ports_service_name_and_errors():
    assert 80 in parse_ports("http")
    with pytest.raises(ValueError, match="unknown service"):
        parse_ports("nosuchservice")
    with pytest.raises(ValueError, match="no ports"):
        parse_ports(",,")
    with pytest.raises(ValueError, match="--top"):
        parse_ports(None, top=0)
