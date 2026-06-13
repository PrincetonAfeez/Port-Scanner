"""Unit tests for validation module in portsleuth CLI."""

import pytest

from portsleuth.cli.validation import (
    validate_concurrency,
    validate_rate,
    validate_scan_tuning,
    validate_timeout,
)


def test_validate_timeout_rejects_zero():
    with pytest.raises(ValueError, match="greater than zero"):
        validate_timeout(0)


def test_validate_concurrency_rejects_zero():
    with pytest.raises(ValueError, match="at least 1"):
        validate_concurrency(0)


def test_validate_rate_rejects_negative():
    with pytest.raises(ValueError, match="zero or greater"):
        validate_rate(-1)


def test_validate_scan_tuning_accepts_defaults():
    validate_scan_tuning(timeout=0.75, concurrency=100, rate=200.0, max_hosts=256)


def test_validate_probe_port_rejects_out_of_range():
    from portsleuth.cli.validation import validate_probe_port

    with pytest.raises(ValueError, match="port out of range"):
        validate_probe_port(0)
