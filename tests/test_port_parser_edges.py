"""Parser edge-case tests for ``portsleuth.targets.ports.parse_ports``.

Additional parser coverage also lives in:
- ``tests/unit/test_ports.py`` (ranges, malformed ranges, out-of-range expansion)
- ``tests/unit/test_ports_validation_extended.py`` (service names, empty commas, --top)
"""

import pytest

from portsleuth.targets.ports import parse_ports


def test_parse_ports_rejects_empty_comma_input():
    with pytest.raises(ValueError, match="no ports were parsed"):
        parse_ports(",")


@pytest.mark.parametrize(
    "spec",
    [
        "0",
        "65536",
        "80-0",
        "70000-70001",
        "abc-not-a-service",
    ],
)
def test_parse_ports_rejects_invalid_specs(spec):
    with pytest.raises(ValueError):
        parse_ports(spec)


def test_parse_ports_accepts_single_port_range_and_dedupes():
    assert parse_ports("80,80,81-82") == [80, 81, 82]


def test_parse_ports_rejects_invalid_top_value():
    with pytest.raises(ValueError, match="--top must be greater than zero"):
        parse_ports(None, top=0)


def test_parse_ports_accepts_service_names():
    assert 80 in parse_ports("http")
