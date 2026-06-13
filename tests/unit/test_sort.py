"""Unit tests for sort module in portsleuth CLI."""

from portsleuth.targets.sort import address_sort_key


def test_address_sort_key_ipv4_and_ipv6():
    assert address_sort_key("10.0.0.2") > address_sort_key("10.0.0.1")
    assert address_sort_key("::1")[0] == 6
    assert address_sort_key("not-an-ip") == (0, 0)
