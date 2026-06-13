"""Unit tests for resolve extended module in portsleuth CLI."""

from portsleuth.targets.resolve import resolve_expression, resolve_many, split_target_expression


def test_split_and_empty_expression():
    assert split_target_expression(" a , b ") == ["a", "b"]
    resolved = resolve_expression("  ")
    assert resolved.error == "empty target expression"


def test_resolve_cidr_single_address_network():
    resolved = resolve_expression("127.0.0.1/32")
    assert resolved.is_cidr is True
    assert len(resolved.targets) == 1


def test_resolve_cidr_too_large():
    resolved = resolve_expression("10.0.0.0/8", max_hosts=10)
    assert resolved.error is not None


def test_resolve_many_returns_list():
    assert len(resolve_many("127.0.0.1,::1")) >= 1
