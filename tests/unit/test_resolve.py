"""Unit tests for resolve module in portsleuth CLI."""

from portsleuth.models import Target
from portsleuth.targets.parse import _filter_family, build_target_plan
from portsleuth.targets.resolve import resolve_expression


def test_resolve_ip_literal():
    resolved = resolve_expression("127.0.0.1")
    assert resolved.error is None
    assert resolved.targets[0].address == "127.0.0.1"
    assert resolved.targets[0].is_loopback is True


def test_resolve_cidr_expands_hosts_with_per_ip_label():
    resolved = resolve_expression("127.0.0.0/30")
    assert resolved.is_cidr is True
    addresses = [t.address for t in resolved.targets]
    assert addresses == ["127.0.0.1", "127.0.0.2"]
    # Each target's expression is its own IP, not the CIDR string.
    assert resolved.targets[0].expression == "127.0.0.1"


def test_resolve_bad_cidr_reports_error():
    resolved = resolve_expression("10.0.0.0/99")
    assert resolved.error is not None


def test_filter_family_prefers_ipv4_but_keeps_ipv6_only():
    v4 = Target(expression="h", address="127.0.0.1", family="IPv4")
    v6 = Target(expression="h", address="::1", family="IPv6")
    assert _filter_family([v4, v6], "ipv4") == [v4]
    assert _filter_family([v4, v6], "ipv6") == [v6]
    assert _filter_family([v4, v6], "auto") == [v4, v6]
    # IPv6-only set is preserved even when ipv4 is requested.
    assert _filter_family([v6], "ipv4") == [v6]


def test_build_target_plan_defaults_to_ipv4_for_localhost():
    plan = build_target_plan("localhost")
    families = {t.family for t in plan.targets}
    assert families == {"IPv4"}
