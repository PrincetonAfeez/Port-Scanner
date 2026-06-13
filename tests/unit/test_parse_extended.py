"""Unit tests for parse extended module in portsleuth CLI."""

import pytest

from portsleuth.exceptions import TargetResolutionError
from portsleuth.targets.parse import authorization_summary_from_plan, build_target_plan


def test_build_target_plan_family_auto_and_ipv6():
    plan = build_target_plan("127.0.0.1", family="auto")
    assert plan.targets

    plan6 = build_target_plan("::1", family="ipv6")
    assert plan6.targets[0].family == "IPv6"


def test_build_target_plan_cidr_with_audit():
    plan = build_target_plan("127.0.0.0/30", authorized=True, reason="lab cidr")
    assert plan.requires_audit is True
    assert plan.targets


def test_build_target_plan_all_dns_failures_raises():
    with pytest.raises(TargetResolutionError, match="all targets failed"):
        build_target_plan("bad.invalid,also.invalid", family="ipv4")


def test_authorization_summary_from_plan():
    plan = build_target_plan("127.0.0.1")
    summary = authorization_summary_from_plan(plan, authorized=False, reason=None)
    assert summary.categories == ["loopback"]
    assert summary.requires_audit is False
