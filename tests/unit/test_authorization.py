"""Unit tests for authorization module in portsleuth CLI."""

from portsleuth.exceptions import AuthorizationError
from portsleuth.targets.parse import build_target_plan


def test_loopback_allowed_without_flag():
    plan = build_target_plan("127.0.0.1")
    assert plan.targets[0].is_loopback is True
    assert plan.requires_audit is False


def test_private_target_requires_authorization():
    try:
        build_target_plan("192.168.1.10")
    except AuthorizationError as exc:
        assert "--authorized" in str(exc)
    else:
        raise AssertionError("expected AuthorizationError")


def test_cidr_requires_reason_after_authorization():
    try:
        build_target_plan("127.0.0.0/30", authorized=True)
    except AuthorizationError as exc:
        assert "--reason" in str(exc)
    else:
        raise AssertionError("expected AuthorizationError")

