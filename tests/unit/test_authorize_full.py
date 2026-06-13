"""Unit tests for authorize full module in portsleuth CLI."""

from portsleuth.exceptions import AuthorizationError
from portsleuth.models import Target
from portsleuth.targets.authorize import authorize_targets, enforce_authorization


def _target(**kwargs):
    defaults = dict(expression="x", address="10.0.0.1", is_loopback=False, is_private=True)
    defaults.update(kwargs)
    return Target(**defaults)


def test_authorize_empty_targets():
    decision = authorize_targets("x", [], is_cidr=False, authorized=False, reason=None)
    assert decision.allowed is False
    assert decision.category == "invalid"


def test_authorize_cidr_and_public_branches():
    cidr = authorize_targets("10.0.0.0/24", [_target()], is_cidr=True, authorized=False, reason=None)
    assert cidr.category == "cidr"
    cidr_ok = authorize_targets("10.0.0.0/24", [_target()], is_cidr=True, authorized=True, reason="lab")
    assert cidr_ok.requires_audit is True

    public = authorize_targets(
        "8.8.8.8",
        [_target(is_private=False, is_loopback=False, address="8.8.8.8")],
        is_cidr=False,
        authorized=False,
        reason=None,
    )
    assert public.category == "public"

    public_ok = authorize_targets(
        "8.8.8.8",
        [_target(is_private=False, is_loopback=False, address="8.8.8.8")],
        is_cidr=False,
        authorized=True,
        reason="owned",
    )
    assert public_ok.allowed is True


def test_authorize_private_requires_flag():
    decision = authorize_targets("10.0.0.1", [_target()], is_cidr=False, authorized=False, reason=None)
    assert decision.category == "private"
    ok = authorize_targets("10.0.0.1", [_target()], is_cidr=False, authorized=True, reason=None)
    assert ok.requires_audit is True


def test_enforce_authorization_raises():
    try:
        enforce_authorization("10.0.0.1", [_target()], is_cidr=False, authorized=False, reason=None)
    except AuthorizationError as exc:
        assert "10.0.0.1" in str(exc)
    else:
        raise AssertionError("expected AuthorizationError")
