"""Authorization for portsleuth CLI."""

from __future__ import annotations

from dataclasses import dataclass

from portsleuth.exceptions import AuthorizationError
from portsleuth.models import Target


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    category: str
    message: str
    requires_audit: bool = False


def authorize_targets(
    expression: str,
    targets: list[Target],
    *,
    is_cidr: bool,
    authorized: bool,
    reason: str | None,
) -> AuthorizationDecision:
    clean_reason = (reason or "").strip()
    if not targets:
        return AuthorizationDecision(False, "invalid", "target did not resolve to any addresses")

    if is_cidr:
        if not authorized:
            return AuthorizationDecision(False, "cidr", "CIDR targets require --authorized")
        if not clean_reason:
            return AuthorizationDecision(False, "cidr", "CIDR targets require --reason")
        return AuthorizationDecision(True, "cidr", "authorized CIDR scan", requires_audit=True)

    if all(target.is_loopback for target in targets):
        return AuthorizationDecision(True, "loopback", "loopback target is allowed by default")

    if any(not target.is_private and not target.is_loopback for target in targets):
        if not authorized:
            return AuthorizationDecision(False, "public", "public targets require --authorized")
        if not clean_reason:
            return AuthorizationDecision(False, "public", "public targets require --reason")
        return AuthorizationDecision(True, "public", "authorized public target scan", requires_audit=True)

    if not authorized:
        return AuthorizationDecision(False, "private", "non-local private targets require --authorized")
    return AuthorizationDecision(True, "private", "authorized private target scan", requires_audit=True)


def enforce_authorization(
    expression: str,
    targets: list[Target],
    *,
    is_cidr: bool,
    authorized: bool,
    reason: str | None,
) -> AuthorizationDecision:
    decision = authorize_targets(
        expression,
        targets,
        is_cidr=is_cidr,
        authorized=authorized,
        reason=reason,
    )
    if not decision.allowed:
        raise AuthorizationError(f"{expression}: {decision.message}")
    return decision
