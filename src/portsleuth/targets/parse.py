"""Target parsing for portsleuth CLI."""

from __future__ import annotations

from dataclasses import dataclass, field

from portsleuth.exceptions import TargetResolutionError
from portsleuth.models import AuthorizationSummary, Target
from portsleuth.targets.authorize import AuthorizationDecision, enforce_authorization
from portsleuth.targets.resolve import resolve_many, split_target_expression


@dataclass
class TargetPlan:
    targets: list[Target]
    decisions: list[AuthorizationDecision] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dns_failures: list[tuple[str, str]] = field(default_factory=list)
    requires_audit: bool = False


def authorization_summary_from_plan(
    plan: TargetPlan,
    *,
    authorized: bool,
    reason: str | None,
) -> AuthorizationSummary:
    return AuthorizationSummary(
        authorized=authorized,
        reason=reason,
        requires_audit=plan.requires_audit,
        categories=sorted({decision.category for decision in plan.decisions}),
    )


def build_target_plan(
    expression: str,
    *,
    authorized: bool = False,
    reason: str | None = None,
    max_hosts: int = 256,
    family: str = "ipv4",
) -> TargetPlan:
    targets: list[Target] = []
    decisions: list[AuthorizationDecision] = []
    warnings: list[str] = []
    dns_failures: list[tuple[str, str]] = []
    requires_audit = False
    multi_target = len(split_target_expression(expression)) > 1

    for resolved in resolve_many(expression, max_hosts=max_hosts):
        if resolved.error:
            if multi_target:
                dns_failures.append((resolved.expression, resolved.error))
                warnings.append(f"skipped {resolved.expression}: {resolved.error}")
                continue
            raise TargetResolutionError(f"{resolved.expression}: {resolved.error}")
        selected = _filter_family(resolved.targets, family)
        decision = enforce_authorization(
            resolved.expression,
            selected,
            is_cidr=resolved.is_cidr,
            authorized=authorized,
            reason=reason,
        )
        decisions.append(decision)
        requires_audit = requires_audit or decision.requires_audit
        if resolved.warning:
            warnings.append(resolved.warning)
        targets.extend(selected)

    if not targets:
        if dns_failures:
            raise TargetResolutionError(f"all targets failed DNS resolution: {dns_failures[0][1]}")
        raise TargetResolutionError("no targets were resolved")
    return TargetPlan(
        targets=targets,
        decisions=decisions,
        warnings=warnings,
        dns_failures=dns_failures,
        requires_audit=requires_audit,
    )


def _filter_family(targets: list[Target], family: str) -> list[Target]:
    """Restrict resolved targets to one address family.

    Default is IPv4 (the portable core). If the filter would drop every target
    (e.g. an explicit IPv6 literal or an IPv6-only host), the originals are kept
    so the user's explicit choice is respected.
    """
    if family == "auto" or not targets:
        return targets
    want = "IPv6" if family == "ipv6" else "IPv4"
    filtered = [target for target in targets if target.family == want]
    return filtered or targets

