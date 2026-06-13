"""Target resolution for portsleuth CLI."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

from portsleuth.config import DEFAULT_MAX_CIDR_HOSTS
from portsleuth.models import Target


@dataclass
class ResolvedExpression:
    expression: str
    targets: list[Target] = field(default_factory=list)
    is_cidr: bool = False
    error: str | None = None
    warning: str | None = None


def split_target_expression(expression: str) -> list[str]:
    return [part.strip() for part in expression.split(",") if part.strip()]


def resolve_expression(expression: str, max_hosts: int = DEFAULT_MAX_CIDR_HOSTS) -> ResolvedExpression:
    text = expression.strip()
    if not text:
        return ResolvedExpression(expression=expression, error="empty target expression")

    if "/" in text:
        return _resolve_cidr(text, max_hosts=max_hosts)

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return _resolve_hostname(text)

    return ResolvedExpression(expression=text, targets=[_target_from_ip(text, address)])


def resolve_many(expression: str, max_hosts: int = DEFAULT_MAX_CIDR_HOSTS) -> list[ResolvedExpression]:
    return [resolve_expression(part, max_hosts=max_hosts) for part in split_target_expression(expression)]


def _resolve_cidr(expression: str, max_hosts: int) -> ResolvedExpression:
    try:
        network = ipaddress.ip_network(expression, strict=False)
    except ValueError as exc:
        return ResolvedExpression(expression=expression, is_cidr=True, error=str(exc))

    addresses = list(network.hosts())
    if not addresses and network.num_addresses == 1:
        addresses = [network.network_address]
    if len(addresses) > max_hosts:
        return ResolvedExpression(
            expression=expression,
            is_cidr=True,
            error=f"CIDR expands to {len(addresses)} hosts; limit is {max_hosts}",
        )

    warning = f"CIDR scan expands to {len(addresses)} host(s)."
    return ResolvedExpression(
        expression=expression,
        targets=[_target_from_ip(str(address), address) for address in addresses],
        is_cidr=True,
        warning=warning,
    )


def _resolve_hostname(hostname: str) -> ResolvedExpression:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return ResolvedExpression(expression=hostname, error=f"DNS lookup failed: {exc}")

    targets: list[Target] = []
    seen: set[str] = set()
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        address_text = sockaddr[0]
        if address_text in seen:
            continue
        seen.add(address_text)
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            continue
        targets.append(_target_from_ip(hostname, address, hostname=hostname, family=family))

    targets.sort(key=lambda target: (target.family != "IPv4", target.address))
    if not targets:
        return ResolvedExpression(expression=hostname, error="DNS lookup returned no usable addresses")
    return ResolvedExpression(expression=hostname, targets=targets)


def _target_from_ip(
    expression: str,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    hostname: str | None = None,
    family: socket.AddressFamily | None = None,
) -> Target:
    if family is None:
        family_name = "IPv6" if address.version == 6 else "IPv4"
    else:
        family_name = "IPv6" if family == socket.AF_INET6 else "IPv4"
    return Target(
        expression=expression,
        hostname=hostname,
        address=str(address),
        family=family_name,
        is_loopback=address.is_loopback,
        is_private=address.is_private,
    )

