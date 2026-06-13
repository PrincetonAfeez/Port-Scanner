"""Target sorting for portsleuth CLI."""

from __future__ import annotations

import ipaddress


def address_sort_key(address: str) -> tuple[int, int]:
    """Sort numerically by IP, grouping by address family first."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return (0, 0)
    return (ip.version, int(ip))
