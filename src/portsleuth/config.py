"""Configuration for portsleuth CLI."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from portsleuth import __version__

DEFAULT_TARGET = "127.0.0.1"
DEFAULT_TIMEOUT = 0.75
DEFAULT_CONCURRENCY = 100
DEFAULT_RATE_LIMIT = 200.0
DEFAULT_AUDIT_FILE = ".portsleuth/audit.jsonl"
DEFAULT_MAX_CIDR_HOSTS = 256
USER_AGENT = f"portsleuth/{__version__}"

#: Config file looked up in the working directory (override with PORTSLEUTH_CONFIG).
CONFIG_FILENAME = "scan.toml"


@dataclass
class Settings:
    """Effective default settings, overlaid from scan.toml if present.

    CLI flags take precedence over these; these take precedence over the
    built-in DEFAULT_* constants.
    """

    target: str = DEFAULT_TARGET
    timeout: float = DEFAULT_TIMEOUT
    concurrency: int = DEFAULT_CONCURRENCY
    rate_limit: float = DEFAULT_RATE_LIMIT
    audit_file: str = DEFAULT_AUDIT_FILE
    max_cidr_hosts: int = DEFAULT_MAX_CIDR_HOSTS
    source: str | None = None  # path of the loaded config file, if any


# toml key -> (Settings attribute, coercer, validator)
# Validators reject out-of-range values; coercers also reject booleans for
# numeric fields (TOML true/false would otherwise coerce silently to 1/0).
def _positive(value: float) -> bool:
    return value > 0


def _non_negative(value: float) -> bool:
    return value >= 0


def _at_least_one(value: int) -> bool:
    return value >= 1


def _non_empty(value: str) -> bool:
    return bool(value.strip())


_CONFIG_KEYS = {
    "target": ("target", str, _non_empty),
    "timeout": ("timeout", float, _positive),
    "concurrency": ("concurrency", int, _at_least_one),
    "rate": ("rate_limit", float, _non_negative),
    "rate_limit": ("rate_limit", float, _non_negative),
    "audit_file": ("audit_file", str, _non_empty),
    "max_hosts": ("max_cidr_hosts", int, _at_least_one),
    "max_cidr_hosts": ("max_cidr_hosts", int, _at_least_one),
}


def load_settings(path: str | os.PathLike[str] | None = None) -> Settings:
    """Load settings from scan.toml (a ``[defaults]`` table or top-level keys).

    Returns built-in defaults when no file is present. Raises ValueError on a
    malformed file or bad value so the CLI can report it cleanly.
    """
    if path is not None:
        candidate = Path(path)
    else:
        candidate = Path(os.environ.get("PORTSLEUTH_CONFIG", CONFIG_FILENAME))

    settings = Settings()
    if not candidate.is_file():
        return settings

    try:
        # utf-8-sig tolerates an editor-added BOM, which tomllib otherwise rejects.
        text = candidate.read_text(encoding="utf-8-sig")
        data = tomllib.loads(text)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid {candidate}: {exc}") from exc

    table = data.get("defaults", data)
    if not isinstance(table, dict):
        raise ValueError(f"invalid {candidate}: 'defaults' must be a table")

    for key, (attr, coerce, is_valid) in _CONFIG_KEYS.items():
        if key not in table:
            continue
        raw = table[key]
        # A TOML boolean would coerce to 0/1 for numeric fields; reject it.
        if coerce is not str and isinstance(raw, bool):
            raise ValueError(f"invalid value for '{key}' in {candidate}: expected a number, got a boolean")
        try:
            value = coerce(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid value for '{key}' in {candidate}: {exc}") from exc
        if not is_valid(value):
            raise ValueError(f"invalid value for '{key}' in {candidate}: out of range ({value!r})")
        setattr(settings, attr, value)

    settings.source = str(candidate)
    return settings

COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    514: "syslog",
    515: "printer",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "dev-http",
    3306: "mysql",
    3389: "rdp",
    5000: "dev-http",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    9000: "app",
    9090: "app",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}

TOP_PORTS = list(COMMON_PORTS.keys())

HTTP_LIKE_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888}
HTTPS_LIKE_PORTS = {443, 8443, 9443}

