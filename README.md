# portsleuth

`portsleuth` is a safe educational Python CLI port scanner for a Networking and Protocols capstone. It focuses on the portable core first: DNS resolution, authorization, asyncio TCP connect scanning, rate limiting, local lab services, raw HTTP probing, WSGI demonstration, structured output, and packet header/checksum evidence.

It is not an `nmap` clone and does not include stealth, evasion, spoofing, IDS bypass, credential attacks, or exploit checks.

## Quick Start

From this folder:

```powershell
python -m pip install -e .
portsleuth doctor
portsleuth scan 127.0.0.1 --ports 9089-9091
```

The default scan ports above are empty unless something is listening. To see an
open port, start a lab fixture first (see the Demo Script below) or scan a port
you know is in use.

Without installing, use:

```powershell
$env:PYTHONPATH="src"
python -m portsleuth doctor
```

Optional extra for inspecting certificate fields of self-signed lab targets
(`probe tls --insecure`); the verified path and everything else need no extras:

```powershell
python -m pip install -e ".[tls]"
```

## Core Commands

```powershell
portsleuth scan 127.0.0.1 --ports 8000-8010
portsleuth scan 127.0.0.1 --ports 80,443,8080 --format json
portsleuth scan 127.0.0.1 --ports 9090 --probe
portsleuth probe http 127.0.0.1 --port 8080 --show-preview
portsleuth probe tls example.com --port 443 --authorized --reason "owned test target"
portsleuth discover 127.0.0.1 --authorized --reason "lab sweep"
portsleuth lab serve-tcp --port 9090 --banner "portsleuth fixture"
portsleuth lab serve-wsgi --port 8080
portsleuth benchmark 127.0.0.1 --ports 1-1000
portsleuth report scan-report.json --format table
portsleuth config
```

`--probe` may also be written as `--banner`, and `--format grep` is an alias for
`grepable`. TLS probes verify certificates by default; pass `--insecure` for
self-signed lab targets. Hostnames that resolve to both IPv4 and IPv6 default to
IPv4 (the portable core); use `--family ipv6` or `--family auto` to change that.
With `--family auto`, dual-stack hostnames produce one result row per address.
`--top N` selects the first N ports from a curated static list (not an nmap
frequency ranking). `scan --probe-insecure` skips TLS verification during
`--probe` on HTTPS ports; standalone `probe tls` uses `--insecure` the same way.
`portsleuth --version` prints the version; `--verbose` raises diagnostics on
stderr to INFO. Scan results go to stdout; warnings and errors go to stderr.

Meaningful exit codes: `0` success, `1` general error, `2` invalid usage,
`3` authorization denied, `4` target resolution failure, `5` unsupported
technique/platform, `6` insufficient privileges (`doctor --require-raw` when
raw sockets are unavailable), `7` partial scan failure (error, permission denied,
unknown, or unreachable port results), `8` lab startup failure,
`130` interrupted (partial results are written when available; exit `7` instead when
partial results include error, permission denied, unknown, or unreachable states).

## Configuration

Defaults can be overridden with a `scan.toml` file in the working directory (or
the path in `PORTSLEUTH_CONFIG`). Command-line flags always win over the file,
which wins over the built-in defaults. Copy `scan.toml.example` to `scan.toml` to
start, and run `portsleuth config` to see the effective values and which source
they came from.

```toml
[defaults]
timeout = 0.75
concurrency = 100
rate = 200.0
```

## Safety Model

All targets pass through an authorization gate before any scan begins.

- Loopback targets are allowed by default.
- Non-local private targets require `--authorized`.
- Public targets require `--authorized` and `--reason`.
- CIDR ranges require `--authorized` and `--reason` (including loopback CIDRs
  such as `127.0.0.0/30`, which still require the flags and write an audit record).
- Scans that pass the gate for a private, public, or CIDR target write an audit
  record to `.portsleuth/audit.jsonl` (path is relative to the current directory;
  override with `--audit-file`). Single loopback targets do not write audit records.
  The same audit trail applies to `discover`, `benchmark`, and authorized `probe`
  commands.

Example authorized local-lab scan:

```powershell
portsleuth scan 192.168.1.10 --ports 22,80,443 --authorized --reason "home lab"
```

## What The Scanner Demonstrates

- DNS resolution from hostnames to socket addresses.
- TCP connect scanning with open, closed, filtered, unreachable, and unknown classification.
- `asyncio` concurrency with a semaphore and token-bucket rate limiter.
- Conservative timeouts to avoid hanging on silent hosts.
- Hand-written HTTP request bytes over TCP.
- HTTP status-line and header parsing.
- TLS handshake inspection with certificate subject, issuer, validity dates, and SANs.
- TCP-ping host discovery (`portsleuth discover`) for hosts that drop ICMP.
- WSGI as a Python application interface, demonstrated through `wsgiref.simple_server`.
- Platform-aware raw socket capability checks through `portsleuth doctor`.
- Packet-level knowledge through IPv4, TCP, UDP, ICMP, and checksum modules.

## Implemented vs planned

| Area | Status |
|------|--------|
| TCP connect scanner, asyncio engine, rate limit | Implemented |
| Authorization gate, audit JSONL (Unix fcntl lock; in-process lock on Windows) | Implemented |
| HTTP/TLS probing, WSGI lab, TCP-ping discovery | Implemented |
| Packet header pack/unpack evidence (`portsleuth packet demo`) | Implemented |
| Raw SYN scan, UDP scan, ICMP sweep | Planned (capability-gated; see ADRs) |
| `classify.py` / dedicated async engine module | Absorbed into `scan/connect.py` + `scan/classify.py` |
| Django dashboard, nmap comparison | Stretch / out of scope |

See `docs/adr/` for design decisions.

## Demo Script

Terminal 1:

```powershell
portsleuth lab serve-tcp --port 9090 --banner "portsleuth fixture"
```

Terminal 2:

```powershell
portsleuth scan 127.0.0.1 --ports 9089-9091 --probe
```

Terminal 3:

```powershell
portsleuth lab serve-wsgi --port 8080
```

Terminal 4:

```powershell
portsleuth probe http 127.0.0.1 --port 8080 --show-preview
portsleuth benchmark 127.0.0.1 --ports 1-100
```

## Platform Notes

The dependable scanner is the TCP connect scanner, which uses normal sockets and works without special privileges on typical Windows, macOS, Linux, and WSL setups.

Raw packet behavior differs by OS. `portsleuth doctor` reports whether raw ICMP and raw TCP sockets can be created. The packet header modules are included as protocol evidence; raw SYN scanning is intentionally reported as unsupported by the portable scanner path unless a future privileged implementation is added.

## Development

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
python -m ruff check src tests
```

The integration tests only use loopback fixtures and do not scan public hosts.
Privileged raw-socket tests live in `tests/privileged/` and only run when
`PORTSLEUTH_PRIVILEGED_TESTS=1` is set and the platform supports raw sockets.

## Production Reflection

A production scanner would need stronger IPv6 support, richer fingerprinting, resumable jobs, durable report storage, RBAC, signed scan policies, enterprise allowlists, deeper UDP retry policy, robust cancellation, and systematic comparison against mature tools in a controlled lab.

The audit log appends newline-delimited JSON with `fcntl` file locking on Unix and
an in-process lock on Windows, which is adequate for single-operator local use; a
production build would use a database or centralized logging so concurrent scans
on every platform are serialized safely.

## License

MIT — see [LICENSE](LICENSE).

