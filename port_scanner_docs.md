# Architecture Decision Record
## App — Port Scanner
**Network Reconnaissance Group | Document 1 of 5**
**Status: Accepted**

---

## Context

The Network Reconnaissance group requires a safe educational Python port scanner for a Networking and Protocols capstone. The scanner must demonstrate DNS resolution, target parsing, authorization policy, TCP connect scanning, asyncio concurrency, rate limiting, HTTP/TLS/banner probing, TCP-ping discovery, lab fixture services, structured output, packet-header evidence, and platform capability checks.

The project is intentionally **not** an `nmap` clone. It does not implement stealth scans, evasion, spoofing, IDS bypass, credential attacks, vulnerability detection, or exploit checks. The design must support legitimate learning and local-lab usage first.

The selected architecture is a CLI-first Python package named `portsleuth` with a portable TCP connect scanner as the core. Privileged or platform-dependent techniques such as raw SYN and UDP scanning are represented in the interface and packet-evidence modules, but they report as unsupported in the portable scan path until a future capability-gated implementation is added.

---

## Decisions

### Decision 1 — Make TCP connect scanning the portable core

**Chosen:** Implement scanning with `asyncio.open_connection()` and TCP connect semantics.

**Rejected:** Raw SYN scan as the default engine.

**Reason:** TCP connect scanning works without root/admin privileges and behaves consistently across platforms. Raw SYN behavior varies by OS, privilege level, and firewall rules. The scanner can teach protocol boundaries without encouraging stealth or privileged scanning.

---

### Decision 2 — Safety gate every target before scanning

**Chosen:** All scans go through a target authorization gate.

Rules:
- single loopback targets are allowed by default
- non-local private targets require `--authorized`
- public targets require `--authorized` and `--reason`
- CIDR ranges require `--authorized` and `--reason`
- authorized private/public/CIDR scans write an audit record

**Rejected:** Allowing arbitrary target scans by default.

**Reason:** Port scanning can affect systems the user does not own. The app must demonstrate professional safety controls as part of the capstone.

---

### Decision 3 — Use JSONL audit records for non-loopback / CIDR scans

**Chosen:** Authorized scans that require an audit append newline-delimited JSON to `.portsleuth/audit.jsonl` by default.

**Rejected:** No audit trail or console-only consent.

**Reason:** Authorization should leave evidence. JSONL is simple, append-friendly, readable, and scriptable. The implementation uses process-level locking and Unix `fcntl` locking where available.

---

### Decision 4 — Resolve targets before authorization

**Chosen:** Convert hostnames, IP literals, comma-lists, and CIDR expressions into `Target` objects before policy enforcement.

**Rejected:** Authorizing raw strings only.

**Reason:** Policy depends on what the target resolves to. A hostname could resolve to public, private, loopback, IPv4, or IPv6 addresses. The scanner must classify real socket destinations, not just text input.

---

### Decision 5 — Default to IPv4 for hostname results

**Chosen:** Hostnames that resolve to both IPv4 and IPv6 default to IPv4. Users may choose `--family ipv6` or `--family auto`.

**Rejected:** Always scanning every resolved address.

**Reason:** IPv4 is the most portable local-lab default. Auto mode is still available when the user intentionally wants every address row.

---

### Decision 6 — Use an asyncio semaphore plus token bucket

**Chosen:** Concurrent scans run under a semaphore, and optional pacing uses an `AsyncTokenBucket`.

**Rejected:** Launching one connection attempt per port without coordination.

**Reason:** Concurrency is useful for speed, but uncontrolled scans are noisy and resource-heavy. The semaphore controls simultaneous sockets; the token bucket controls attempt rate.

---

### Decision 7 — Cap concurrency based on target/port volume

**Chosen:** Requested concurrency is capped through a file-descriptor safety layer.

**Rejected:** Trusting any arbitrary `--concurrency` value.

**Reason:** Local scans can exhaust open file descriptors. The scanner should protect the user’s machine while still demonstrating high-concurrency asyncio.

---

### Decision 8 — Preserve unsupported techniques explicitly

**Chosen:** `syn` and `udp` are accepted technique names but return `unsupported` results in the portable core.

**Rejected:** Hiding planned techniques entirely or half-implementing them.

**Reason:** This allows the CLI and documentation to discuss raw packet techniques honestly while avoiding unsafe or incomplete behavior.

---

### Decision 9 — Probe only after an open TCP connection

**Chosen:** Optional `--probe` attaches HTTP/TLS/banner evidence to open-port results.

**Rejected:** Probing every port regardless of connect result.

**Reason:** Probing is extra network activity. It should only happen when a TCP service is reachable.

---

### Decision 10 — Implement HTTP probes by writing bytes manually

**Chosen:** HTTP probes build raw `HEAD` / `GET` request bytes and parse the status line and headers.

**Rejected:** Using `requests` or `http.client` for probe behavior.

**Reason:** This capstone is about networking and protocols. The hand-built HTTP probe makes the request/response boundary visible.

---

### Decision 11 — Keep TLS verification on by default

**Chosen:** TLS probes verify certificates by default. `--insecure` exists for self-signed lab targets.

**Rejected:** Always disabling certificate validation.

**Reason:** Safe defaults matter. The educational path can still inspect self-signed lab certificates, but bypassing verification must be explicit.

---

### Decision 12 — Include local lab fixture servers

**Chosen:** Ship TCP, UDP, and WSGI lab servers.

**Rejected:** Requiring public targets for demos.

**Reason:** The scanner should be demonstrable against controlled loopback services. Fixtures make tests and demos reproducible without scanning third-party infrastructure.

---

### Decision 13 — Add TCP-ping discovery instead of ICMP sweep

**Chosen:** Host discovery uses TCP connection/refusal behavior on common service ports.

**Rejected:** Default ICMP sweep.

**Reason:** ICMP often requires privilege or is blocked. TCP-ping shows host liveness using normal sockets and remains portable.

---

### Decision 14 — Keep output structured and re-renderable

**Chosen:** `ScanReport`, `PortResult`, and probe results serialize to dictionaries used by JSON, table, grepable, and report re-rendering.

**Rejected:** Printing ad hoc text only.

**Reason:** Scans are operational evidence. Users should be able to save, validate, and re-render results.

---

### Decision 15 — Include packet header/checksum evidence separately

**Chosen:** Provide packet demo functionality to show protocol-header understanding while keeping raw packet scanning out of the default path.

**Rejected:** Combining packet demo with actual privileged scanning.

**Reason:** The capstone can demonstrate IPv4/TCP/UDP/ICMP knowledge without shipping stealthy or platform-fragile scan behavior.

---

## Consequences

**Positive:**
- The default scanner is portable and low-risk.
- Safety policy is visible and enforceable.
- Audit records demonstrate responsible operator behavior.
- Asyncio concurrency is real, not simulated.
- HTTP/TLS/banner probes provide protocol evidence.
- Local fixtures allow repeatable demos.
- Structured reports support JSON and re-rendering.
- Unsupported raw techniques are documented honestly.
- The CLI exit-code contract supports scripting.

**Negative / Trade-offs:**
- It is slower and less feature-rich than mature scanners.
- TCP connect scans can be logged by target systems.
- No stealth, SYN, UDP, service-version database, OS fingerprinting, exploit checks, or evasive behavior.
- TLS certificate extraction is richer only when optional dependencies are installed.
- IPv6 support exists but is not the default.
- JSONL audit is adequate for a local operator, not enterprise governance.
- Discovery is TCP-based, not ICMP-based.

---

## Alternatives Not Explored

- Raw SYN scanning as the default engine.
- UDP scanning with retry/open-filtered heuristics.
- ICMP echo sweep.
- OS fingerprinting.
- Service fingerprint databases.
- Nmap compatibility layer.
- Distributed/resumable scan jobs.
- Django dashboard.
- Persistent report database.
- RBAC, signed scan policies, or enterprise allowlists.
- Packet capture integration as a core dependency.

---

*Constitution reference: Article 1 (Python fundamentals and architectural thinking), Article 3.3 (scope discipline), Article 4 (quality proportional to scope), Article 5 (trade-off documentation), Article 6 (verification), and Article 7 (progressive complexity).*

---


# Technical Design Document
## App — Port Scanner
**Network Reconnaissance Group | Document 2 of 5**

---

## Overview

Port Scanner is a Python CLI package named `portsleuth`. It provides a safe educational TCP connect scanner with target authorization, asyncio concurrency, rate limiting, DNS resolution, host discovery, HTTP/TLS/banner probing, local lab fixtures, packet-header evidence, and report rendering.

**Package:** `portsleuth`  
**Console script:** `portsleuth`  
**Python:** `>=3.11`  
**Runtime dependencies:** none  
**Optional TLS extra:** `cryptography` for self-signed certificate field extraction  
**Dev tools:** pytest, pytest-cov, ruff  
**Primary command:** `portsleuth scan`

---

## System Context

```text
CLI
  │
  ▼
load_settings()
  │
  ▼
argparse command handler
  │
  ├── parse ports / top ports
  ├── validate tuning
  ├── resolve target expression
  ├── enforce authorization
  ├── write audit if required
  └── dispatch command
        │
        ├── scan → asyncio TCP connect scanner
        ├── discover → TCP-ping sweep
        ├── probe http/tls/banner
        ├── lab serve-tcp/serve-wsgi/serve-udp
        ├── packet demo
        ├── doctor
        ├── benchmark
        ├── report
        └── config
```

---

## Main Package Areas

```text
src/portsleuth/
  __init__.py
  capabilities.py
  config.py
  exceptions.py
  models.py

  cli/
    main.py
    exit_codes.py
    output.py
    packet_demo.py
    report_schema.py
    validation.py

  concurrency/
    rate_limit.py
    benchmark.py

  discovery/
    tcp_ping.py

  fingerprint/
    banner.py
    http_parse.py
    http_probe.py
    services.py
    tls.py

  lab/
    fixture_tcp.py
    fixture_udp.py
    fixture_wsgiref.py

  observability/
    audit.py

  packets/
    packet demo/header evidence modules

  scan/
    classify.py
    connect.py
    fd_limit.py

  targets/
    authorize.py
    parse.py
    ports.py
    resolve.py
    sort.py
```

---

## Data Flow: Scan Command

```text
portsleuth scan TARGET --ports SPEC
  │
  ▼
load_settings()
  │
  ▼
parse_ports()
  │
  ├── --top N
  ├── explicit numeric ports
  ├── numeric ranges
  └── service names via socket.getservbyname()
  │
  ▼
build_target_plan()
  │
  ├── split comma expression
  ├── resolve IP / hostname / CIDR
  ├── apply address family filter
  ├── enforce authorization
  ├── collect DNS failures for multi-target scans
  └── produce warnings + audit requirement
  │
  ▼
ScanOptions
  │
  ├── timeout
  ├── concurrency
  ├── rate_limit
  ├── technique
  ├── probe
  └── probe_insecure
  │
  ▼
scan_many()
  │
  ├── cap concurrency
  ├── create semaphore
  ├── create optional AsyncTokenBucket
  ├── create one task per target/port
  ├── scan_port()
  ├── sort results
  └── return PortResult list
  │
  ▼
ScanReport
  │
  ├── authorization summary
  ├── started/finished timestamps
  ├── duration
  └── result rows
  │
  ▼
format_report()
  │
  ├── table
  ├── json
  └── grepable
```

---

## Core Data Structures

### `ScanState`

Important states:
- `open`
- `closed`
- `filtered`
- `unknown`
- `unreachable`
- `dns_error`
- `permission_denied`
- `unsupported`
- `error`
- `open_filtered` reserved for future UDP scanner

Partial-exit states:
- `error`
- `dns_error`
- `permission_denied`
- `unknown`
- `unreachable`

---

### `Target`

```python
@dataclass(frozen=True)
class Target:
    expression: str
    address: str
    hostname: str | None = None
    family: str = "IPv4"
    is_loopback: bool = False
    is_private: bool = False
```

Purpose:
- preserve original target expression
- store resolved socket address
- track hostname for SNI/Host headers
- carry safety classification

---

### `AuthorizationSummary`

```python
@dataclass(frozen=True)
class AuthorizationSummary:
    authorized: bool
    reason: str | None
    requires_audit: bool
    categories: list[str]
```

Included in saved reports.

---

### `PortResult`

```python
@dataclass
class PortResult:
    target: str
    address: str
    port: int
    state: ScanState
    technique: Technique = Technique.TCP_CONNECT
    service: str | None = None
    service_confidence: str | None = None
    latency_ms: float | None = None
    reason: str | None = None
    banner: str | None = None
    http: HTTPProbeResult | None = None
    tls: TLSProbeResult | None = None
    error: str | None = None
```

Represents one target/address/port observation.

---

### `ScanOptions`

```python
@dataclass
class ScanOptions:
    timeout: float
    concurrency: int
    rate_limit: float
    technique: Technique = Technique.TCP_CONNECT
    probe: bool = False
    probe_insecure: bool = False
```

---

### `ScanReport`

```python
@dataclass
class ScanReport:
    target_expression: str
    ports: list[int]
    options: ScanOptions
    results: list[PortResult]
    authorization_summary: AuthorizationSummary | None
    started_at: str
    finished_at: str | None
    duration_ms: float | None
```

Serializable report model for JSON and re-rendering.

---

## Target Resolution

### Input forms

Supported:
- single IP
- hostname
- comma-separated expressions
- CIDR ranges

Flow:
```text
resolve_many(expression)
  └── resolve_expression(part)
      ├── CIDR → ip_network().hosts()
      ├── IP literal → Target
      └── hostname → socket.getaddrinfo()
```

Important behavior:
- CIDRs are capped by `max_hosts`
- single-address networks are supported
- hostname results are deduplicated
- targets are sorted IPv4 before IPv6
- family filter defaults to IPv4 but falls back if it would drop every target

---

## Authorization

Authorization categories:
- `loopback`
- `private`
- `public`
- `cidr`
- `invalid`

Policy:
```text
loopback single target → allowed
private non-loopback → requires --authorized
public → requires --authorized and --reason
CIDR → requires --authorized and --reason
```

Authorized private/public/CIDR scans set `requires_audit=True`.

---

## Audit Logging

Audit records include:
- timestamp
- target expression
- resolved targets
- ports
- technique
- authorized flag
- reason
- rate limit
- concurrency
- timeout
- probe flags when applicable

Output:
```text
.portsleuth/audit.jsonl
```

Locking:
- in-process `threading.Lock` keyed by path
- Unix `fcntl.flock` around append
- no-op OS-level lock on Windows

---

## Scanner Algorithm

### `scan_many()`

```text
scan_many(targets, ports, options)
  if technique is not TCP_CONNECT:
      return unsupported rows

  concurrency = cap_concurrency(requested)
  semaphore = asyncio.Semaphore(concurrency)
  limiter = AsyncTokenBucket(rate) if rate > 0

  for every target/port:
      create worker task

  as tasks finish:
      collect PortResult
      report progress callback when configured

  on interruption:
      cancel pending tasks
      dedupe finished results
      sort partial rows
      raise ScanInterrupted(results)
```

---

### `scan_port()`

```text
scan_port(target, port)
  started = perf_counter()
  service = guess_service(port)

  try:
      reader, writer = await asyncio.open_connection(address, port)
      result = open
      if probe:
          attach HTTP/TLS/banner evidence
      return result

  except TimeoutError:
      return filtered

  except PermissionError:
      return permission_denied

  except OSError:
      classify errno into closed/unreachable/filtered/unknown

  except Exception:
      return error

  finally:
      close writer
```

---

## Socket Error Classification

Classification:
- connection refused → `closed`
- network/host unreachable → `unreachable`
- timed out → `filtered`
- permission error → `permission_denied`
- other socket errors → `unknown`

The classifier handles common Unix and Windows errno values.

---

## Rate Limiting

`AsyncTokenBucket`:
- rate in connection attempts per second
- capacity defaults to a small burst cap
- protected by `asyncio.Lock`
- waits until a token is available

Purpose:
- prevent small scans from draining an overly large bucket instantly
- make scan pacing visible and testable

---

## Protocol Probes

### HTTP probe

Behavior:
- builds manual HTTP/1.1 request bytes
- supports `HEAD` and `GET`
- sends Host, User-Agent, Accept, Connection
- reads up to a bounded preview
- parses status line and headers
- falls back from HEAD to GET when useful
- marks likely HTTPS ports as `possible_https` when HTTP response is absent/malformed

---

### TLS probe

Behavior:
- uses `ssl` to perform handshake
- verifies certificates by default
- requires valid SNI when verifying
- allows `--insecure` for self-signed lab targets
- returns protocol, cipher, subject, issuer, SAN, validity dates when available
- optional `cryptography` improves certificate field extraction for unverified certs

---

### Banner probe

Behavior:
- opens TCP connection
- reads up to 512 bytes
- decodes UTF-8 with replacement
- returns trimmed banner or `None`

---

## TCP-Ping Discovery

Purpose:
- determine host liveness when ICMP is unavailable or filtered

Default ports:
```text
80, 443, 22, 445, 3389
```

Rule:
- open connection counts as host up
- connection refused also counts as host up because the host stack replied
- timeouts/non-refused errors do not prove liveness

---

## Configuration

Source order:
```text
CLI flags > scan.toml / PORTSLEUTH_CONFIG > built-in defaults
```

Default values:
- target: `127.0.0.1`
- timeout: `0.75`
- concurrency: `100`
- rate limit: `200.0`
- audit file: `.portsleuth/audit.jsonl`
- max CIDR hosts: `256`

Config file:
```toml
[defaults]
target = "127.0.0.1"
timeout = 0.75
concurrency = 100
rate = 200.0
audit_file = ".portsleuth/audit.jsonl"
max_hosts = 256
```

Validation rejects:
- malformed TOML
- boolean numeric values
- non-positive timeout
- concurrency below 1
- negative rate
- empty target/audit file
- max-hosts below 1

---

## Lab Fixtures

### TCP fixture

Serves a banner over TCP.

### UDP fixture

Serves a UDP banner for protocol demonstration.

### WSGI fixture

Routes:
- `/`
- `/health`
- `/redirect`
- `/headers`

Uses `wsgiref.simple_server` and supports HEAD with no body.

---

## Capability Checks

`portsleuth doctor` reports:
- OS and Python version
- root/admin status
- raw ICMP socket availability
- raw TCP socket creatability
- whether SYN scan is likely supported
- packet capture tools on PATH
- default lab port availability
- default timeout/concurrency/rate
- optional TLS certificate-field support
- platform notes

`doctor --require-raw` exits with privilege code when raw packet capability is unavailable.

---

## Error Handling Strategy

CLI catches and maps:
- `AuthorizationError` → authorization denied
- `TargetResolutionError` → target error
- `ValueError` → usage error
- `KeyboardInterrupt` → interrupted
- `OSError` → general error
- `PortsleuthError` → general error

Scan interruption preserves partial results when possible.

---

## Known Limits

- No production-grade discovery/scanning.
- No stealth or evasion.
- No implemented raw SYN scanner in the portable path.
- No implemented UDP scanner in the portable path.
- No vulnerability detection.
- No credential checks.
- No OS fingerprinting.
- No persistent report database.
- No distributed scan jobs.
- Audit logging is local-file based.
- IPv6 is supported but not default.
- TLS detail extraction for insecure certs requires optional extra.

---

## Verification Summary

The repository configures:
- package install through `pyproject.toml`
- pytest testpaths under `tests`
- coverage source as `portsleuth`
- coverage fail-under 90 in coverage config
- Ruff linting over `src` and tests
- GitHub Actions on Ubuntu and Windows
- Python 3.11 and 3.12 matrix test runs
- separate coverage and lint jobs

---

*Constitution reference: Article 4 (engineering quality), Article 6 (behavior verification), Article 7 (progressive complexity), and Article 8 (valid learner work).*

---


# Interface Design Specification
## App — Port Scanner
**Network Reconnaissance Group | Document 3 of 5**

---

## Public CLI Interface

### Console script

```powershell
portsleuth <command> [options]
```

### Version

```powershell
portsleuth --version
```

### Verbose diagnostics

```powershell
portsleuth --verbose scan 127.0.0.1 --ports 80
```

Diagnostics go to stderr. Scan results go to stdout.

---

## Commands

| Command | Purpose |
|---|---|
| `scan` | TCP connect port scan |
| `probe http` | Send hand-written HTTP probe |
| `probe tls` | Perform TLS handshake and summarize cert |
| `probe banner` | Read TCP banner |
| `discover` | TCP-ping host discovery |
| `lab serve-tcp` | Run TCP banner fixture |
| `lab serve-wsgi` | Run WSGI HTTP fixture |
| `lab serve-udp` | Run UDP banner fixture |
| `packet demo` | Show packet/header/checksum evidence |
| `benchmark` | Compare sync/threaded/async scanning |
| `report` | Re-render saved JSON scan report |
| `config` | Print effective config |
| `doctor` | Print platform/capability report |

---

## `scan`

```powershell
portsleuth scan TARGET --ports 22,80,443
portsleuth scan TARGET --ports 8000-8010
portsleuth scan TARGET --top 20
portsleuth scan 127.0.0.1 --ports 9090 --probe
portsleuth scan example.com --ports 443 --authorized --reason "owned test target"
```

### Target argument

`TARGET` may be:
- hostname
- IPv4 address
- IPv6 address
- comma-list
- CIDR range

Examples:
```text
127.0.0.1
localhost
example.com
127.0.0.1,localhost
127.0.0.0/30
```

---

## Scan Options

| Option | Description |
|---|---|
| `--ports SPEC` | Comma/range/service list |
| `--top N` | First N curated common ports |
| `--timeout SECONDS` | Per-port connect timeout |
| `--concurrency N` | Maximum concurrent connection attempts before internal cap |
| `--rate N` | Connection attempts per second; `0` disables pacing |
| `--technique connect|syn|udp` | `connect` implemented; others report unsupported |
| `--probe` / `--banner` | Probe open ports for HTTP/TLS/banner |
| `--probe-insecure` | Skip TLS verification during scan probes |
| `--format table|json|grepable|grep` | Output format |
| `--output PATH` | Write output to file |
| `--progress` | Print progress to stderr |

---

## Target Safety Options

| Option | Description |
|---|---|
| `--authorized` | Required for private/public/CIDR targets beyond single loopback |
| `--reason TEXT` | Required for public and CIDR scans |
| `--max-hosts N` | CIDR expansion cap |
| `--family ipv4|ipv6|auto` | Address family selection for hostname results |
| `--audit-file PATH` | JSONL audit output path |

---

## Authorization Contract

| Target class | Allowed without flags | Requires audit |
|---|---:|---:|
| Single loopback target | Yes | No |
| Non-local private target | No, needs `--authorized` | Yes |
| Public target | No, needs `--authorized --reason` | Yes |
| CIDR target | No, needs `--authorized --reason` | Yes |

Failed authorization exits with code `3`.

---

## Port Specification Contract

Examples:
```powershell
--ports 22
--ports 22,80,443
--ports 8000-8010
--ports http,https,ssh
--top 10
```

Rules:
- ports must be 1 through 65535
- ranges must be ascending
- service names use `socket.getservbyname(name, "tcp")`
- `--top` overrides `--ports`
- missing `--ports` uses curated common ports

---

## Scan Output Contract

### Table

Human-readable rows.

### JSON

Serialized `ScanReport`:
```json
{
  "target_expression": "127.0.0.1",
  "ports": [80, 443],
  "options": {
    "timeout": 0.75,
    "concurrency": 100,
    "rate_limit": 200.0,
    "technique": "connect",
    "probe": false,
    "probe_insecure": false
  },
  "started_at": "...",
  "finished_at": "...",
  "duration_ms": 12.3,
  "results": []
}
```

### Grepable

Line-oriented output suitable for simple shell filtering.

Alias:
```text
grep = grepable
```

---

## Scan Result Contract

Each result contains:
- target
- resolved address
- port
- state
- technique
- service guess
- service confidence
- latency
- reason
- optional banner
- optional HTTP probe
- optional TLS probe
- optional error

States:
```text
open
closed
filtered
unknown
unreachable
dns_error
permission_denied
unsupported
error
open_filtered
```

---

## `probe http`

```powershell
portsleuth probe http 127.0.0.1 --port 8080
portsleuth probe http 127.0.0.1 --port 8080 --method GET --path /health --show-preview
portsleuth probe http example.com --port 80 --authorized --reason "owned target" --format json
```

Options:
- `--port`
- `--path`
- `--method HEAD|GET`
- `--timeout`
- `--format text|json`
- `--show-preview`

Returns HTTP state, version, status code, reason, headers, server, location, preview, and error when available.

---

## `probe tls`

```powershell
portsleuth probe tls example.com --port 443 --authorized --reason "owned target"
portsleuth probe tls 127.0.0.1 --port 8443 --insecure --authorized --reason "lab"
```

Options:
- `--port`
- `--timeout`
- `--server-name`
- `--insecure`
- `--format text|json`

Behavior:
- verifies certificates by default
- requires hostname/SNI when verifying
- `--insecure` permits self-signed lab certs
- optional TLS extra improves cert field extraction for unverified certs

---

## `probe banner`

```powershell
portsleuth probe banner 127.0.0.1 --port 9090
```

Options:
- `--port`
- `--timeout`
- `--format text|json`

Returns the first readable banner text or no banner.

---

## `discover`

```powershell
portsleuth discover 127.0.0.1
portsleuth discover 192.168.1.0/30 --authorized --reason "home lab"
portsleuth discover example.com --authorized --reason "owned target" --ports 80,443
```

Behavior:
- uses TCP-ping against common ports unless `--ports` supplied
- open or refused response means host is up
- timeout/no response means unknown/down for that probe set

---

## `lab`

### TCP fixture

```powershell
portsleuth lab serve-tcp --port 9090 --banner "portsleuth fixture"
```

### WSGI fixture

```powershell
portsleuth lab serve-wsgi --port 8080
```

Routes:
- `/`
- `/health`
- `/redirect`
- `/headers`

### UDP fixture

```powershell
portsleuth lab serve-udp --port 5353 --banner "portsleuth udp fixture"
```

---

## `doctor`

```powershell
portsleuth doctor
portsleuth doctor --format json
portsleuth doctor --require-raw
```

Reports:
- OS
- Python version
- admin/root status
- raw ICMP availability
- raw TCP socket creatability
- raw SYN likelihood
- packet capture tools
- fixture-port status
- default settings
- optional TLS cert field support
- notes

---

## `packet demo`

```powershell
portsleuth packet demo --protocol all
portsleuth packet demo --protocol tcp
portsleuth packet demo --protocol udp
portsleuth packet demo --protocol icmp
```

Purpose:
- demonstrates packet-header/checksum knowledge without using raw packet scanning by default

---

## `benchmark`

```powershell
portsleuth benchmark 127.0.0.1 --ports 1-1000
```

Compares:
- synchronous scanning
- threaded scanning
- asyncio scanning

Benchmark uses authorization and audit behavior for non-loopback targets.

---

## `report`

```powershell
portsleuth report scan-report.json --format table
portsleuth report scan-report.json --format json
portsleuth report scan-report.json --format grepable
```

Validates a saved report before rendering.

---

## `config`

```powershell
portsleuth config
portsleuth config --format json
```

Shows effective defaults and source:
- config source
- target
- timeout
- concurrency
- rate limit
- audit file
- max CIDR hosts
- curated common port count

---

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Success |
| `1` | General error |
| `2` | Invalid usage |
| `3` | Authorization denied |
| `4` | Target resolution failure |
| `5` | Unsupported technique/platform |
| `6` | Insufficient privileges |
| `7` | Partial scan failure |
| `8` | Lab startup failure |
| `130` | Interrupted |

Partial scan failure occurs when any result is `error`, `dns_error`, `permission_denied`, `unknown`, or `unreachable`.

---

## Side Effects

| Operation | Side Effect |
|---|---|
| `scan` | Opens TCP connections to authorized target/ports |
| `scan --output` | Writes report file |
| authorized scan | Appends audit JSONL |
| `discover` | Opens TCP connections to discovery ports |
| `probe http/tls/banner` | Opens one TCP/TLS connection per selected target |
| `lab serve-*` | Binds local fixture port |
| `benchmark` | Opens TCP connections repeatedly |
| `doctor` | Attempts raw-socket creation and fixture-port binding checks |
| `packet demo` | Prints packet evidence only |

---

## Error Output Contract

- diagnostics go to stderr
- results go to stdout
- invalid target exits `4`
- unauthorized scan exits `3`
- unsupported non-portable technique exits `5`
- lab startup failure exits `8`
- interrupted scan writes partial results when available

---

*Constitution reference: Article 4 (input/output boundaries), Article 6 (verification), and Article 8 (understandable and verifiable work).*

---


# Runbook
## App — Port Scanner
**Network Reconnaissance Group | Document 4 of 5**

---

## Requirements

### Runtime

- Python 3.11+
- No required runtime dependencies

### Optional

```powershell
python -m pip install -e ".[tls]"
```

Use this for richer certificate field extraction during `probe tls --insecure`.

### Development

- pytest
- pytest-cov
- ruff

---

## Installation

### Runtime install

```powershell
python -m pip install -e .
```

### Development install

```powershell
python -m pip install -e ".[dev]"
```

### No install, source checkout

```powershell
$env:PYTHONPATH="src"
python -m portsleuth doctor
```

Linux/macOS:
```bash
PYTHONPATH=src python -m portsleuth doctor
```

---

## First Smoke Test

```powershell
portsleuth doctor
portsleuth scan 127.0.0.1 --ports 9089-9091
```

Expected:
- `doctor` prints platform/capability information
- scan returns rows for each requested port
- empty loopback ports usually show closed or filtered depending on OS/firewall

---

## Local Demo: Open TCP Port

Terminal 1:
```powershell
portsleuth lab serve-tcp --port 9090 --banner "portsleuth fixture"
```

Terminal 2:
```powershell
portsleuth scan 127.0.0.1 --ports 9089-9091 --probe
```

Expected:
- port `9090` reports `open`
- banner evidence appears when readable

---

## Local Demo: HTTP / WSGI

Terminal 1:
```powershell
portsleuth lab serve-wsgi --port 8080
```

Terminal 2:
```powershell
portsleuth probe http 127.0.0.1 --port 8080 --show-preview
portsleuth scan 127.0.0.1 --ports 8080 --probe
```

Expected:
- HTTP probe detects HTTP response
- WSGI lab route information appears in preview when requested

---

## Local Demo: Discovery

```powershell
portsleuth discover 127.0.0.1 --ports 8080,9090
```

Expected:
- host is up when any probed port is open or refused

---

## Standard Operating Procedures

### Scan explicit ports

```powershell
portsleuth scan 127.0.0.1 --ports 22,80,443
```

---

### Scan a range

```powershell
portsleuth scan 127.0.0.1 --ports 8000-8010
```

---

### Scan top curated ports

```powershell
portsleuth scan 127.0.0.1 --top 20
```

---

### Save JSON report

```powershell
portsleuth scan 127.0.0.1 --ports 1-100 --format json --output scan-report.json
```

---

### Re-render saved report

```powershell
portsleuth report scan-report.json --format table
```

---

### Authorized private target scan

```powershell
portsleuth scan 192.168.1.10 --ports 22,80,443 --authorized --reason "home lab"
```

Expected:
- audit record appended to `.portsleuth/audit.jsonl`

---

### Authorized public target probe

```powershell
portsleuth probe tls example.com --port 443 --authorized --reason "owned test target"
```

---

### CIDR scan

```powershell
portsleuth scan 127.0.0.0/30 --ports 80 --authorized --reason "local CIDR lab"
```

Expected:
- CIDR expansion warning
- audit record written
- scan rows per expanded host/port

---

### Config file

Create `scan.toml`:

```toml
[defaults]
target = "127.0.0.1"
timeout = 0.75
concurrency = 100
rate = 200.0
audit_file = ".portsleuth/audit.jsonl"
max_hosts = 256
```

Show effective settings:
```powershell
portsleuth config
```

Use alternate config:
```powershell
$env:PORTSLEUTH_CONFIG="path\to\scan.toml"
portsleuth config
```

---

## Quality Checks

### Tests

```powershell
python -m pytest
```

### Coverage

```powershell
python -m pytest --cov=portsleuth --cov-report=term-missing
```

### Lint

```powershell
python -m ruff check src tests
```

---

## CI Parity

The GitHub Actions workflow runs:
- Ubuntu latest + Windows latest
- Python 3.11 and 3.12
- editable install with dev extras
- pytest
- coverage on Ubuntu/Python 3.12
- Ruff lint

---

## Health Checks

### Doctor

```powershell
portsleuth doctor
```

Expected:
- platform details
- fixture port status
- raw-socket notes
- default scan settings

### Require raw sockets

```powershell
portsleuth doctor --require-raw
```

Expected:
- exit code `6` if raw ICMP/TCP sockets are unavailable

---

### Port parser

```powershell
portsleuth scan 127.0.0.1 --ports http,https,ssh
```

Expected:
- service names resolve to TCP ports
- scan proceeds on loopback

---

### Rate limiting

```powershell
portsleuth scan 127.0.0.1 --ports 1-100 --rate 10 --progress
```

Expected:
- progress on stderr
- paced connection attempts

---

### Audit check

```powershell
portsleuth scan 127.0.0.0/30 --ports 80 --authorized --reason "audit test"
Get-Content .portsleuth/audit.jsonl
```

Expected:
- JSONL record with target expression, resolved targets, ports, technique, authorization, reason, rate, concurrency, and timeout

---

## Expected Failure Modes

### Authorization denied

Trigger:
```powershell
portsleuth scan example.com --ports 80
```

Expected:
- stderr authorization error
- exit code `3`

Fix:
```powershell
portsleuth scan example.com --ports 80 --authorized --reason "owned test target"
```

---

### Target resolution failure

Trigger:
```powershell
portsleuth scan does-not-exist.invalid --ports 80
```

Expected:
- exit code `4`

---

### Bad port

Trigger:
```powershell
portsleuth scan 127.0.0.1 --ports 0
```

Expected:
- usage error
- exit code `2`

---

### Unsupported technique

Trigger:
```powershell
portsleuth scan 127.0.0.1 --ports 80 --technique syn
```

Expected:
- unsupported result rows
- exit code `5`

---

### Partial scan failure

Cause:
- unreachable target
- unknown socket error
- permission denied
- DNS failure in multi-target scan

Expected:
- scan output still prints
- exit code `7`

---

### Lab startup failure

Cause:
- requested fixture port already in use

Expected:
- exit code `8`

---

### TLS verification failure

Cause:
- self-signed certificate
- hostname/SNI missing
- certificate mismatch

Fix for lab only:
```powershell
portsleuth probe tls 127.0.0.1 --port 8443 --insecure --authorized --reason "local lab"
```

---

## Troubleshooting Decision Tree

```text
Scan did not run
  ├── Authorization denied?
  │     └── add --authorized and --reason when target is not single loopback
  ├── Target failed to resolve?
  │     └── check hostname/DNS or use an IP
  ├── CIDR too large?
  │     └── reduce range or raise --max-hosts intentionally
  ├── Invalid ports?
  │     └── use 1-65535, valid service names, or --top N
  └── Unsupported technique?
        └── use --technique connect

Scan ran but results unexpected
  ├── All filtered?
  │     └── check timeout/firewall/routing
  ├── Closed where expected open?
  │     └── confirm fixture/service is listening
  ├── No banner?
  │     └── many services speak only after client input
  ├── HTTP probe says possible HTTPS?
  │     └── try probe tls or scan --probe-insecure for lab certs
  └── Public/private target?
        └── verify audit log and reason

Tooling issue
  ├── doctor shows no raw sockets?
  │     └── expected on many non-admin platforms
  ├── optional TLS fields missing?
  │     └── install .[tls]
  └── tests fail on privileged raw tests?
        └── those require PORTSLEUTH_PRIVILEGED_TESTS=1 and platform support
```

---

## Maintenance Notes

- Keep connect scan as the safe default.
- Do not add stealth/evasion behavior.
- Preserve authorization and audit gates before adding new scan commands.
- Keep unsupported techniques honest until fully implemented and capability-gated.
- Keep loopback fixture tests as the primary integration path.
- Preserve stdout/stderr separation.
- Preserve stable exit codes.
- Add tests before changing socket classification.
- Add tests before changing CIDR or authorization behavior.
- Add tests before changing report schema.
- Avoid production claims unless RBAC, allowlists, durable audit, cancellation, and persistence are added.

---

*Constitution reference: Article 6 (behavior verification), Article 5 (constraints and trade-offs), and Article 8 (verifiable learner work).*

---


# Lessons Learned
## App — Port Scanner
**Network Reconnaissance Group | Document 5 of 5**

---

## Why This Design Was Chosen

This design was chosen because a port scanner is a powerful networking capstone, but it also carries real ethical and operational risk. The scanner needed to prove protocol knowledge without becoming an unsafe tool.

The safest core is TCP connect scanning. It uses ordinary socket behavior, works cross-platform, and teaches exactly what an open, refused, timed-out, unreachable, or permission-denied connection looks like. Adding asyncio makes the scanner realistic without requiring raw packet privileges.

The safety model is just as important as the scanner. Loopback targets are convenient for labs. Anything broader must be authorized, and public/CIDR scans require a reason. This makes the tool defensible as an educational artifact.

The local fixtures complete the learning loop. Instead of scanning unknown systems, the user can run a TCP banner service, WSGI HTTP lab, or UDP lab locally and prove the scanner behavior in a controlled environment.

---

## What Was Intentionally Omitted

**Stealth scans:** Out of scope because the project is defensive/educational.

**IDS bypass/evasion:** Out of scope and not aligned with portfolio intent.

**Credential or exploit checks:** The scanner observes ports and protocol hints only.

**Raw SYN scan:** Represented as a planned/capability-gated technique, but not implemented in the portable core.

**UDP scan:** Represented as planned; actual UDP classification requires retry policy and open-filtered ambiguity handling.

**OS fingerprinting:** Deferred because it requires more invasive packet behavior and lab validation.

**Service-version database:** Deferred because the project focuses on socket/protocol fundamentals.

**Django dashboard:** Stretch only; the CLI/report surface is enough for V1.

**Enterprise policy engine:** Local audit is adequate for capstone scope, not enterprise governance.

---

## Biggest Weakness

The biggest weakness is that TCP connect scanning is simple and visible. It is safe and portable, but it is not stealthy and not as capable as raw packet scanning. That is the correct trade-off for this project, but it should be stated clearly during defense.

The second weakness is that audit logging is a local JSONL file. It is good evidence for single-operator use, but a real organization would need a database, centralized logs, immutable storage, operator identity, and signed approvals.

The third weakness is service identification. Common-port guesses and simple probes are useful, but they are not the same as a full fingerprinting engine.

---

## Scaling Considerations

**If scanning larger targets:**
- add resumable jobs
- persist scan state
- implement cancellation and backpressure
- store reports in a database
- expose progress events

**If production governance matters:**
- add RBAC
- add signed scan policies
- add enterprise allowlists
- centralize audit logs
- require operator identity
- prevent scans outside approved scopes

**If protocol coverage expands:**
- implement UDP with conservative retry/open-filtered semantics
- add raw SYN only behind capability/privilege gates
- add ICMP discovery only where permitted
- compare behavior against mature tools in a controlled lab

**If fingerprinting expands:**
- add a signature database
- separate probes from scan core
- keep probes opt-in
- preserve timeout/rate-limit controls

---

## What the Next Refactor Would Be

1. **Introduce durable scan jobs** — store target plan, options, progress, and results in SQLite.

2. **Add structured cancellation** — make interruption safer and more predictable.

3. **Add UDP scanner prototype** — explicitly model `open|filtered` ambiguity.

4. **Add policy file support** — define allowed CIDRs and required reason formats.

5. **Add comparative lab tests** — compare known local services against expected open/closed/probe behavior.

---

## What This Project Taught

- **Networking tools need ethics built in.** Authorization gates and audit logs are part of the architecture, not decoration.

- **Port states are interpretations.** Open, closed, filtered, unreachable, and unknown are inferred from socket outcomes.

- **Concurrency needs safety controls.** Semaphores and rate limiting prevent the tool from overwhelming the local host or target.

- **DNS resolution affects policy.** A hostname must be resolved before deciding whether it is loopback, private, public, IPv4, or IPv6.

- **Refused connections prove liveness.** TCP-ping can mark a host up even when no target service is open.

- **Protocol probes are separate from scans.** A port can be open without a useful banner or HTTP response.

- **Raw packet knowledge can be demonstrated without unsafe defaults.** Packet demos and doctor checks show protocol awareness while TCP connect remains the safe core.

- **Mature scanners are mature for a reason.** Building a safe subset clarifies why tools like nmap require years of protocol, OS, and network edge-case handling.

---

*Constitution v2.0 checklist: This document satisfies Article 5 (trade-off documentation), Article 6 (verification), and Article 7 (progressive complexity) for Port Scanner.*
