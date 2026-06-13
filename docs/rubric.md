# Capstone Rubric Alignment

This document maps **portsleuth** deliverables to typical Networking & Protocols capstone criteria.

## Technical depth

| Criterion | Evidence |
|-----------|----------|
| TCP connect scanning | `scan/connect.py`, integration tests against loopback fixtures |
| Asyncio concurrency + rate limiting | `scan/connect.py`, `concurrency/rate_limit.py`, `benchmark` command |
| DNS resolution & targeting | `targets/resolve.py`, `targets/parse.py`, authorization gate |
| HTTP as bytes over TCP | `fingerprint/http_probe.py`, `probe http`, WSGI lab |
| TLS handshake inspection | `fingerprint/tls.py`, `probe tls` |
| UDP / ICMP / raw packet knowledge | `packet/` modules, `packet demo`, ADR 0003 |
| Platform capability gating | `capabilities.py`, `doctor` command |

## Safety & ethics

| Criterion | Evidence |
|-----------|----------|
| Localhost default | CLI defaults, `scan.toml.example` |
| Authorization gate | `targets/authorize.py`, ADR 0001 |
| Audit trail | `observability/audit.py`, `--audit-file` |
| No stealth / evasion | README constraints, unsupported technique stubs |

## Engineering quality

| Criterion | Evidence |
|-----------|----------|
| Structured output | JSON / table / grepable, `cli/report_schema.py` |
| Tests | `tests/unit`, `tests/integration`, optional `tests/privileged` |
| Design decisions | `docs/adr/` |
| Reproducible demo | `docs/demo-script.md` |

## Presentation

| Criterion | Evidence |
|-----------|----------|
| Demo script | `docs/demo-script.md` |
| Protocol checklist | `docs/protocol-mastery-checklist.md` |
| Example artifacts | `docs/evidence/scan-report-example.json`, `docs/benchmark-example.txt` |
