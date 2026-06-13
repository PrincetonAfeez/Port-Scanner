# Protocol Mastery Checklist

Use this checklist when preparing a capstone defense. Checked items are implemented in the portable core or evidence modules.

## Targeting and DNS

- [x] Target parser accepts localhost, hostnames, IPv4, comma lists, and authorized CIDR
- [x] Hostnames resolved explicitly via `getaddrinfo`
- [x] DNS failures reported clearly (exit 4 for single target; `dns_error` rows for partial comma-list failures)
- [x] Non-local targets require `--authorized` (and `--reason` for public/CIDR)

## TCP connect scanning

- [x] Async connect scanner with semaphore and timeouts
- [x] Open / closed / filtered / unreachable classification
- [x] Rate limiting via token bucket (`--rate`, `0` disables pacing)
- [x] File-descriptor guard via concurrency cap
- [x] Ctrl-C partial results (`ScanInterrupted`)

## Service probing

- [x] Hand-written HTTP request bytes
- [x] HTTP status-line and header parsing (including `http_version`)
- [x] TLS handshake + certificate summary
- [x] Banner grab via `scan --probe` and `probe banner`
- [x] WSGI lab server for HTTP demonstration

## Discovery

- [x] TCP-ping host discovery (`discover`)
- [ ] ICMP echo sweep (planned — capability-gated)
- [x] Partial results on interrupt

## Raw / advanced scanning (Lane 2 — planned)

- [ ] Live raw SYN scan (`--technique syn`)
- [ ] UDP scan with open|filtered ambiguity
- [ ] ICMP-based discovery module
- [x] Hand-packed IPv4/TCP/UDP/ICMP headers + checksums (`packet/` modules)
- [x] `packet demo` CLI evidence (TCP, UDP, ICMP)

## Safety and output

- [x] Authorization gate with audit JSONL
- [x] Structured JSON reports with schema validation
- [x] `authorization_summary` in scan reports
- [x] Meaningful exit codes documented in README

## Stretch (out of scope)

- [ ] Per-host rate limiter
- [ ] Django + HTMX dashboard
- [ ] Config lab-network allowlist
- [ ] nmap comparison harness
