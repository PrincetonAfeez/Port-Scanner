# ADR 0001 - Authorization Gate

## Decision

Every target expression is resolved and authorized before scanning begins.

Loopback scans are allowed by default. Non-local private targets require `--authorized`. Public targets and CIDR ranges require both `--authorized` and a written `--reason`.

## Rationale

A port scanner is a dual-use tool. The project should make safe use visible in code, not only in documentation. The authorization gate prevents accidental scans of networks the user did not intend to touch, and audit records create a small safety trail for non-local scans.

## Consequences

The CLI is slightly more explicit for private, public, or range-based targets. That cost is acceptable because the capstone is about responsible networking practice as well as sockets and protocols.

