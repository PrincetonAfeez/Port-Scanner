# ADR 0006 - Platform Capability Gating

## Decision

Raw packet capabilities are reported through `portsleuth doctor` and are not assumed to exist.

## Rationale

Raw sockets behave differently across Linux, WSL, macOS, and Windows. Native Windows in particular restricts raw TCP behavior. A scanner that reports platform reality is easier to defend than one that silently fails.

## Consequences

Normal tests avoid privileged packet operations. Future privileged tests should run only when explicitly enabled and when capability checks pass.

