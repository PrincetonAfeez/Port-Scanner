# ADR 0002 - TCP Connect Scan vs SYN Scan

## Decision

The portable core uses TCP connect scanning. Raw SYN scanning is treated as capability-gated future work.

## Rationale

TCP connect scanning uses normal sockets, completes the TCP three-way handshake, and works across common student environments without special privileges. SYN scanning better demonstrates raw TCP/IP mechanics, but it requires raw sockets and OS-specific privileges.

## Consequences

`portsleuth scan` is dependable on Windows, macOS, Linux, and WSL. The packet modules still demonstrate header layout and checksum understanding, while `doctor` explains whether raw socket features are likely available.

