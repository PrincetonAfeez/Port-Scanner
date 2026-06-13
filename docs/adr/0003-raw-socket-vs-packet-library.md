# ADR 0003 - Raw Socket vs Packet Library

## Decision

Packet headers and checksums are implemented by hand for IPv4, TCP, UDP, and ICMP.

## Rationale

The capstone goal is protocol understanding. Writing compact header pack/unpack code shows byte layout, pseudo headers, and one's-complement checksums directly. A production scanner would probably use mature libraries and more extensive packet parsing.

## Consequences

The packet layer is intentionally small and testable. It is protocol evidence, not a complete packet manipulation framework.

