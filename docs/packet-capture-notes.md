# Packet Capture Notes

## Purpose

This project demonstrates protocol understanding through **hand-packed headers** and optional capture-tool awareness — not through live IDS evasion or stealth scanning.

## What `portsleuth packet demo` shows

- IPv4 header construction (`packet/ipv4.py`)
- TCP SYN segment with checksum (`packet/tcp.py`)
- UDP datagram with pseudo-header checksum (`packet/udp.py`)
- ICMP echo request (`packet/icmp.py`)

Run:

```powershell
portsleuth packet demo
portsleuth packet demo --protocol tcp
portsleuth packet demo --protocol udp
portsleuth packet demo --protocol icmp
```

## Optional capture tools

`portsleuth doctor` lists whether `tcpdump`, `tshark`, or `wireshark` appear on `PATH`.

For a local lab capture while scanning the WSGI fixture:

```bash
# Linux/macOS example (requires privileges for some interfaces)
sudo tcpdump -i lo -n port 8080
```

```powershell
# Windows: use Wireshark on the loopback adapter while running:
portsleuth scan 127.0.0.1 --ports 8080 --probe
```

## Evidence for defense

1. Show hex dump from `packet demo` and map fields to your checklist (src/dst IP, protocol number, TCP flags, checksum).
2. Optionally show one capture screenshot with a matching TCP handshake from `scan` (normal connect, not raw SYN).
3. Explain why raw SYN is capability-gated (ADR 0002, ADR 0006).

## Out of scope

- Automated pcap parsing inside portsleuth
- Spoofed packets or fragmented scan techniques
- IPv6 packet crafting
