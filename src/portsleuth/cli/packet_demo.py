"""Packet demo for portsleuth CLI."""   

from __future__ import annotations

from portsleuth.packet.icmp import ICMP_ECHO_REQUEST, ICMPEchoPacket
from portsleuth.packet.ipv4 import IPv4Header
from portsleuth.packet.tcp import TCP_SYN, TCPHeader
from portsleuth.packet.udp import UDPHeader


def format_packet_demo(protocol: str = "all") -> str:
    """Build example IPv4/TCP/UDP/ICMP headers as protocol evidence."""
    sections: list[str] = [
        "Example hand-packed headers (not sent by the portable connect scanner):",
        "",
    ]
    if protocol in {"all", "tcp"}:
        sections.extend(_format_tcp_section())
        sections.append("")
    if protocol in {"all", "udp"}:
        sections.extend(_format_udp_section())
        sections.append("")
    if protocol in {"all", "icmp"}:
        sections.extend(_format_icmp_section())
        sections.append("")
    sections.extend(
        [
            "The portable scanner uses normal connect() sockets; raw SYN/ICMP/UDP",
            "scanning is capability-gated and reported as unsupported unless a",
            "privileged path is added (see docs/protocol-mastery-checklist.md).",
        ]
    )
    return "\n".join(sections).rstrip()


def _format_tcp_section() -> list[str]:
    tcp = TCPHeader(src_port=40000, dst_port=80, seq=100, flags=TCP_SYN)
    tcp_bytes = tcp.pack(src_ip="192.0.2.1", dst_ip="198.51.100.2")
    ip = IPv4Header(
        src="192.0.2.1",
        dst="198.51.100.2",
        protocol=6,
        total_length=20 + len(tcp_bytes),
    )
    return [
        f"IPv4 header ({len(ip.pack())} bytes):",
        _hex_dump(ip.pack()),
        "",
        f"TCP SYN header ({len(tcp_bytes)} bytes):",
        _hex_dump(tcp_bytes),
    ]


def _format_udp_section() -> list[str]:
    payload = b"portsleuth"
    udp = UDPHeader(src_port=40001, dst_port=53, length=8 + len(payload))
    udp_bytes = udp.pack(src_ip="192.0.2.1", dst_ip="198.51.100.2", payload=payload)
    ip = IPv4Header(
        src="192.0.2.1",
        dst="198.51.100.2",
        protocol=17,
        total_length=20 + len(udp_bytes) + len(payload),
    )
    return [
        f"IPv4/UDP datagram ({len(ip.pack()) + len(udp_bytes) + len(payload)} bytes payload included):",
        _hex_dump(ip.pack()),
        "",
        f"UDP header ({len(udp_bytes)} bytes):",
        _hex_dump(udp_bytes),
        "",
        f"UDP payload ({len(payload)} bytes):",
        _hex_dump(payload),
    ]


def _format_icmp_section() -> list[str]:
    icmp = ICMPEchoPacket(identifier=42, sequence=1, type=ICMP_ECHO_REQUEST)
    icmp_bytes = icmp.pack()
    ip = IPv4Header(
        src="192.0.2.1",
        dst="198.51.100.2",
        protocol=1,
        total_length=20 + len(icmp_bytes),
    )
    return [
        f"IPv4/ICMP echo request ({len(ip.pack()) + len(icmp_bytes)} bytes):",
        _hex_dump(ip.pack()),
        "",
        f"ICMP echo ({len(icmp_bytes)} bytes):",
        _hex_dump(icmp_bytes),
    ]


def _hex_dump(data: bytes, width: int = 16) -> str:
    rows: list[str] = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        rows.append(f"{offset:04x}  {hex_part.ljust(width * 3 - 1)}  {ascii_part}")
    return "\n".join(rows)
