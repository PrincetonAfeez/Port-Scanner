"""Checksum helpers for portsleuth CLI."""

from __future__ import annotations

import ipaddress
import struct


def ones_complement_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_pseudo_header(src: str, dst: str, protocol: int, length: int) -> bytes:
    return struct.pack(
        "!4s4sBBH",
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
        0,
        protocol,
        length,
    )

