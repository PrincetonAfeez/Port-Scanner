"""UDP packet for portsleuth CLI."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from portsleuth.packet.checksum import ipv4_pseudo_header, ones_complement_checksum


@dataclass
class UDPHeader:
    src_port: int
    dst_port: int
    length: int = 8
    checksum: int = 0

    def pack(self, *, src_ip: str | None = None, dst_ip: str | None = None, payload: bytes = b"") -> bytes:
        length = 8 + len(payload)
        header = struct.pack("!HHHH", self.src_port, self.dst_port, length, 0)
        checksum = self.checksum
        if src_ip and dst_ip:
            pseudo = ipv4_pseudo_header(src_ip, dst_ip, 17, length)
            checksum = ones_complement_checksum(pseudo + header + payload)
        return struct.pack("!HHHH", self.src_port, self.dst_port, length, checksum)

    @classmethod
    def unpack(cls, data: bytes) -> UDPHeader:
        if len(data) < 8:
            raise ValueError("UDP header requires at least 8 bytes")
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
        return cls(src_port=src_port, dst_port=dst_port, length=length, checksum=checksum)

