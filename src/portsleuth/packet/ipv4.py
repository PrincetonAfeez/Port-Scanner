"""IPv4 packet for portsleuth CLI."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

from portsleuth.packet.checksum import ones_complement_checksum


@dataclass
class IPv4Header:
    src: str
    dst: str
    protocol: int
    total_length: int = 20
    identification: int = 0
    ttl: int = 64
    tos: int = 0
    flags_fragment: int = 0
    checksum: int = 0

    version: int = 4
    ihl: int = 5

    def pack(self, *, calculate_checksum: bool = True) -> bytes:
        version_ihl = (self.version << 4) + self.ihl
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            self.tos,
            self.total_length,
            self.identification,
            self.flags_fragment,
            self.ttl,
            self.protocol,
            0 if calculate_checksum else self.checksum,
            ipaddress.IPv4Address(self.src).packed,
            ipaddress.IPv4Address(self.dst).packed,
        )
        checksum = ones_complement_checksum(header) if calculate_checksum else self.checksum
        return struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            self.tos,
            self.total_length,
            self.identification,
            self.flags_fragment,
            self.ttl,
            self.protocol,
            checksum,
            ipaddress.IPv4Address(self.src).packed,
            ipaddress.IPv4Address(self.dst).packed,
        )

    @classmethod
    def unpack(cls, data: bytes) -> IPv4Header:
        if len(data) < 20:
            raise ValueError("IPv4 header requires at least 20 bytes")
        (
            version_ihl,
            tos,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum,
            src,
            dst,
        ) = struct.unpack("!BBHHHBBH4s4s", data[:20])
        return cls(
            version=version_ihl >> 4,
            ihl=version_ihl & 0x0F,
            tos=tos,
            total_length=total_length,
            identification=identification,
            flags_fragment=flags_fragment,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            src=str(ipaddress.IPv4Address(src)),
            dst=str(ipaddress.IPv4Address(dst)),
        )

