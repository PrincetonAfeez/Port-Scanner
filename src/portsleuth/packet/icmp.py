"""ICMP packet for portsleuth CLI."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from portsleuth.packet.checksum import ones_complement_checksum

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8


@dataclass
class ICMPEchoPacket:
    identifier: int
    sequence: int
    payload: bytes = b"portsleuth"
    type: int = ICMP_ECHO_REQUEST
    code: int = 0
    checksum: int = 0

    def pack(self, *, calculate_checksum: bool = True) -> bytes:
        header = struct.pack(
            "!BBHHH",
            self.type,
            self.code,
            0 if calculate_checksum else self.checksum,
            self.identifier,
            self.sequence,
        )
        checksum = ones_complement_checksum(header + self.payload) if calculate_checksum else self.checksum
        return struct.pack("!BBHHH", self.type, self.code, checksum, self.identifier, self.sequence) + self.payload

    @classmethod
    def unpack(cls, data: bytes) -> ICMPEchoPacket:
        if len(data) < 8:
            raise ValueError("ICMP echo packet requires at least 8 bytes")
        packet_type, code, checksum, identifier, sequence = struct.unpack("!BBHHH", data[:8])
        return cls(
            type=packet_type,
            code=code,
            checksum=checksum,
            identifier=identifier,
            sequence=sequence,
            payload=data[8:],
        )

