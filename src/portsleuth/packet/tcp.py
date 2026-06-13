"""TCP packet for portsleuth CLI."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from portsleuth.packet.checksum import ipv4_pseudo_header, ones_complement_checksum

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq: int = 0
    ack: int = 0
    flags: int = TCP_SYN
    window: int = 65535
    urgent_pointer: int = 0
    checksum: int = 0
    options: bytes = b""

    @property
    def data_offset(self) -> int:
        return (20 + len(_pad_options(self.options))) // 4

    def pack(self, *, src_ip: str | None = None, dst_ip: str | None = None, payload: bytes = b"") -> bytes:
        options = _pad_options(self.options)
        offset_flags = (self.data_offset << 12) | self.flags
        header = struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack,
            offset_flags,
            self.window,
            0,
            self.urgent_pointer,
        ) + options
        checksum = self.checksum
        if src_ip and dst_ip:
            pseudo = ipv4_pseudo_header(src_ip, dst_ip, 6, len(header) + len(payload))
            checksum = ones_complement_checksum(pseudo + header + payload)
        return struct.pack(
            "!HHIIHHHH",
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack,
            offset_flags,
            self.window,
            checksum,
            self.urgent_pointer,
        ) + options

    @classmethod
    def unpack(cls, data: bytes) -> TCPHeader:
        if len(data) < 20:
            raise ValueError("TCP header requires at least 20 bytes")
        src_port, dst_port, seq, ack, offset_flags, window, checksum, urgent = struct.unpack(
            "!HHIIHHHH",
            data[:20],
        )
        offset = offset_flags >> 12
        option_length = max(0, offset * 4 - 20)
        return cls(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=offset_flags & 0x01FF,
            window=window,
            checksum=checksum,
            urgent_pointer=urgent,
            options=data[20 : 20 + option_length],
        )


def _pad_options(options: bytes) -> bytes:
    if len(options) % 4 == 0:
        return options
    return options + (b"\x00" * (4 - (len(options) % 4)))

