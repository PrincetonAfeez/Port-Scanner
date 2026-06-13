"""Unit tests for packets module in portsleuth CLI."""

from portsleuth.packet.checksum import ones_complement_checksum
from portsleuth.packet.icmp import ICMP_ECHO_REQUEST, ICMPEchoPacket
from portsleuth.packet.ipv4 import IPv4Header
from portsleuth.packet.tcp import TCP_SYN, TCPHeader
from portsleuth.packet.udp import UDPHeader


def test_checksum_known_rfc_example():
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert ones_complement_checksum(data) == 0x220D


def test_ipv4_header_pack_unpack():
    header = IPv4Header(src="192.0.2.1", dst="198.51.100.2", protocol=6, total_length=40, identification=123)
    packed = header.pack()
    parsed = IPv4Header.unpack(packed)
    assert parsed.version == 4
    assert parsed.ihl == 5
    assert parsed.protocol == 6
    assert parsed.src == "192.0.2.1"
    assert parsed.dst == "198.51.100.2"


def test_tcp_header_pack_unpack():
    header = TCPHeader(src_port=40000, dst_port=80, seq=100, flags=TCP_SYN)
    packed = header.pack(src_ip="192.0.2.1", dst_ip="198.51.100.2")
    parsed = TCPHeader.unpack(packed)
    assert parsed.src_port == 40000
    assert parsed.dst_port == 80
    assert parsed.flags & TCP_SYN
    assert parsed.checksum != 0


def test_udp_header_pack_unpack():
    header = UDPHeader(src_port=5353, dst_port=53)
    packed = header.pack(src_ip="192.0.2.1", dst_ip="198.51.100.2", payload=b"data")
    parsed = UDPHeader.unpack(packed)
    assert parsed.length == 12
    assert parsed.checksum != 0


def test_icmp_echo_pack_unpack():
    packet = ICMPEchoPacket(identifier=7, sequence=3, payload=b"abc")
    packed = packet.pack()
    parsed = ICMPEchoPacket.unpack(packed)
    assert parsed.type == ICMP_ECHO_REQUEST
    assert parsed.identifier == 7
    assert parsed.sequence == 3
    assert parsed.payload == b"abc"


def test_unpack_rejects_truncated_buffers():
    import pytest

    with pytest.raises(ValueError):
        IPv4Header.unpack(b"\x00" * 10)
    with pytest.raises(ValueError):
        TCPHeader.unpack(b"\x00" * 10)
    with pytest.raises(ValueError):
        UDPHeader.unpack(b"\x00" * 4)
    with pytest.raises(ValueError):
        ICMPEchoPacket.unpack(b"\x00" * 4)


def test_checksum_pads_odd_length_buffer():
    # An odd-length buffer must not raise (it is zero-padded internally).
    assert isinstance(ones_complement_checksum(b"\x01\x02\x03"), int)

