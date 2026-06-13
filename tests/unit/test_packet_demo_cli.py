"""Unit tests for packet demo module in portsleuth CLI."""

from portsleuth.cli.packet_demo import format_packet_demo


def test_packet_demo_all_protocols():
    all_text = format_packet_demo("all")
    assert "TCP SYN" in all_text
    assert "UDP header" in all_text
    assert "ICMP echo" in all_text


def test_packet_demo_single_protocols():
    assert "TCP SYN" in format_packet_demo("tcp")
    assert "UDP header" in format_packet_demo("udp")
    assert "ICMP echo" in format_packet_demo("icmp")
