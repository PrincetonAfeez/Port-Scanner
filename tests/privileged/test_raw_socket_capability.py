"""Capability-gated raw-socket tests.

These never run in the normal suite. They require both an explicit opt-in
(PORTSLEUTH_PRIVILEGED_TESTS=1) and a platform where raw sockets can actually be
created. On unsupported platforms they skip with a clear reason rather than fail.
"""

import os
import socket

import pytest

from portsleuth.capabilities import detect_capabilities

pytestmark = pytest.mark.skipif(
    os.environ.get("PORTSLEUTH_PRIVILEGED_TESTS") != "1",
    reason="set PORTSLEUTH_PRIVILEGED_TESTS=1 to run privileged raw-socket tests",
)


def test_raw_icmp_socket_can_be_created():
    report = detect_capabilities(default_timeout=0.5, default_concurrency=10, default_rate_limit=0.0)
    if not report.raw_icmp_available:
        pytest.skip(f"raw ICMP not available on {report.os}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.close()
