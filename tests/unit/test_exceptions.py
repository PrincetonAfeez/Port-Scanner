"""Unit tests for exceptions module in portsleuth CLI."""

from portsleuth.exceptions import DiscoverInterrupted, ScanInterrupted
from portsleuth.models import PortResult, ScanState


def test_scan_interrupted_carries_results():
    results = [
        PortResult(target="127.0.0.1", address="127.0.0.1", port=80, state=ScanState.OPEN),
    ]
    exc = ScanInterrupted(results)
    assert exc.results is results
    assert str(exc) == "scan interrupted"


def test_discover_interrupted_carries_statuses():
    exc = DiscoverInterrupted(["status"])
    assert exc.statuses == ["status"]
