"""Unit tests for round3 module in portsleuth CLI."""

import pytest

from portsleuth.cli.report_schema import validate_report_data
from portsleuth.models import ScanOptions, ScanState, Target, Technique
from portsleuth.scan.connect import build_dns_error_results, scan_port_sync
from portsleuth.targets.parse import build_target_plan


def test_validate_report_data_accepts_rate_limit_zero():
    validate_report_data(
        {
            "target_expression": "127.0.0.1",
            "ports": [9],
            "options": {
                "timeout": 0.75,
                "concurrency": 100,
                "rate_limit": 0,
                "technique": "connect",
                "probe": False,
                "probe_insecure": False,
            },
            "authorization_summary": {
                "authorized": False,
                "reason": None,
                "requires_audit": False,
                "categories": ["loopback"],
            },
            "results": [
                {
                    "target": "127.0.0.1",
                    "address": "127.0.0.1",
                    "port": 9,
                    "state": "closed",
                }
            ],
        }
    )


def test_build_dns_error_results_for_partial_comma_list():
    plan = build_target_plan("127.0.0.1,invalid.invalid", family="ipv4")
    assert plan.targets
    assert plan.dns_failures
    results = build_dns_error_results(plan.dns_failures, [80, 443], Technique.TCP_CONNECT)
    assert len(results) == 1
    assert results[0].state == ScanState.DNS_ERROR


def test_scan_port_sync_returns_error_on_unexpected_exception(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("portsleuth.scan.connect.socket.create_connection", boom)
    assert scan_port_sync("127.0.0.1", 9, 0.1) == ScanState.ERROR


def test_scan_many_interrupt_dedupe_keeps_distinct_targets_same_address():
    import asyncio

    from portsleuth.exceptions import ScanInterrupted
    from portsleuth.scan.connect import scan_many

    async def run():
        targets = [
            Target(expression="127.0.0.1", address="127.0.0.1", is_loopback=True),
            Target(expression="localhost", address="127.0.0.1", hostname="localhost", is_loopback=True),
        ]
        ports = list(range(1, 200))
        options = ScanOptions(
            timeout=0.05,
            concurrency=50,
            rate_limit=0,
            technique=Technique.TCP_CONNECT,
        )
        task = asyncio.create_task(scan_many(targets, ports, options))
        await asyncio.sleep(0.15)
        task.cancel()
        with pytest.raises(ScanInterrupted) as exc_info:
            await task
        keys = [(item.target, item.address, item.port) for item in exc_info.value.results]
        assert len(keys) == len(set(keys))

    asyncio.run(run())
