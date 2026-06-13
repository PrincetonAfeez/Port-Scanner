"""Unit tests for audit module in portsleuth CLI."""

import json

from portsleuth.models import ScanOptions, Target, Technique
from portsleuth.observability.audit import write_audit_record


def test_write_audit_record_appends_parseable_jsonl(tmp_path):
    audit_path = tmp_path / "nested" / "audit.jsonl"
    targets = [Target(expression="192.168.1.10", address="192.168.1.10", is_private=True)]
    options = ScanOptions(timeout=0.75, concurrency=100, rate_limit=200.0, technique=Technique.TCP_CONNECT)

    write_audit_record(
        str(audit_path),
        target_expression="192.168.1.10",
        targets=targets,
        ports=[22, 80],
        options=options,
        authorized=True,
        reason="home lab",
    )
    write_audit_record(
        str(audit_path),
        target_expression="192.168.1.10",
        targets=targets,
        ports=[443],
        options=options,
        authorized=True,
        reason="home lab",
    )

    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2  # appended, not overwritten
    record = json.loads(lines[0])
    assert record["authorized"] is True
    assert record["reason"] == "home lab"
    assert record["ports"] == [22, 80]
    assert record["resolved_targets"][0]["address"] == "192.168.1.10"
