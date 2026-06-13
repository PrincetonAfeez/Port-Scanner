"""Unit tests for audit extended module in portsleuth CLI."""

import json
import os

from portsleuth.models import ScanOptions, Target, Technique
from portsleuth.observability import audit as audit_mod
from portsleuth.observability.audit import write_audit_record


def test_write_audit_record_includes_probe_flags(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    options = ScanOptions(
        timeout=0.75,
        concurrency=1,
        rate_limit=0,
        technique=Technique.TCP_CONNECT,
        probe=True,
        probe_insecure=True,
    )
    write_audit_record(
        str(audit_path),
        target_expression="192.168.1.1",
        targets=[Target(expression="192.168.1.1", address="192.168.1.1", is_private=True)],
        ports=[443],
        options=options,
        authorized=True,
        reason="lab",
        technique="scan",
    )
    record = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert record["probe"] is True
    assert record["probe_insecure"] is True


def test_lock_file_unix_path(monkeypatch, tmp_path):
    if os.name == "nt":
        return
    audit_path = tmp_path / "audit.jsonl"
    options = ScanOptions(timeout=0.75, concurrency=1, rate_limit=0, technique=Technique.TCP_CONNECT)
    write_audit_record(
        str(audit_path),
        target_expression="192.168.1.2",
        targets=[Target(expression="192.168.1.2", address="192.168.1.2", is_private=True)],
        ports=[22],
        options=options,
        authorized=True,
        reason="lab",
    )
    assert audit_path.exists()


def test_lock_for_reuses_process_lock(tmp_path):
    path = tmp_path / "a.jsonl"
    lock1 = audit_mod._lock_for(path)
    lock2 = audit_mod._lock_for(path)
    assert lock1 is lock2
