"""Unit tests for config extended module in portsleuth CLI."""

import pytest

from portsleuth.config import load_settings


def test_load_settings_rejects_non_table_defaults(tmp_path):
    bad = tmp_path / "scan.toml"
    bad.write_text('defaults = "nope"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="defaults"):
        load_settings(bad)


def test_load_settings_accepts_top_level_keys(tmp_path):
    cfg = tmp_path / "scan.toml"
    cfg.write_text(
        """
        target = "10.0.0.5"
        timeout = 1.5
        concurrency = 5
        rate = 10
        audit_file = "custom.jsonl"
        max_hosts = 32
        """,
        encoding="utf-8",
    )
    settings = load_settings(cfg)
    assert settings.target == "10.0.0.5"
    assert settings.rate_limit == 10.0
    assert settings.max_cidr_hosts == 32
