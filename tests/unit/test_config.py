"""Unit tests for config module in portsleuth CLI."""

import pytest

from portsleuth.config import DEFAULT_TIMEOUT, Settings, load_settings


def test_load_settings_returns_builtin_defaults_when_no_file(tmp_path):
    settings = load_settings(tmp_path / "missing.toml")
    assert settings.timeout == DEFAULT_TIMEOUT
    assert settings.source is None


def test_load_settings_overlays_defaults_table(tmp_path):
    config = tmp_path / "scan.toml"
    config.write_text(
        "[defaults]\ntimeout = 2.5\nconcurrency = 7\nrate = 0\n",
        encoding="utf-8",
    )
    settings = load_settings(config)
    assert settings.timeout == 2.5
    assert settings.concurrency == 7
    assert settings.rate_limit == 0.0
    assert settings.source == str(config)


def test_load_settings_accepts_top_level_keys(tmp_path):
    config = tmp_path / "scan.toml"
    config.write_text("timeout = 1.25\n", encoding="utf-8")
    assert load_settings(config).timeout == 1.25


def test_load_settings_rejects_malformed_toml(tmp_path):
    config = tmp_path / "scan.toml"
    config.write_text("this is not toml = = =\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(config)


def test_load_settings_rejects_bad_value_type(tmp_path):
    config = tmp_path / "scan.toml"
    config.write_text('[defaults]\nconcurrency = "lots"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(config)


def test_load_settings_rejects_boolean_for_numeric_field(tmp_path):
    config = tmp_path / "scan.toml"
    config.write_text("[defaults]\nconcurrency = true\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(config)


def test_load_settings_rejects_out_of_range_values(tmp_path):
    for body in ("timeout = 0", "timeout = -1", "concurrency = 0", "rate = -5", "max_hosts = 0"):
        config = tmp_path / "scan.toml"
        config.write_text(f"[defaults]\n{body}\n", encoding="utf-8")
        with pytest.raises(ValueError):
            load_settings(config)


def test_load_settings_rejects_empty_target(tmp_path):
    config = tmp_path / "scan.toml"
    config.write_text('[defaults]\ntarget = "   "\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_settings(config)


def test_load_settings_tolerates_utf8_bom(tmp_path):
    config = tmp_path / "scan.toml"
    config.write_text("[defaults]\ntimeout = 3.0\n", encoding="utf-8-sig")
    assert load_settings(config).timeout == 3.0


def test_flags_override_config_defaults(tmp_path, capsys):
    # build_parser uses settings as argparse defaults; explicit flags must win.
    from portsleuth.cli.main import build_parser

    parser = build_parser(Settings(timeout=2.5, concurrency=7))
    args = parser.parse_args(["scan", "127.0.0.1", "--timeout", "9.9"])
    assert args.timeout == 9.9  # flag overrides config
    assert args.concurrency == 7  # config still supplies the default
