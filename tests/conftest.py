"""Fixtures for portsleuth CLI."""

import pytest


@pytest.fixture(autouse=True)
def isolate_config(monkeypatch, tmp_path):
    """Keep the suite independent of any scan.toml in the developer's CWD.

    Point PORTSLEUTH_CONFIG at a guaranteed-missing path so load_settings()
    always falls back to the built-in defaults. Tests that exercise config
    loading pass an explicit path to load_settings and are unaffected.
    """
    monkeypatch.setenv("PORTSLEUTH_CONFIG", str(tmp_path / "no-such-scan.toml"))
