"""Unit tests for __main__ module in portsleuth CLI."""

import runpy
import sys

import pytest


def test_main_module_entrypoint(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["portsleuth", "doctor"])
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("portsleuth.__main__", run_name="__main__")
    assert exc_info.value.code == 0
