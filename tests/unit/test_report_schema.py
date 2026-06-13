"""Unit tests for report schema module in portsleuth CLI."""

import pytest

from portsleuth.cli.report_schema import validate_report_data


def test_validate_report_data_accepts_minimal_report():
    validate_report_data(
        {
            "target_expression": "127.0.0.1",
            "ports": [80],
            "options": {
                "timeout": 0.75,
                "concurrency": 100,
                "rate_limit": 200.0,
                "technique": "connect",
            },
            "results": [
                {
                    "target": "127.0.0.1",
                    "address": "127.0.0.1",
                    "port": 80,
                    "state": "closed",
                }
            ],
        }
    )


def test_validate_report_data_rejects_bad_port_type():
    with pytest.raises(ValueError, match="ports\\[0\\]"):
        validate_report_data(
            {
                "target_expression": "127.0.0.1",
                "ports": ["80"],
                "options": {
                    "timeout": 0.75,
                    "concurrency": 100,
                    "rate_limit": 200.0,
                    "technique": "connect",
                },
                "results": [],
            }
        )


def test_validate_report_data_rejects_invalid_state():
    with pytest.raises(ValueError, match="state must be a known scan state"):
        validate_report_data(
            {
                "target_expression": "127.0.0.1",
                "ports": [80],
                "options": {
                    "timeout": 0.75,
                    "concurrency": 100,
                    "rate_limit": 200.0,
                    "technique": "connect",
                },
                "results": [
                    {
                        "target": "127.0.0.1",
                        "address": "127.0.0.1",
                        "port": 80,
                        "state": "not_a_state",
                    }
                ],
            }
        )


def test_validate_report_data_rejects_missing_results():
    with pytest.raises(ValueError, match="missing required keys"):
        validate_report_data(
            {
                "target_expression": "127.0.0.1",
                "ports": [80],
                "options": {
                    "timeout": 0.75,
                    "concurrency": 100,
                    "rate_limit": 200.0,
                    "technique": "connect",
                },
            }
        )
