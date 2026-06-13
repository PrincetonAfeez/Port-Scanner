"""Report schema validation for portsleuth CLI."""

from __future__ import annotations

from typing import Any

from portsleuth.models import ProbeState, ScanState, Technique

_REQUIRED_TOP_LEVEL = ("target_expression", "ports", "options", "results")
_REQUIRED_OPTIONS = ("timeout", "concurrency", "rate_limit", "technique")
_REQUIRED_RESULT = ("target", "address", "port", "state")
_VALID_STATES = {item.value for item in ScanState}
_VALID_TECHNIQUES = {item.value for item in Technique}
_VALID_PROBE_STATES = {item.value for item in ProbeState}


def validate_report_data(data: Any) -> None:
    if not isinstance(data, dict):
        raise ValueError("report root must be a JSON object")

    missing = [key for key in _REQUIRED_TOP_LEVEL if key not in data]
    if missing:
        raise ValueError(f"report missing required keys: {', '.join(missing)}")

    if not isinstance(data["ports"], list):
        raise ValueError("'ports' must be a list")
    for index, port in enumerate(data["ports"]):
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError(f"ports[{index}] must be an integer from 1 to 65535")

    if not isinstance(data["results"], list):
        raise ValueError("'results' must be a list")

    options = data["options"]
    if not isinstance(options, dict):
        raise ValueError("'options' must be an object")
    missing_options = [key for key in _REQUIRED_OPTIONS if key not in options]
    if missing_options:
        raise ValueError(f"report options missing required keys: {', '.join(missing_options)}")

    timeout = options["timeout"]
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("options.timeout must be a positive number")
    rate_limit = options["rate_limit"]
    if not isinstance(rate_limit, (int, float)) or rate_limit < 0:
        raise ValueError("options.rate_limit must be zero or greater")
    if not isinstance(options["concurrency"], int) or options["concurrency"] < 1:
        raise ValueError("options.concurrency must be an integer >= 1")
    if options["technique"] not in _VALID_TECHNIQUES:
        raise ValueError(f"options.technique must be one of: {', '.join(sorted(_VALID_TECHNIQUES))}")
    for key in ("probe", "probe_insecure"):
        if key in options and not isinstance(options[key], bool):
            raise ValueError(f"options.{key} must be a boolean when present")

    summary = data.get("authorization_summary")
    if summary is not None:
        _validate_authorization_summary(summary)

    for index, item in enumerate(data["results"]):
        _validate_result_item(item, index)


def _validate_authorization_summary(summary: Any) -> None:
    if not isinstance(summary, dict):
        raise ValueError("authorization_summary must be an object")
    for key in ("authorized", "requires_audit"):
        if key not in summary or not isinstance(summary[key], bool):
            raise ValueError(f"authorization_summary.{key} must be a boolean")
    if "reason" in summary and summary["reason"] is not None and not isinstance(summary["reason"], str):
        raise ValueError("authorization_summary.reason must be a string or null")
    categories = summary.get("categories")
    if categories is None or not isinstance(categories, list) or not all(isinstance(item, str) for item in categories):
        raise ValueError("authorization_summary.categories must be a list of strings")


def _validate_result_item(item: Any, index: int) -> None:
    if not isinstance(item, dict):
        raise ValueError(f"results[{index}] must be an object")
    missing_result = [key for key in _REQUIRED_RESULT if key not in item]
    if missing_result:
        raise ValueError(f"results[{index}] missing required keys: {', '.join(missing_result)}")
    port = item["port"]
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"results[{index}].port must be an integer from 1 to 65535")
    if not isinstance(item["target"], str) or not isinstance(item["address"], str):
        raise ValueError(f"results[{index}].target and .address must be strings")
    if item["state"] not in _VALID_STATES:
        raise ValueError(f"results[{index}].state must be a known scan state")
    if "http" in item and item["http"] is not None:
        _validate_http_probe(item["http"], index)
    if "tls" in item and item["tls"] is not None:
        _validate_tls_probe(item["tls"], index)


def _validate_http_probe(http: Any, index: int) -> None:
    if not isinstance(http, dict):
        raise ValueError(f"results[{index}].http must be an object")
    state = http.get("state")
    if state not in _VALID_PROBE_STATES:
        raise ValueError(f"results[{index}].http.state must be a known probe state")
    for key in ("method", "path"):
        if key not in http or not isinstance(http[key], str):
            raise ValueError(f"results[{index}].http.{key} must be a string")
    if "http_version" in http and http["http_version"] is not None and not isinstance(http["http_version"], str):
        raise ValueError(f"results[{index}].http.http_version must be a string or null")


def _validate_tls_probe(tls: Any, index: int) -> None:
    if not isinstance(tls, dict):
        raise ValueError(f"results[{index}].tls must be an object")
    if "ok" not in tls or not isinstance(tls["ok"], bool):
        raise ValueError(f"results[{index}].tls.ok must be a boolean")
