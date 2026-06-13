"""Unit tests for services module in portsleuth CLI."""

from portsleuth.fingerprint.services import confidence_for_service, guess_service


def test_known_port_has_medium_confidence():
    assert confidence_for_service(80, "http") == "medium"


def test_uncurated_named_port_has_low_confidence():
    assert confidence_for_service(9, "discard") == "low"


def test_no_service_has_no_confidence():
    assert confidence_for_service(80, None) is None


def test_guess_service_uses_common_ports_table():
    assert guess_service(22) == "ssh"
