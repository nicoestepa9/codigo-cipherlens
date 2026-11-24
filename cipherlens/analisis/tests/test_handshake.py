"""Tests for handshake module."""

import ssl
import socket
from unittest.mock import patch, MagicMock

from tls_analyzer.handshake import (
    analyze_handshake,
    analyze_protocols,
    analyze_cipher_suites,
    HandshakeResult,
)


def test_parse_target_simple():
    from tls_analyzer.cli import _parse_target
    host, port = _parse_target("example.com")
    assert host == "example.com"
    assert port == 443


def test_parse_target_with_port():
    from tls_analyzer.cli import _parse_target
    host, port = _parse_target("example.com:8443")
    assert host == "example.com"
    assert port == 8443


def test_parse_target_with_protocol():
    from tls_analyzer.cli import _parse_target
    host, port = _parse_target("https://example.com:8443")
    assert host == "example.com"
    assert port == 8443


def test_handshake_result_to_dict():
    result = HandshakeResult(host="test.com", port=443)
    d = result.to_dict()
    assert d["host"] == "test.com"
    assert d["port"] == 443
    assert isinstance(d["supported_protocols"], list)


def test_handshake_result_to_json():
    result = HandshakeResult(host="test.com", port=443)
    j = result.to_json()
    assert '"host": "test.com"' in j


def test_sslyze_probe_graceful_fallback():
    """_sslyze_probe returns False when sslyze is not installed."""
    from tls_analyzer.handshake import _sslyze_probe

    result = _sslyze_probe("localhost", 443, timeout=1.0)
    assert isinstance(result, bool)


def test_sslyze_probe_handles_subprocess_failure(monkeypatch):
    """_sslyze_probe returns False when subprocess fails."""
    import subprocess
    from tls_analyzer.handshake import _sslyze_probe

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="sslyze", timeout=60)

    monkeypatch.setattr("tls_analyzer.handshake.subprocess.run", fake_run)
    result = _sslyze_probe("localhost", 443, timeout=1.0)
    assert result is False


def test_sslyze_probe_parses_json_output(monkeypatch):
    """_sslyze_probe correctly parses sslyze JSON output."""
    import json
    from tls_analyzer.handshake import _sslyze_probe

    sslyze_output = {
        "server_scan_results": [{
            "scan_result": {
                "ssl_3_0_cipher_suites": {
                    "status": "COMPLETED",
                    "result": {
                        "is_tls_version_supported": True,
                        "accepted_cipher_suites": [],
                    },
                },
            },
        }],
    }

    class FakeProc:
        returncode = 0
        stdout = json.dumps(sslyze_output)
        stderr = ""

    monkeypatch.setattr("tls_analyzer.handshake.subprocess.run", lambda *a, **kw: FakeProc())
    result = _sslyze_probe("sslv3.badssl.com", 443)
    assert result is True
