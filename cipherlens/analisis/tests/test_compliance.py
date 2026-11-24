"""Tests for the combined NIST compliance report (evaluate_all)."""

import json
from pathlib import Path

import pytest

from tls_analyzer import compliance
from tls_analyzer.nist import NISTEvaluationError

SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


def _clean_data(**overrides) -> dict:
    data = {
        "host": "example.com",
        "port": 443,
        "_meta": {"scan_time": "2026-07-27 21:45:45"},
        "handshake": {
            "negotiated_protocol": "TLSv1.3",
            "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
            "supported_protocols": ["TLS 1.2", "TLS 1.3"],
            "accepted_cipher_suites": [
                {"name": "TLS_AES_128_GCM_SHA256", "protocol": "TLSv1.3", "bits": 128, "kea": "tls13"},
            ],
            "server_hello_extensions": {
                "extensions": [
                    {"type": 51, "group": "0x001d (x25519)", "length": 32},
                ],
            },
        },
        "certificate_chain": [
            {
                "subject": {"CN": "example.com"},
                "not_before": "2025-01-01T00:00:00+00:00",
                "not_after": "2026-01-01T00:00:00+00:00",
                "is_expired": False,
                "key_type": "EC (secp256r1)",
                "key_size": 256,
                "signature_algorithm": "ecdsa-with-SHA256",
                "is_self_signed": False,
                "basic_constraints": "CA=False, pathLen=None",
                "extended_key_usage": ["serverAuth"],
                "ca_issuers": ["http://example.com/ca.crt"],
                "ocsp_responders": ["http://ocsp.example.com"],
            }
        ],
    }
    data.update(overrides)
    return data


def test_evaluate_all_runs_three_standards():
    report = compliance.evaluate_all(_clean_data())
    assert report["standards"] == ["80052", "80057", "800131a"]
    assert len(report["reports"]) == 3
    assert report["host"] == "example.com"
    assert "evaluation_date" in report


def test_evaluate_all_prefixed_ids_and_standard_field():
    report = compliance.evaluate_all(_clean_data())
    ids = [f["id"] for f in report["findings"]]
    assert any(i.startswith("80052-") for i in ids)
    assert any(i.startswith("80057-") for i in ids)
    assert any(i.startswith("800131a-") for i in ids)
    assert all(f.get("standard") in ("80052", "80057", "800131a") for f in report["findings"])


def test_summary_is_sum_of_reports():
    report = compliance.evaluate_all(_clean_data())
    for key in ("critical", "high", "medium", "info", "not_evaluable"):
        total = sum(r["summary"].get(key, 0) for r in report["reports"])
        assert report["summary"][key] == total, key


def test_evaluate_all_single_standard():
    report = compliance.evaluate_all(_clean_data(), standards=["80052"])
    assert report["standards"] == ["80052"]
    assert len(report["reports"]) == 1
    assert all(f["id"].startswith("80052-") for f in report["findings"])


def test_evaluate_all_github_fixture_clean():
    with open(SCANS_DIR / "github.com_443_20260727_214545.json", encoding="utf-8") as f:
        data = json.load(f)
    report = compliance.evaluate_all(data)
    assert report["host"] == "github.com"
    assert report["summary"]["critical"] == 0
    assert report["summary"]["high"] == 0


def test_evaluate_all_missing_handshake_raises():
    with pytest.raises(NISTEvaluationError, match="handshake"):
        compliance.evaluate_all({"host": "x.com"})
