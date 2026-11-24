"""Tests for the NIST SP 800-57 Part 1 Rev.5 compliance detector."""

import json
from datetime import date
from pathlib import Path

import pytest

from tls_analyzer import nist80057
from tls_analyzer.nist80057 import NISTEvaluationError, evaluate, compute_strengths

SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


def _ids(report: dict) -> list[str]:
    return [f.get("id") for f in report.get("findings", [])]


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
                {"name": "ECDHE-RSA-AES128-GCM-SHA256", "protocol": "TLSv1.2", "bits": 128, "kea": "kx-ecdhe"},
            ],
            "server_hello_extensions": {
                "extensions": [
                    {"type": 51, "group": "0x0017 (secp256r1)", "length": 65},
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


def test_github_fixture_passes_clean():
    with open(SCANS_DIR / "github.com_443_20260727_214545.json", encoding="utf-8") as f:
        data = json.load(f)
    report = evaluate(data)
    assert report["host"] == "github.com"
    assert report["summary"]["critical"] == 0
    assert report["summary"]["high"] == 0
    assert "SCHED-04" in _ids(report)
    assert report["evaluated_against"] == "NIST SP 800-57 Part 1 Rev.5 (May 2020)"


def test_clean_data_no_critical_or_high():
    report = evaluate(_clean_data())
    assert report["summary"]["critical"] == 0
    assert report["summary"]["high"] == 0
    assert "SCHED-04" in _ids(report)


def test_weak_rsa_key_is_critical():
    data = _clean_data()
    data["certificate_chain"][0]["key_type"] = "RSA"
    data["certificate_chain"][0]["key_size"] = 1024
    report = evaluate(data)
    ids = _ids(report)
    assert "KEY-01" in ids
    assert "SCHED-02" in ids
    key01 = next(f for f in report["findings"] if f["id"] == "KEY-01")
    assert key01["severity"] == "CRITICAL"
    assert "Table 2" in key01["section_reference"]


def test_sha1_signature_is_critical():
    data = _clean_data()
    data["certificate_chain"][0]["signature_algorithm"] = "sha1WithRSAEncryption"
    report = evaluate(data)
    ids = _ids(report)
    assert "HASH-01" in ids
    hash01 = next(f for f in report["findings"] if f["id"] == "HASH-01")
    assert hash01["severity"] == "CRITICAL"
    assert "Table 3" in hash01["section_reference"]


def test_3des_cipher_is_critical():
    data = _clean_data()
    data["handshake"]["negotiated_cipher"] = "DES-CBC3-SHA"
    data["handshake"]["accepted_cipher_suites"] = [
        {"name": "DES-CBC3-SHA", "protocol": "TLSv1.2", "bits": 112, "kea": "kx-rsa"},
    ]
    report = evaluate(data)
    assert "KEY-05" in _ids(report)


def test_2tdea_cipher_is_critical():
    data = _clean_data()
    data["handshake"]["negotiated_cipher"] = "DES-EDE2-CBC"
    data["handshake"]["accepted_cipher_suites"] = [
        {"name": "DES-EDE2-CBC", "protocol": "TLSv1.2", "bits": 80, "kea": "kx-rsa"},
    ]
    report = evaluate(data)
    assert "KEY-04" in _ids(report)


def test_112_bit_key_flag_after_2030_schedule():
    data = _clean_data()
    data["certificate_chain"][0]["key_type"] = "RSA"
    data["certificate_chain"][0]["key_size"] = 2048
    data["certificate_chain"][0]["not_after"] = "2032-01-01T00:00:00+00:00"
    report = evaluate(data, evaluation_date=date(2031, 6, 1))
    ids = _ids(report)
    assert "SCHED-01" in ids
    assert "SCHED-03" in ids
    assert "KEY-07" in ids


def test_long_validity_certificate_is_medium():
    data = _clean_data()
    data["certificate_chain"][0]["not_before"] = "2020-01-01T00:00:00+00:00"
    data["certificate_chain"][0]["not_after"] = "2030-01-01T00:00:00+00:00"
    report = evaluate(data)
    assert "CRYPTO-01" in _ids(report)


def test_missing_handshake_raises():
    with pytest.raises(NISTEvaluationError, match="handshake"):
        evaluate({"host": "x.com"})


def test_tolerates_empty_certificate_chain():
    data = _clean_data()
    data["certificate_chain"] = []
    report = evaluate(data)  # should not raise
    assert report["host"] == "example.com"


def test_compute_strengths_effective_minimum():
    data = _clean_data()
    data["certificate_chain"][0]["key_type"] = "RSA"
    data["certificate_chain"][0]["key_size"] = 2048
    data["certificate_chain"][0]["signature_algorithm"] = "sha256WithRSAEncryption"
    strengths = compute_strengths(data)
    assert strengths["certificate_key_strength_bits"] == 112
    assert strengths["signature_hash_strength_bits"] == 128
    assert strengths["cipher_strength_bits"] == 128
    assert strengths["effective_strength_bits"] == 112


def test_cross_standard_consistency_rsa_1024():
    from tls_analyzer import nist800131a

    data = _clean_data()
    data["certificate_chain"][0]["key_type"] = "RSA"
    data["certificate_chain"][0]["key_size"] = 1024
    r57 = evaluate(data)
    r131 = nist800131a.evaluate(data)
    r57_weak = any(f["id"] == "KEY-01" for f in r57["findings"])
    r131_weak = any(f["id"] == "SIG-01" for f in r131["findings"])
    assert r57_weak and r131_weak, "ambos estandares deben marcar RSA-1024 como debil"
