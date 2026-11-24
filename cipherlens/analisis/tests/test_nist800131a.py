"""Tests for the NIST SP 800-131A Rev.2 compliance detector."""

import json
from datetime import date
from pathlib import Path

import pytest

from tls_analyzer import nist800131a
from tls_analyzer.nist800131a import (
    NISTEvaluationError,
    STATUS_ACCEPTABLE,
    STATUS_DEPRECATED,
    STATUS_DISALLOWED,
    STATUS_LEGACY_USE,
    classify,
    evaluate,
)

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


def _finding(report: dict, rule_id: str) -> dict:
    return next(f for f in report["findings"] if f["id"] == rule_id)


def test_github_fixture_passes_clean():
    with open(SCANS_DIR / "github.com_443_20260727_214545.json", encoding="utf-8") as f:
        data = json.load(f)
    report = evaluate(data)
    assert report["summary"]["disallowed"] == 0
    assert "SIG-06" in _ids(report)
    assert "HASH-04" in _ids(report)
    assert report["evaluated_against"] == "NIST SP 800-131A Rev.2 (March 2019)"


def test_clean_data_no_disallowed():
    report = evaluate(_clean_data())
    assert report["summary"]["disallowed"] == 0
    assert "SIG-06" in _ids(report)


def test_weak_rsa_signature_is_disallowed():
    data = _clean_data()
    data["certificate_chain"][0]["key_type"] = "RSA"
    data["certificate_chain"][0]["key_size"] = 1024
    report = evaluate(data)
    sig01 = _finding(report, "SIG-01")
    assert sig01["status"] == STATUS_DISALLOWED
    assert sig01["severity"] == "CRITICAL"


def test_sha1_signature_is_disallowed():
    data = _clean_data()
    data["certificate_chain"][0]["signature_algorithm"] = "sha1WithRSAEncryption"
    report = evaluate(data)
    hash01 = _finding(report, "HASH-01")
    assert hash01["status"] == STATUS_DISALLOWED


def test_p192_curve_signing_is_disallowed():
    data = _clean_data()
    data["certificate_chain"][0]["key_type"] = "EC (secp192r1)"
    data["certificate_chain"][0]["key_size"] = 192
    report = evaluate(data)
    sig03 = _finding(report, "SIG-03")
    assert sig03["status"] == STATUS_DISALLOWED


def test_p256_curve_is_acceptable_signature():
    data = _clean_data()
    report = evaluate(data)
    sig06 = _finding(report, "SIG-06")
    assert sig06["status"] == STATUS_ACCEPTABLE


def test_3des_in_2026_is_disallowed():
    data = _clean_data()
    data["handshake"]["negotiated_cipher"] = "DES-CBC3-SHA"
    data["handshake"]["accepted_cipher_suites"] = [
        {"name": "DES-CBC3-SHA", "protocol": "TLSv1.2", "bits": 112, "kea": "kx-rsa"},
    ]
    report = evaluate(data)
    blk02 = _finding(report, "BLK-02")
    assert blk02["status"] == STATUS_DISALLOWED
    assert blk02["severity"] == "CRITICAL"


def test_3des_before_2024_is_deprecated():
    data = _clean_data()
    data["handshake"]["negotiated_cipher"] = "DES-CBC3-SHA"
    data["handshake"]["accepted_cipher_suites"] = [
        {"name": "DES-CBC3-SHA", "protocol": "TLSv1.2", "bits": 112, "kea": "kx-rsa"},
    ]
    report = evaluate(data, evaluation_date=date(2022, 6, 1))
    blk03 = _finding(report, "BLK-03")
    assert blk03["status"] == STATUS_DEPRECATED


def test_rsa_key_transport_in_2026_is_critical():
    data = _clean_data()
    data["certificate_chain"][0]["key_type"] = "RSA"
    data["certificate_chain"][0]["key_size"] = 2048
    data["handshake"]["negotiated_cipher"] = "TLS_RSA_WITH_AES_128_CBC_SHA"
    data["handshake"]["accepted_cipher_suites"] = [
        {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "protocol": "TLSv1.2", "bits": 128, "kea": "kx-rsa"},
    ]
    report = evaluate(data)
    rsa02 = _finding(report, "RSA-02")
    assert rsa02["status"] == STATUS_DISALLOWED
    assert rsa02["severity"] == "CRITICAL"


@pytest.mark.parametrize("source", ["negotiated", "accepted"])
def test_openssl_static_rsa_alias_does_not_require_iana_input(source):
    data = _clean_data()
    hs = data["handshake"]
    hs["accepted_cipher_suites"].append({"name": "UNKNOWN-SUITE"})
    if source == "negotiated":
        hs["negotiated_cipher"] = "AES128-GCM-SHA256"
    else:
        hs["accepted_cipher_suites"].append({"name": "AES128-GCM-SHA256"})

    report = evaluate(data)
    finding = _finding(report, "RSA-02")
    assert finding["severity"] == "CRITICAL"
    assert "TLS_RSA_WITH_AES_128_GCM_SHA256" in finding["observed_value"]
    assert "RSA-04" not in _ids(report)


def test_ecdhe_with_rsa_authentication_does_not_use_rsa_transport():
    data = _clean_data()
    data["handshake"]["negotiated_cipher"] = "ECDHE-RSA-AES128-GCM-SHA256"
    ids = _ids(evaluate(data))
    assert "RSA-04" in ids
    assert "RSA-02" not in ids


@pytest.mark.parametrize(
    ("name", "bits", "disallowed"),
    [
        ("AES-128-ECB", 128, True),
        ("AES_96_GCM", 128, True),
        ("ECDHE-RSA-AES128-GCM-SHA256", 96, True),
        ("ECDHE-RSA-AES128-GCM-SHA256", 128, False),
        ("TLS_AES_256_GCM_SHA384", 256, False),
        ("FAKE-ECB", 64, False),
    ],
)
def test_aes_mode_and_key_size(name, bits, disallowed):
    data = _clean_data()
    data["handshake"]["negotiated_cipher"] = name
    data["handshake"]["accepted_cipher_suites"] = [{"name": name, "bits": bits}]
    report = evaluate(data)
    if disallowed:
        finding = _finding(report, "BLK-06")
        assert finding["severity"] == "CRITICAL"
        assert finding["status"] == STATUS_DISALLOWED
        assert "BLK-05" not in _ids(report)
    else:
        assert "BLK-06" not in _ids(report)


def test_aes_ecb_is_detected_in_accepted_suites_even_when_gcm_is_negotiated():
    data = _clean_data()
    data["handshake"]["accepted_cipher_suites"].append({"name": "TLS_RSA_WITH_AES_128_ECB_SHA256"})

    report = evaluate(data)
    assert "ECB" in _finding(report, "BLK-06")["observed_value"]
    assert "GCM" in _finding(report, "BLK-05")["observed_value"]


def test_aes_key_size_can_come_from_negotiated_cipher_metadata():
    data = _clean_data()
    hs = data["handshake"]
    hs["accepted_cipher_suites"] = []
    hs["cipher_info"] = {"name": hs["negotiated_cipher"], "bits": 96}

    assert _finding(evaluate(data), "BLK-06")["severity"] == "CRITICAL"


def test_x25519_group_is_not_evaluable_with_note():
    data = _clean_data()
    report = evaluate(data)
    dh06 = _finding(report, "DH-06")
    assert dh06["status"] == "NOT_EVALUABLE"
    assert "x25519" in dh06["title"].lower() or "x25519" in dh06["observed_value"].lower()


def test_sha1_used_as_hmac_does_not_trigger_hash01():
    data = _clean_data()
    data["handshake"]["negotiated_cipher"] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    data["handshake"]["accepted_cipher_suites"] = [
        {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "protocol": "TLSv1.2", "bits": 128, "kea": "kx-ecdhe"},
    ]
    report = evaluate(data)
    assert "HASH-01" not in _ids(report)


def test_missing_handshake_raises():
    with pytest.raises(NISTEvaluationError, match="handshake"):
        evaluate({"host": "x.com"})


def test_tolerates_empty_certificate_chain():
    data = _clean_data()
    data["certificate_chain"] = []
    report = evaluate(data)  # should not raise
    assert report["host"] == "example.com"


def test_classify_states():
    assert classify("3des", None, "encrypt", date(2026, 1, 1))["status"] == STATUS_DISALLOWED
    assert classify("3des", None, "encrypt", date(2022, 1, 1))["status"] == STATUS_DEPRECATED
    assert classify("3des", None, "decrypt", date(2026, 1, 1))["status"] == STATUS_LEGACY_USE
    assert classify("2tdea", None, "encrypt", date(2026, 1, 1))["status"] == STATUS_DISALLOWED
    assert classify("aes-128-gcm", None, "encrypt", date(2026, 1, 1))["status"] == STATUS_ACCEPTABLE
    assert classify("rsa", 1024, "sign", date(2026, 1, 1))["status"] == STATUS_DISALLOWED
    assert classify("rsa", 1024, "verify", date(2026, 1, 1))["status"] == STATUS_LEGACY_USE
    assert classify("rsa", 2048, "sign", date(2026, 1, 1))["status"] == STATUS_ACCEPTABLE
    assert classify("ecdsa", 192, "sign", date(2026, 1, 1))["status"] == STATUS_DISALLOWED
    assert classify("ecdsa", 192, "verify", date(2026, 1, 1))["status"] == STATUS_LEGACY_USE
    assert classify("ecdsa", 256, "sign", date(2026, 1, 1))["status"] == STATUS_ACCEPTABLE
    assert classify("sha1", None, "sign", date(2026, 1, 1))["status"] == STATUS_DISALLOWED
    assert classify("sha1", None, "mac", date(2026, 1, 1))["status"] == STATUS_ACCEPTABLE
    assert classify("sha256", None, "sign", date(2026, 1, 1))["status"] == STATUS_ACCEPTABLE
