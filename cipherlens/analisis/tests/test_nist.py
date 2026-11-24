"""Tests for the NIST SP 800-52 Rev.2 compliance detector."""

import json
import os
from pathlib import Path

import pytest

from tls_analyzer import nist
from tls_analyzer.nist import NISTEvaluationError, evaluate, load_scan_file
from tls_analyzer.scanner import Severity, scan, build_eval_data
from tls_analyzer.handshake import HandshakeResult
from tls_analyzer.certificate import CertificateInfo
from tls_analyzer.cli import _nist_input_kind

SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


def _ids(report: dict) -> list[str]:
    return [f.get("id") for f in report.get("findings", [])]


def _clean_data(**overrides) -> dict:
    """Build a 'clean' scan JSON that should trigger almost no rules."""
    data = {
        "host": "example.com",
        "port": 443,
        "handshake": {
            "negotiated_protocol": "TLSv1.3",
            "negotiated_cipher": "TLS_AES_128_GCM_SHA256",
            "supported_protocols": ["TLS 1.2", "TLS 1.3"],
            "accepted_cipher_suites": [
                {"name": "ECDHE-RSA-AES128-GCM-SHA256", "protocol": "TLSv1.2", "bits": 128, "kea": "kx-ecdhe"},
            ],
            "rejected_cipher_suites": [],
            "server_hello_extensions": {
                "compression_method": 0,
                "extensions": [
                    {"type": 51, "type_name": "key_share", "length": 36},
                ],
            },
        },
        "certificate_chain": [
            {
                "subject": {"CN": "example.com"},
                "issuer": {"CN": "Example CA"},
                "not_before": "2025-01-01T00:00:00+00:00",
                "not_after": "2026-01-01T00:00:00+00:00",
                "is_expired": False,
                "days_until_expiry": 100,
                "san": ["example.com"],
                "key_type": "EC (secp256r1)",
                "key_size": 256,
                "signature_algorithm": "ecdsa-with-SHA256",
                "is_self_signed": False,
                "basic_constraints": "CA=False, pathLen=None",
                "key_usage": ["digitalSignature"],
                "extended_key_usage": ["serverAuth"],
                "ca_issuers": ["http://example.com/ca.crt"],
                "ocsp_responders": ["http://ocsp.example.com"],
                "crl_distribution_points": [],
            }
        ],
    }
    data.update(overrides)
    return data


@pytest.mark.parametrize("suite", ["ECDHE-RSA-AES128-SHA256", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"])
@pytest.mark.parametrize("has_encrypt_then_mac", [False, True])
def test_cbc_alias_and_iana_require_encrypt_then_mac(suite, has_encrypt_then_mac):
    data = _clean_data()
    handshake = data["handshake"]
    handshake["negotiated_protocol"] = "TLSv1.2"
    handshake["negotiated_cipher"] = suite
    handshake["server_hello_extensions"]["extensions"] = (
        [{"type": 0x0016}] if has_encrypt_then_mac else []
    )
    ids = _ids(evaluate(data))
    assert ("CIPH-07" in ids) is not has_encrypt_then_mac
    assert "CIPH-02" not in ids


def test_github_fixture_ciph05_and_no_proto05():
    with open(SCANS_DIR / "github.com_443_20260727_214545.json", encoding="utf-8") as f:
        data = json.load(f)
    report = evaluate(data, profile="citizen-facing")

    ids = _ids(report)
    assert "CIPH-05" in ids
    assert "PROTO-05" not in ids
    assert "CERT-01" not in ids
    assert report["summary"]["medium"] == 1
    assert report["summary"]["not_evaluable"] == 7
    assert report["host"] == "github.com"
    assert report["profile"] == "citizen-facing"
    assert report["evaluated_against"] == "NIST SP 800-52 Rev.2 (Aug 2019)"

    ciph05 = next(f for f in report["findings"] if f["id"] == "CIPH-05")
    assert ciph05["severity"] == "MEDIUM"
    assert "3.3.1.1" in ciph05["section_reference"]
    assert ciph05["citation"]
    assert ciph05["observed_value"]
    assert ciph05["recommendation"]


def test_clean_data_no_high_or_critical():
    report = evaluate(_clean_data())
    ids = _ids(report)
    assert not any(i.startswith("PROTO-") for i in ids if i != "PROTO-06")
    assert "CERT-01" not in ids
    assert "CERT-03" not in ids
    assert "CERT-06" not in ids
    assert "CERT-07" not in ids
    assert report["summary"]["high"] == 0
    assert report["summary"]["critical"] == 0


def test_tls10_citizen_facing_is_medium():
    data = _clean_data()
    data["handshake"]["supported_protocols"] = ["TLS 1.0", "TLS 1.2", "TLS 1.3"]
    report = evaluate(data, profile="citizen-facing")
    ids = _ids(report)
    assert "PROTO-02" in ids
    assert "PROTO-03" not in ids
    proto02 = next(f for f in report["findings"] if f["id"] == "PROTO-02")
    assert proto02["severity"] == "MEDIUM"


def test_tls10_government_is_high():
    data = _clean_data()
    data["handshake"]["supported_protocols"] = ["TLS 1.0", "TLS 1.2", "TLS 1.3"]
    report = evaluate(data, profile="government-only")
    ids = _ids(report)
    assert "PROTO-03" in ids
    proto03 = next(f for f in report["findings"] if f["id"] == "PROTO-03")
    assert proto03["severity"] == "HIGH"


def test_expired_cert_is_critical():
    data = _clean_data()
    data["certificate_chain"][0]["is_expired"] = True
    report = evaluate(data)
    cert01 = next(f for f in report["findings"] if f["id"] == "CERT-01")
    assert cert01["severity"] == "CRITICAL"


def test_weak_rsa_cert_is_critical():
    data = _clean_data()
    data["certificate_chain"][0]["key_type"] = "RSA"
    data["certificate_chain"][0]["key_size"] = 1024
    report = evaluate(data)
    ids = _ids(report)
    assert "CERT-03" in ids
    assert "CERT-05" in ids


def test_missing_handshake_raises_clear_error():
    with pytest.raises(NISTEvaluationError, match="handshake"):
        evaluate({"host": "x.com"})


def test_invalid_profile_raises():
    with pytest.raises(NISTEvaluationError, match="[Pp]erfil"):
        evaluate(_clean_data(), profile="invalid")


def test_tolerates_missing_cert_fields():
    data = _clean_data()
    data["certificate_chain"][0].clear()
    report = evaluate(data)  # should not raise
    assert report["host"] == "example.com"


def test_tolerates_empty_certificate_chain():
    data = _clean_data()
    data["certificate_chain"] = []
    report = evaluate(data)  # should not raise
    assert report["host"] == "example.com"


def test_load_scan_file_not_found():
    with pytest.raises(NISTEvaluationError, match="[Nn]o encontrado"):
        load_scan_file("no_such_file.json")


def test_load_scan_file_invalid_json(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(NISTEvaluationError, match="JSON"):
        load_scan_file(str(bad))


def test_load_scan_file_missing_key(tmp_path):
    f = tmp_path / "scan.json"
    f.write_text('{"host": "x.com"}', encoding="utf-8")
    with pytest.raises(NISTEvaluationError, match="handshake"):
        load_scan_file(str(f))


def test_scan_nist_integration_proto05():
    handshake = HandshakeResult(host="legacy.com", port=443)
    handshake.negotiated_protocol = "TLSv1.2"
    handshake.negotiated_cipher = "ECDHE-RSA-AES128-GCM-SHA256"
    handshake.supported_protocols = ["TLS 1.2"]
    handshake.accepted_cipher_suites = [
        {"name": "ECDHE-RSA-AES128-GCM-SHA256", "protocol": "TLSv1.2", "bits": 128, "kea": "kx-ecdhe"},
    ]

    cert = CertificateInfo(
        subject={"CN": "legacy.com"},
        issuer={"CN": "CA"},
        not_before="2025-01-01T00:00:00+00:00",
        not_after="2026-01-01T00:00:00+00:00",
        is_expired=False,
        days_until_expiry=100,
        san=["legacy.com"],
        key_type="EC (secp256r1)",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        is_self_signed=False,
        basic_constraints="CA=False, pathLen=None",
        extended_key_usage=["serverAuth"],
        ca_issuers=["http://ca.example/ca.crt"],
        ocsp_responders=["http://ocsp.example"],
    )

    result = scan(handshake, [cert], "legacy.com")
    ids = [f.id for f in result.findings]
    assert "PROTO-05" in ids
    assert result.profile == "citizen-facing"

    proto05 = next(f for f in result.findings if f.id == "PROTO-05")
    assert proto05.severity == Severity.MEDIUM
    assert proto05.section_reference == "SP 800-52 Rev.2, Section 3.1"
    assert proto05.citation


def test_scan_not_evaluable_severity():
    handshake = HandshakeResult(host="x.com", port=443)
    handshake.negotiated_protocol = "TLSv1.3"
    handshake.negotiated_cipher = "TLS_AES_128_GCM_SHA256"
    handshake.supported_protocols = ["TLS 1.3"]
    handshake.accepted_cipher_suites = [
        {"name": "TLS_AES_128_GCM_SHA256", "protocol": "TLSv1.3", "bits": 128, "kea": "tls13"},
    ]

    result = scan(handshake, [], "x.com")
    ne = [f for f in result.findings if f.severity == Severity.NOT_EVALUABLE]
    assert ne
    assert result.summary()["not_evaluable"] == len(ne)


def test_compression_non_null_is_high():
    data = _clean_data()
    data["handshake"]["server_hello_extensions"]["compression_method"] = 1
    report = evaluate(data)
    comp01 = next(f for f in report["findings"] if f["id"] == "COMP-01")
    assert comp01["severity"] == "HIGH"


def test_nist_input_kind_detects_file_vs_target(tmp_path):
    json_file = tmp_path / "scan.json"
    json_file.write_text("{}", encoding="utf-8")

    assert _nist_input_kind("scans/whatever.json") == "file"
    assert _nist_input_kind(str(json_file)) == "file"
    assert _nist_input_kind("https://www.youtube.com/") == "target"
    assert _nist_input_kind("example.com") == "target"
    assert _nist_input_kind("example.com:8443") == "target"


def test_build_eval_data_produces_spec_json_and_evaluates():
    handshake = HandshakeResult(host="example.com", port=443)
    handshake.negotiated_protocol = "TLSv1.3"
    handshake.negotiated_cipher = "TLS_AES_128_GCM_SHA256"
    handshake.supported_protocols = ["TLS 1.3"]
    handshake.accepted_cipher_suites = [
        {"name": "TLS_AES_128_GCM_SHA256", "protocol": "TLSv1.3", "bits": 128, "kea": "tls13"},
    ]

    cert = CertificateInfo(
        subject={"CN": "example.com"},
        issuer={"CN": "CA"},
        not_before="2025-01-01T00:00:00+00:00",
        not_after="2026-01-01T00:00:00+00:00",
        is_expired=False,
        days_until_expiry=100,
        san=["example.com"],
        key_type="EC (secp256r1)",
        key_size=256,
        signature_algorithm="ecdsa-with-SHA256",
        is_self_signed=False,
        basic_constraints="CA=False, pathLen=None",
        extended_key_usage=["serverAuth"],
        ca_issuers=["http://ca.example/ca.crt"],
        ocsp_responders=["http://ocsp.example"],
    )

    data = build_eval_data(handshake, [cert])
    assert data["host"] == "example.com"
    assert data["port"] == 443
    assert "handshake" in data
    assert "certificate_chain" in data
    assert len(data["certificate_chain"]) == 1

    report = evaluate(data, profile="citizen-facing")
    assert report["host"] == "example.com"
    assert "findings" in report
    assert all(f.get("severity") for f in report["findings"])
