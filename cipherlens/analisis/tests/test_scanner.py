"""Tests for scanner module."""

from tls_analyzer.scanner import (
    ScanResult,
    Finding,
    Severity,
    calculate_score,
    scan,
)
from tls_analyzer.handshake import HandshakeResult
from tls_analyzer.certificate import CertificateInfo


def test_calculate_score_no_findings():
    score = calculate_score([])
    assert score == 100


def test_calculate_score_critical():
    findings = [Finding(id="T", title="T", description="D", severity=Severity.CRITICAL, category="C")]
    score = calculate_score(findings)
    assert score == 75


def test_calculate_score_multiple():
    findings = [
        Finding(id="T", title="T", description="D", severity=Severity.CRITICAL, category="C"),
        Finding(id="T2", title="T2", description="D", severity=Severity.HIGH, category="C"),
        Finding(id="T3", title="T3", description="D", severity=Severity.MEDIUM, category="C"),
    ]
    score = calculate_score(findings)
    assert score == 52


def test_calculate_score_floor():
    findings = [Finding(id=str(i), title="T", description="D", severity=Severity.CRITICAL, category="C") for i in range(10)]
    score = calculate_score(findings)
    assert score == 0


def test_scan_result_summary():
    result = ScanResult(host="test.com", port=443)
    result.findings = [
        Finding(id="1", title="T", description="D", severity=Severity.CRITICAL, category="C"),
        Finding(id="2", title="T", description="D", severity=Severity.HIGH, category="C"),
    ]
    summary = result.summary()
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["total"] == 2


def test_scan_connection_error():
    handshake = HandshakeResult(host="bad.host", port=443, connection_error="Connection refused")
    result = scan(handshake, [], "bad.host")
    assert result.score == 0
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL


def _rsa1024_sha1_handshake_and_cert():
    handshake = HandshakeResult(host="legacy.com", port=443)
    handshake.negotiated_protocol = "TLSv1.2"
    handshake.negotiated_cipher = "ECDHE-RSA-AES128-GCM-SHA256"
    handshake.supported_protocols = ["TLS 1.2", "TLS 1.3"]
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
        key_type="RSA",
        key_size=1024,
        signature_algorithm="sha1WithRSAEncryption",
        is_self_signed=False,
        basic_constraints="CA=False, pathLen=None",
        extended_key_usage=["serverAuth"],
        ca_issuers=["http://ca.example/ca.crt"],
        ocsp_responders=["http://ocsp.example"],
    )
    return handshake, cert


def test_scan_dedups_weak_rsa_across_standards():
    handshake, cert = _rsa1024_sha1_handshake_and_cert()
    result = scan(handshake, [cert], "legacy.com")

    cert03 = next(f for f in result.findings if f.id == "CERT-03")
    rule_ids = cert03.details["rule_ids"]
    assert "80052-CERT-03" in rule_ids
    assert "80057-KEY-01" in rule_ids
    assert "800131a-SIG-01" in rule_ids

    ids = [f.id for f in result.findings]
    assert "KEY-01" not in ids
    assert "SIG-01" not in ids
    assert "HASH-01" not in ids


def test_scan_dedups_sha1_signature_across_standards():
    handshake, cert = _rsa1024_sha1_handshake_and_cert()
    result = scan(handshake, [cert], "legacy.com")

    cert06 = next(f for f in result.findings if f.id == "CERT-06")
    rule_ids = cert06.details["rule_ids"]
    assert "80052-CERT-06" in rule_ids
    assert "80057-HASH-01" in rule_ids
    assert "800131a-HASH-01" in rule_ids
    assert "80057-HASH-02" in rule_ids


def test_scan_score_deducts_once_per_defect():
    handshake, cert = _rsa1024_sha1_handshake_and_cert()
    result = scan(handshake, [cert], "legacy.com")

    critical = result.summary()["critical"]
    assert critical == 3  # CERT-03, CERT-05, CERT-06 (cada defecto una sola vez)

    expected = 100 - critical * 25 - result.summary()["medium"] * 8
    assert result.score == expected


def test_scan_single_standard_selection():
    handshake, cert = _rsa1024_sha1_handshake_and_cert()
    result = scan(handshake, [cert], "legacy.com", standards=["80052"])
    ids = [f.id for f in result.findings]
    assert "CERT-03" in ids
    assert not any(i.startswith(("KEY-", "SCHED-", "BLK-", "SIG-", "RBG-", "DH-")) for i in ids)
