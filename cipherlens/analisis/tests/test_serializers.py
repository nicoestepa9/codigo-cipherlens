"""Tests de los serializadores del motor hacia el contrato del frontend (F0)."""

from tls_analyzer import serializers
from tls_analyzer.handshake import HandshakeResult
from tls_analyzer.scanner import Finding, ScanResult, Severity
from tls_analyzer.certificate import CertificateInfo


def test_score_to_status_thresholds():
    assert serializers.score_to_status(80) == "secure"
    assert serializers.score_to_status(100) == "secure"
    assert serializers.score_to_status(50) == "warning"
    assert serializers.score_to_status(79) == "warning"
    assert serializers.score_to_status(0) == "critical"
    assert serializers.score_to_status(49) == "critical"


def test_finding_dto_severity_mapping():
    f = Finding(
        id="CERT-01",
        title="TLS 1.0 enabled",
        description="desc",
        severity=Severity.CRITICAL,
        category="Protocol",
        recommendation="disable",
        section_reference="SP 800-52 3.3",
        citation="shall not be used",
        observed_value="TLSv1.0",
    )
    dto = serializers.finding_dto(f.to_dict(), "example.com", "2026-08-07T00:00:00Z")
    assert dto["severity"] == "critical"
    assert dto["affectedHost"] == "example.com"
    assert dto["ruleId"] == "CERT-01"
    assert dto["evaluable"] is True
    assert dto["sectionReference"] == "SP 800-52 3.3"


def test_finding_dto_not_evaluable_maps_to_info():
    f = Finding(
        id="NE-01", title="FIPS module", description="d",
        severity=Severity.NOT_EVALUABLE, category="Configuration",
    )
    dto = serializers.finding_dto(f.to_dict(), "host", "2026-08-07T00:00:00Z")
    assert dto["severity"] == "info"
    assert dto["evaluable"] is False


def test_certificate_dto_status_mapping():
    cert = {
        "subject": {"CN": "example.com"},
        "issuer": {"CN": "Let's Encrypt"},
        "san": ["example.com"],
        "is_expired": False,
        "days_until_expiry": 10,
        "fingerprint_sha256": "abc",
    }
    assert serializers.certificate_dto(cert)["status"] == "expiring_soon"

    cert["days_until_expiry"] = 90
    assert serializers.certificate_dto(cert)["status"] == "valid"

    cert["is_expired"] = True
    assert serializers.certificate_dto(cert)["status"] == "expired"


def test_cipher_status_classification():
    assert serializers.cipher_status({"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}) == "secure"
    assert serializers.cipher_status({"name": "TLS_RSA_WITH_AES_128_CBC_SHA"}) == "critical"
    assert serializers.cipher_status({"name": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"}) == "critical"
    assert serializers.cipher_status({"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "protocol": "TLS 1.0"}) == "warning"


def test_scan_result_dto_full():
    hs = HandshakeResult(host="example.com", port=443, ip_address="93.184.216.34")
    hs.negotiated_protocol = "TLSv1.3"
    hs.negotiated_cipher = "TLS_AES_128_GCM_SHA256"
    hs.supported_protocols = ["TLSv1.3", "TLSv1.2"]
    hs.accepted_cipher_suites = [
        {"name": "TLS_AES_128_GCM_SHA256", "protocol": "TLS 1.3", "kea": "", "mac": "", "bits": 128},
        {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "protocol": "TLS 1.2", "kea": "ECDHE", "mac": "SHA256", "bits": 128},
    ]

    result = ScanResult(
        host="example.com", port=443, handshake=hs, score=90,
        findings=[
            Finding(
                id="PROTO-01", title="TLS 1.1 enabled", description="d",
                severity=Severity.MEDIUM, category="Protocol",
            ),
        ],
    )

    dto = serializers.scan_result_dto(
        result, scan_id="scan-1", target="example.com:443",
        scan_started_at="2026-08-07T00:00:00Z", scan_duration_ms=1234,
        ai_recommendation="Keep up the good work.",
    )

    assert dto["id"] == "scan-1"
    assert dto["host"] == "example.com"
    assert dto["port"] == 443
    assert dto["status"] == "secure"
    assert dto["score"] == 90
    assert dto["negotiatedProtocol"] == "TLSv1.3"
    assert dto["negotiatedCipher"] == "TLS_AES_128_GCM_SHA256"
    assert dto["keyExchange"] == ""
    assert len(dto["cipherSuites"]) == 2
    assert dto["cipherSuites"][0]["selected"] is True
    assert dto["findings"][0]["severity"] == "medium"
    assert dto["osFingerprint"]["detected"] is False
    assert dto["handshakeSteps"] == []
    assert dto["aiRecommendation"] == "Keep up the good work."
    assert dto["connectionError"] is None
    assert dto["certificate"]["id"] == ""
