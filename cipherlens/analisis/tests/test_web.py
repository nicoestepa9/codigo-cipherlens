"""Tests for the Flask web interface."""

import json

from flask import render_template

from tls_analyzer.handshake import HandshakeResult
from tls_analyzer.scanner import ScanResult, Finding, Severity
from tls_analyzer.web.app import create_app


def _sample_result() -> ScanResult:
    hs = HandshakeResult(host="example.com", port=443)
    hs.negotiated_protocol = "TLSv1.3"
    hs.negotiated_cipher = "TLS_AES_128_GCM_SHA256"
    r = ScanResult(host="example.com", port=443, handshake=hs, score=90)
    r.findings = [
        Finding(
            id="CIPH-05",
            title="RC4 en uso",
            description="El servidor ofrece cipher suites RC4.",
            severity=Severity.MEDIUM,
            category="Cipher Suite",
            recommendation="Quitar RC4.",
            section_reference="SP 800-52 Rev.2, Section 3.3.1.1",
            citation="RC4 shall not be used",
            observed_value="RC4-SHA",
        ),
        Finding(
            id="NE-01",
            title="Validacion de modulo criptografico FIPS 140",
            description="No se puede evaluar desde el JSON.",
            severity=Severity.NOT_EVALUABLE,
            category="Configuration",
            recommendation="Requiere acceso al servidor.",
            section_reference="SP 800-52 Rev.2, Section 3.3.3",
            citation="cryptographic modules shall be validated to FIPS 140",
        ),
    ]
    return r


def test_scan_data_script_is_valid_json():
    app = create_app()
    with app.test_request_context():
        html = render_template("index.html", result=_sample_result())

    marker = 'id="scan-data"'
    start = html.index(marker) + len('id="scan-data" type="application/json">')
    end = html.index("</script>", start)
    payload = html[start:end]

    assert "&#34;" not in payload
    data = json.loads(payload)
    assert data["host"] == "example.com"
    assert data["port"] == 443
    assert len(data["findings"]) == 2
    assert data["findings"][0]["id"] == "CIPH-05"


def test_index_page_renders():
    app = create_app()
    resp = app.test_client().get("/")
    assert resp.status_code == 200
    assert b"TLS Analyzer" in resp.data
    assert b"cloud-scan-authorization" in resp.data
    assert b"2026-10-v1" in resp.data


def test_standalone_scan_routes_require_consent_and_are_dev_only(monkeypatch):
    from tls_analyzer.web import app as web_app_module

    client = create_app().test_client()
    missing_api_consent = client.post("/api/scan", json={"target": "example.com"})
    missing_form_consent = client.post("/scan", data={"target": "example.com"})
    assert missing_api_consent.status_code == 422
    assert missing_form_consent.status_code == 422

    monkeypatch.setattr(web_app_module.settings, "env", "production")
    disabled = client.post(
        "/api/scan",
        json={
            "target": "example.com",
            "authorizationAccepted": True,
            "authorizationVersion": "2026-10-v1",
        },
    )
    assert disabled.status_code == 422
    assert "solo está disponible en desarrollo" in disabled.json["error"]


def test_download_endpoint_returns_file():
    app = create_app()
    resp = app.test_client().post("/download", json=_sample_result().to_dict())
    assert resp.status_code == 200
    assert resp.mimetype == "application/json"
    parsed = json.loads(resp.data)
    assert parsed["_meta"]["target"] == "example.com:443"
    assert parsed["host"] == "example.com"
