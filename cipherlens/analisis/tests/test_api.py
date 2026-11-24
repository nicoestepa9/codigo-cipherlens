"""Tests de la API FastAPI (F1-F6) sobre DB en memoria."""

import pytest
from fastapi.testclient import TestClient

from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import Alert, AuditLog


def _client():
    return TestClient(app)


def test_health():
    with _client() as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


def test_dashboard_empty():
    with _client() as client:
        resp = client.get("/api/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["totalServices"] == 0
        assert data["securityScore"] == 0
        assert data["secure"] == 0


def test_certificates_expiration_stats():
    with _client() as client:
        resp = client.get("/api/certificates/expiration-stats")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["byWindow"]) == 4
        assert {"expired", "critical", "warning", "healthy", "total",
                "criticalDays", "warningDays"} <= set(data)


def test_integrations_seeded():
    with _client() as client:
        resp = client.get("/api/integrations")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        assert any(i["type"] == "siem" for i in data)


def test_thresholds_roundtrip():
    with _client() as client:
        resp = client.get("/api/settings/thresholds")
        assert resp.status_code == 200
        assert resp.json()["daysBeforeExpiry"] == [30, 15, 7]

        resp = client.put(
            "/api/settings/thresholds",
            json={"daysBeforeExpiry": [60, 30], "notifyOnCriticalFinding": False,
                  "notifyOnCompliance": True, "criticalDays": 15, "warningDays": 60},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["daysBeforeExpiry"] == [60, 30]
        assert data["notifyOnCriticalFinding"] is False


def test_api_keys_crud():
    with _client() as client:
        resp = client.post("/api/api-keys", json={"name": "ci"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["key"].startswith("cg_")

        resp = client.get("/api/api-keys")
        assert resp.status_code == 200
        keys = resp.json()
        assert len(keys) == 1
        key_id = keys[0]["id"]

        resp = client.delete(f"/api/api-keys/{key_id}")
        assert resp.status_code == 204


def test_vulnerability_list_empty():
    with _client() as client:
        resp = client.get("/api/vulnerabilities", params={"page": 1, "pageSize": 20})
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["pageSize"] == 20


def test_vulnerability_stats_empty():
    with _client() as client:
        resp = client.get("/api/vulnerabilities/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["bySeverity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        assert len(data["overTime"]) == 14


def test_alert_status_update(monkeypatch):
    with _client() as client:
        db = SessionLocal()
        alert = Alert(
            type="system", severity="info", title="Test", description="d",
            status="unread",
        )
        db.add(alert)
        db.commit()
        alert_id = alert.id
        db.close()

        resp = client.put(f"/api/alerts/{alert_id}/status", json={"status": "resolved"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

        resp = client.get("/api/alerts", params={"status": "unread"})
        assert resp.status_code == 200
        assert resp.json() == []


def test_run_scan_endpoint(monkeypatch):
    fake = {
        "id": "scan-1", "target": "example.com:443", "host": "example.com",
        "port": 443, "portIsAlternate": False, "ipAddress": "1.2.3.4",
        "scanStartedAt": "2026-08-07T00:00:00Z", "scanDurationMs": 500,
        "profile": "citizen-facing", "score": 90, "status": "secure",
        "negotiatedProtocol": "TLSv1.3", "negotiatedCipher": "TLS_AES_128_GCM_SHA256",
        "keyExchange": "X25519", "signatureAlgorithm": "sha256WithRSAEncryption",
        "supportedProtocols": ["TLSv1.3", "TLSv1.2"], "cipherSuites": [],
        "certificate": {}, "chain": [], "findings": [],
        "osFingerprint": {"detected": False}, "handshakeSteps": [],
        "aiRecommendation": "ok", "connectionError": None,
    }
    import tls_analyzer.api.routers.scans as scans_router

    observed = {}

    def fake_run_scan(db, target, port=None, options=None, pinned_target=None):
        observed["pinned_target"] = pinned_target
        return fake

    monkeypatch.setattr(scans_router.scan_service, "run_scan", fake_run_scan)
    with _client() as client:
        resp = client.post(
            "/api/scans",
            json={
                "target": "8.8.8.8",
                "port": 443,
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == "scan-1"
        assert resp.json()["status"] == "secure"
        assert observed["pinned_target"].address == "8.8.8.8"


def test_discovery_lifecycle(monkeypatch):
    import tls_analyzer.api.routers.discovery as discovery_router

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setitem(
        discovery_router.start_discovery.__globals__,
        "threading",
        __import__("types").SimpleNamespace(Thread=NoopThread),
    )
    with _client() as client:
        resp = client.post(
            "/api/discovery",
            json={
                "ipRange": "8.8.8.8",
                "ports": [9],
                "domains": [],
                "scanInternal": False,
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert resp.status_code == 200
        job = resp.json()
        assert job["id"]
        assert job["status"] in ("queued", "running", "completed", "failed")

        resp = client.get("/api/discovery/summary")
        assert resp.status_code == 200
        assert "total" in resp.json()

        resp = client.get(f"/api/discovery/{job['id']}")
        assert resp.status_code == 200
        assert resp.json()["id"] == job["id"]


def test_discovery_rejects_oversized_range():
    """Un /16 tarda ~48 min reales, asi que se rechaza antes de crear el job."""
    with _client() as client:
        resp = client.post(
            "/api/discovery",
            json={
                "ipRange": "10.0.0.0/16",
                "ports": [443],
                "domains": [],
                "scanInternal": False,
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert "CLOUD_DISCOVERY_MAX_HOSTS" in detail


def test_discovery_cancel_endpoint(monkeypatch):
    import tls_analyzer.api.routers.discovery as discovery_router

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setitem(
        discovery_router.start_discovery.__globals__,
        "threading",
        __import__("types").SimpleNamespace(Thread=NoopThread),
    )
    with _client() as client:
        resp = client.post(
            "/api/discovery",
            json={
                "ipRange": "8.8.8.8",
                "ports": [443],
                "domains": [],
                "scanInternal": False,
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert resp.status_code == 200
        job_id = resp.json()["id"]

        resp = client.delete(f"/api/discovery/{job_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"

        # Cancelar un job ya terminal es un no-op, no un error.
        resp = client.delete(f"/api/discovery/{job_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cancelled"


def test_discovery_cancel_unknown_job_is_404():
    with _client() as client:
        resp = client.delete("/api/discovery/no-existe")
        assert resp.status_code == 404


def test_cloud_scan_rejects_and_audits_private_destinations(monkeypatch):
    import tls_analyzer.api.routers.scans as scans_router

    monkeypatch.setattr(
        scans_router.scan_service,
        "run_scan",
        lambda *args, **kwargs: pytest.fail("private target reached scan service"),
    )
    with _client() as client:
        response = client.post(
            "/api/scans",
            json={
                "target": "169.254.169.254",
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert response.status_code == 422
        assert "agente" in response.json()["detail"]

    db = SessionLocal()
    try:
        blocked = (
            db.query(AuditLog)
            .filter(AuditLog.action == "cloud_scan.destination_blocked")
            .order_by(AuditLog.ts.desc())
            .first()
        )
        assert blocked is not None
        assert blocked.entity_id == "169.254.169.254"
    finally:
        db.close()


def test_cloud_scan_uses_single_dns_resolution_and_pinned_address(monkeypatch):
    import socket

    from tls_analyzer.cloud_network import (
        open_target_connection,
        resolve_target_addresses,
    )
    import tls_analyzer.api.cloud_guardrails as cloud_guardrails
    import tls_analyzer.api.routers.scans as scans_router

    resolutions = []
    connections = []

    def resolver(host, port, family, socktype):
        resolutions.append(host)
        ip = "8.8.8.8" if len(resolutions) == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    class FakeSocket:
        pass

    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    monkeypatch.setattr(
        cloud_guardrails,
        "resolve_target_addresses",
        lambda host, enforce_public=True: resolve_target_addresses(
            host, enforce_public=enforce_public, resolver=resolver
        ),
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: connections.append(address[0]) or FakeSocket(),
    )

    def fake_scan(db, target, port=None, options=None, pinned_target=None):
        open_target_connection(
            target, port or 443, 1.0, pinned_target=pinned_target
        )
        return {
            "id": "pinned-scan",
            "target": target,
            "host": target,
            "port": port or 443,
            "scanStartedAt": "2026-10-23T00:00:00+00:00",
        }

    monkeypatch.setattr(scans_router.scan_service, "run_scan", fake_scan)
    with _client() as client:
        response = client.post(
            "/api/scans",
            json={
                "target": "rebinding.example",
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
    assert response.status_code == 200, response.text
    assert resolutions == ["rebinding.example"]
    assert connections == ["8.8.8.8"]


def test_cloud_scan_hourly_quota_returns_429_and_is_audited(monkeypatch):
    from tls_analyzer.api import cloud_guardrails
    from tls_analyzer.api.models import Organization
    import tls_analyzer.api.routers.scans as scans_router

    fake = {
        "id": "quota-scan",
        "target": "8.8.8.8:443",
        "host": "8.8.8.8",
        "port": 443,
        "scanStartedAt": "2026-10-23T00:00:00+00:00",
    }
    monkeypatch.setattr(
        cloud_guardrails,
        "resolve_target_addresses",
        lambda host, enforce_public=True: ("8.8.8.8",),
    )
    monkeypatch.setattr(scans_router.scan_service, "run_scan", lambda *a, **k: fake)

    db = SessionLocal()
    organization = db.query(Organization).first()
    original_limit = organization.max_cloud_scans_per_hour
    organization.max_cloud_scans_per_hour = 1
    db.query(AuditLog).filter(
        AuditLog.action.in_(
            ("cloud_scan.started", "cloud_discovery.started", "cloud_scan.scheduled_started")
        )
    ).delete(synchronize_session=False)
    db.commit()
    db.close()
    try:
        request = {
            "target": "8.8.8.8",
            "authorizationAccepted": True,
            "authorizationVersion": "2026-10-v1",
        }
        with _client() as client:
            first = client.post("/api/scans", json=request)
            second = client.post("/api/scans", json=request)
        assert first.status_code == 200, first.text
        assert second.status_code == 429
        db = SessionLocal()
        try:
            rejected = db.query(AuditLog).filter(
                AuditLog.action == "cloud_scan.quota_rejected"
            ).first()
            assert rejected is not None
            assert rejected.entity_id == "8.8.8.8"
        finally:
            db.close()
    finally:
        db = SessionLocal()
        organization = db.query(Organization).first()
        organization.max_cloud_scans_per_hour = original_limit
        db.query(AuditLog).filter(
            AuditLog.action.in_(
                (
                    "cloud_scan.started",
                    "cloud_scan.authorization_accepted",
                    "cloud_scan.quota_rejected",
                )
            )
        ).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_cloud_discovery_rejects_internal_cidr_and_scan_internal_flag():
    with _client() as client:
        private_range = client.post(
            "/api/discovery",
            json={
                "ipRange": "10.0.0.0/30",
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert private_range.status_code == 422
        assert "agente" in private_range.json()["detail"]

        forced_internal = client.post(
            "/api/discovery",
            json={
                "ipRange": "8.8.8.8",
                "scanInternal": True,
                "authorizationAccepted": True,
                "authorizationVersion": "2026-10-v1",
            },
        )
        assert forced_internal.status_code == 422


def test_docs_endpoint():
    with _client() as client:
        resp = client.get("/api/docs")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 0
        assert any(e["path"] == "/api/scans" for e in data)


def test_openapi_has_scans_path():
    with _client() as client:
        schema = client.get("/openapi.json").json()
        assert "/api/scans" in schema["paths"]
        assert "/api/dashboard" in schema["paths"]
        assert "/api/discovery" in schema["paths"]


def test_cloud_scan_rejects_without_authorization():
    """Falta authorizationAccepted/authorizationVersion en cloud scan → 422."""
    with _client() as client:
        missing = client.post(
            "/api/scans", json={"target": "8.8.8.8", "port": 443}
        )
        stale = client.post(
            "/api/scans",
            json={
                "target": "8.8.8.8",
                "port": 443,
                "authorizationAccepted": True,
                "authorizationVersion": "old-version",
            },
        )
        assert missing.status_code == stale.status_code == 422


def test_discovery_rejects_without_authorization():
    """Falta authorizationAccepted/authorizationVersion en discovery → 422."""
    with _client() as client:
        missing = client.post(
            "/api/discovery",
            json={"ipRange": "8.8.8.8", "ports": [9], "domains": [], "scanInternal": False},
        )
        stale = client.post(
            "/api/discovery",
            json={
                "ipRange": "8.8.8.8",
                "ports": [9],
                "domains": [],
                "scanInternal": False,
                "authorizationAccepted": True,
                "authorizationVersion": "old-version",
            },
        )
        assert missing.status_code == stale.status_code == 422
