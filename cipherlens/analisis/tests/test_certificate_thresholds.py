"""El status de inventario y el dashboard respetan el umbral de expiracion."""

from fastapi.testclient import TestClient

from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import Certificate, Organization
from tls_analyzer.api.tenancy import set_system_session


def _create_certificate(domain: str, days_until_expiry: int) -> tuple[str, int]:
    db = SessionLocal()
    try:
        set_system_session(db)
        org = db.query(Organization).order_by(Organization.id).first()
        assert org is not None
        cert = Certificate(
            organization_id=org.id,
            domain=domain,
            subject_cn=domain,
            issuer_cn="Threshold Test CA",
            not_after="2030-01-01T00:00:00Z",
            days_until_expiry=days_until_expiry,
            is_expired=days_until_expiry < 0,
            status="valid",
        )
        db.add(cert)
        db.commit()
        return cert.id, org.id
    finally:
        db.close()


def test_inventory_status_uses_configured_warning_threshold(clean_db_after):
    domain = "threshold-test.example"
    cert_id, _ = _create_certificate(domain, 45)

    with TestClient(app) as client:
        resp = client.put(
            "/api/settings/thresholds",
            json={"criticalDays": 7, "warningDays": 60},
        )
        assert resp.status_code == 200

        resp = client.get("/api/certificates", params={"search": domain})
        assert resp.status_code == 200
        assert resp.json()["items"][0]["status"] == "expiring_soon"

        resp = client.get("/api/certificates", params={"search": domain, "status": "valid"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

        resp = client.get(
            "/api/certificates", params={"search": domain, "status": "expiring_soon"}
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

        resp = client.get(f"/api/certificates/{cert_id}")
        assert resp.status_code == 200
        assert resp.json()["certificate"]["status"] == "expiring_soon"

        resp = client.get("/api/certificates/expiration-stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["criticalDays"] == 7
        assert stats["warningDays"] == 60
        assert stats["warning"] >= 1

        resp = client.get("/api/dashboard")
        assert resp.status_code == 200
        assert resp.json()["certificateWarningDays"] == 60
        assert resp.json()["certificatesExpiringSoon"] >= 1

        resp = client.put(
            "/api/settings/thresholds",
            json={"criticalDays": 7, "warningDays": 30},
        )
        assert resp.status_code == 200

        resp = client.get("/api/certificates", params={"search": domain, "status": "valid"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

        resp = client.get(
            "/api/certificates", params={"search": domain, "status": "expiring_soon"}
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0
