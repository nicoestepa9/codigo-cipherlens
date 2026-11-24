"""Tests del motor de alertas (expiración, scan y compliance)."""

from datetime import date, timedelta

from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.models import (
    Alert,
    Certificate,
    ComplianceWindow,
    Finding,
    Scan,
)
from tls_analyzer.alerts_engine import (
    generate_compliance_alerts,
    generate_expiration_alerts,
    generate_scan_alerts,
)


def _cert(**kwargs) -> Certificate:
    c = Certificate(
        domain="expiring.example.com",
        subject_cn="expiring.example.com",
        issuer_cn="Test CA",
        fingerprint_sha256="fp-test-1",
    )
    for k, v in kwargs.items():
        setattr(c, k, v)
    return c


def test_expiration_alert_created_for_expired_cert():
    db = SessionLocal()
    try:
        db.add(_cert(is_expired=True, not_after="2026-01-01", days_until_expiry=-10))
        db.commit()
        n = generate_expiration_alerts(db)
        assert n >= 1
        alert = db.query(Alert).filter(
            Alert.type == "expiration", Alert.related_target == "expiring.example.com"
        ).first()
        assert alert is not None
        assert alert.severity == "critical"
        assert alert.status == "unread"
    finally:
        db.rollback()
        db.query(Alert).filter(Alert.related_target == "expiring.example.com").delete()
        db.query(Certificate).filter(Certificate.fingerprint_sha256 == "fp-test-1").delete()
        db.commit()
        db.close()


def test_expiration_alert_upserts_not_duplicates():
    db = SessionLocal()
    try:
        db.add(_cert(is_expired=True, not_after="2026-01-01", days_until_expiry=-5))
        db.commit()
        generate_expiration_alerts(db)
        generate_expiration_alerts(db)
        count = db.query(Alert).filter(
            Alert.type == "expiration", Alert.related_target == "expiring.example.com"
        ).count()
        assert count == 1
    finally:
        db.rollback()
        db.query(Alert).filter(Alert.related_target == "expiring.example.com").delete()
        db.query(Certificate).filter(Certificate.fingerprint_sha256 == "fp-test-1").delete()
        db.commit()
        db.close()


def test_scan_alert_created_for_critical_finding():
    db = SessionLocal()
    try:
        class FakeScan:
            id = "scan-x"
            host = "vuln.example.com"

        n = generate_scan_alerts(db, FakeScan(), [
            {"severity": "critical", "title": "TLS 1.0", "description": "d",
             "affectedHost": "vuln.example.com", "evaluable": True},
            {"severity": "low", "title": "minor", "description": "d",
             "affectedHost": "vuln.example.com", "evaluable": True},
        ])
        assert n == 1
        alert = db.query(Alert).filter(Alert.related_scan_id == "scan-x").first()
        assert alert is not None
        assert alert.type == "vulnerability"
        assert alert.severity == "critical"
    finally:
        db.rollback()
        db.query(Alert).filter(Alert.related_scan_id == "scan-x").delete()
        db.commit()
        db.close()


def test_compliance_alert():
    db = SessionLocal()
    try:
        window = ComplianceWindow(
            name="PCI-DSS scope",
            framework="PCI-DSS",
            audit_date=(date.today() + timedelta(days=10)).isoformat(),
            scope_filter=["payments.internal.company.com"],
        )
        db.add(window)
        db.add(Scan(
            id="scan-x",
            host="payments.internal.company.com",
            port=443,
            target="payments.internal.company.com:443",
        ))
        db.add(Finding(
            scan_id="scan-x",
            rule_id="CERT-01",
            title="TLS 1.0",
            description="d",
            severity="critical",
            affected_host="payments.internal.company.com",
            evaluable=True,
        ))
        db.commit()
        n = generate_compliance_alerts(db)
        assert n >= 1
    finally:
        db.rollback()
        db.query(ComplianceWindow).filter(ComplianceWindow.name == "PCI-DSS scope").delete()
        db.query(Finding).filter(Finding.scan_id == "scan-x").delete()
        db.query(Scan).filter(Scan.id == "scan-x").delete()
        db.query(Alert).filter(Alert.type == "compliance").delete()
        db.commit()
        db.close()
