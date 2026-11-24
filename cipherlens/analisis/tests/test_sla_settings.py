"""Per-organization SLA settings API and fallback behavior."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tls_analyzer.api.config import settings
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import AuditLog, Organization, User
from tls_analyzer.api.services.auth_service import create_access_token


def test_get_sla_settings_returns_effective_values():
    db = SessionLocal()
    organization = db.query(Organization).order_by(Organization.id).first()
    organization_id = organization.id
    old = (
        organization.sla_days_critical,
        organization.sla_days_high,
        organization.sla_days_medium,
    )
    organization.sla_days_critical = None
    organization.sla_days_high = None
    organization.sla_days_medium = None
    db.commit()
    db.close()

    try:
        with TestClient(app) as client:
            response = client.get("/api/settings/organization")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["slaDaysCritical"] == settings.sla_days_critical
        assert body["slaDaysHigh"] == settings.sla_days_high
        assert body["slaDaysMedium"] == settings.sla_days_medium
    finally:
        db = SessionLocal()
        organization = db.get(Organization, organization_id)
        (
            organization.sla_days_critical,
            organization.sla_days_high,
            organization.sla_days_medium,
        ) = old
        db.commit()
        db.close()


def test_admin_sla_settings_are_persisted_and_audited():
    db = SessionLocal()
    organization = db.query(Organization).order_by(Organization.id).first()
    organization_id = organization.id
    old = (
        organization.sla_days_critical,
        organization.sla_days_high,
        organization.sla_days_medium,
    )
    db.close()

    try:
        with TestClient(app) as client:
            response = client.put(
                "/api/settings/sla",
                json={"criticalDays": 3, "highDays": 9, "mediumDays": 21},
            )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["slaDaysCritical"] == 3
        assert body["slaDaysHigh"] == 9
        assert body["slaDaysMedium"] == 21

        db = SessionLocal()
        try:
            organization = db.get(Organization, organization_id)
            assert organization.sla_days_critical == 3
            assert organization.sla_days_high == 9
            assert organization.sla_days_medium == 21
            event = (
                db.query(AuditLog)
                .filter(
                    AuditLog.action == "organization.sla_changed",
                    AuditLog.organization_id == organization_id,
                )
                .order_by(AuditLog.ts.desc())
                .first()
            )
            assert event is not None
            assert event.meta["new"]["criticalDays"] == 3
        finally:
            db.close()
    finally:
        db = SessionLocal()
        organization = db.get(Organization, organization_id)
        if organization is not None:
            (
                organization.sla_days_critical,
                organization.sla_days_high,
                organization.sla_days_medium,
            ) = old
        db.query(AuditLog).filter(
            AuditLog.action == "organization.sla_changed",
            AuditLog.organization_id == organization_id,
        ).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_sla_settings_reject_invalid_values_and_non_admin():
    db = SessionLocal()
    organization = db.query(Organization).order_by(Organization.id).first()
    user = User(
        email=f"sla-user-{uuid4().hex}@example.test",
        name="SLA user",
        password_hash="unused",
        role="user",
        organization_id=organization.id,
    )
    db.add(user)
    db.commit()
    user_id = user.id
    token = create_access_token(user_id, "user")
    db.close()

    try:
        with TestClient(app) as client:
            invalid = client.put(
                "/api/settings/sla",
                json={"criticalDays": 0, "highDays": 9, "mediumDays": 21},
            )
            forbidden = client.put(
                "/api/settings/sla",
                headers={"Authorization": f"Bearer {token}"},
                json={"criticalDays": 3, "highDays": 9, "mediumDays": 21},
            )
        assert invalid.status_code == 422
        assert forbidden.status_code == 403
    finally:
        db = SessionLocal()
        db.query(User).filter(User.id == user_id).delete(synchronize_session=False)
        db.commit()
        db.close()
