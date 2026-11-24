"""El email es unico global: un duplicado en otra org debe dar 409, no 500."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tls_analyzer.api import models
from tls_analyzer.api.config import settings
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.services import auth_service
from tls_analyzer.api.tenancy import set_system_session


def test_duplicate_email_in_another_organization_returns_409(monkeypatch):
    monkeypatch.setattr(settings, "disable_api_auth", False)
    suffix = uuid4().hex[:8]
    email = f"shared-{suffix}@example.com"
    db = SessionLocal()
    set_system_session(db)
    try:
        org_a = models.Organization(
            name=f"Email A {suffix}", slug=f"email-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"Email B {suffix}", slug=f"email-b-{suffix}", status="active"
        )
        db.add_all([org_a, org_b])
        db.commit()
        db.refresh(org_a)
        db.refresh(org_b)
        admin = models.User(
            email=f"admin-{suffix}@example.com",
            name="Admin",
            password_hash="x",
            role="admin",
            organization_id=org_a.id,
        )
        existing = models.User(
            email=email,
            name="Existing",
            password_hash="x",
            role="user",
            organization_id=org_b.id,
        )
        db.add_all([admin, existing])
        db.commit()
        db.refresh(admin)
        token = auth_service.create_access_token(admin.id, "admin")
        org_ids = [org_a.id, org_b.id]
        user_ids = [admin.id, existing.id]
    finally:
        db.close()

    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/users",
                json={
                    "email": email,
                    "name": "Duplicado",
                    "password": "Sup3rSecret!pass",
                    "role": "user",
                },
                headers={"Authorization": f"Bearer {token}"},
            )
        assert response.status_code == 409
        assert "email" in response.json()["detail"].lower()
    finally:
        cleanup = SessionLocal()
        set_system_session(cleanup)
        try:
            cleanup.query(models.User).filter(
                models.User.id.in_(user_ids)
            ).delete(synchronize_session=False)
            cleanup.query(models.Organization).filter(
                models.Organization.id.in_(org_ids)
            ).delete(synchronize_session=False)
            cleanup.commit()
        finally:
            cleanup.close()
