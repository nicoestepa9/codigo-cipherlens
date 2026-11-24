"""Organization-specific AI provider selection and admin audit coverage."""

from uuid import uuid4

from fastapi.testclient import TestClient

from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import AuditLog, Organization, User
from tls_analyzer.api.services import scan_service
from tls_analyzer.api.tenancy import set_system_session, set_tenant_session


def test_only_external_tenant_sends_ai_request(monkeypatch):
    from tls_analyzer import ai_recommendations

    calls = []

    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "## Hallazgos críticos y altos\nPROTO-01: disable weak TLS.",
                    }
                ]
            }

        def raise_for_status(self):
            return None

    class FakeHttpxClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, **kwargs):
            calls.append(url)
            return Response()

    monkeypatch.setattr(ai_recommendations.httpx, "Client", FakeHttpxClient)
    monkeypatch.setattr(ai_recommendations.settings, "ai_provider", "anthropic")
    monkeypatch.setattr(ai_recommendations.settings, "ai_api_key", "test-key")

    suffix = uuid4().hex
    db = SessionLocal()
    set_system_session(db)
    external = Organization(
        name=f"AI external {suffix}", slug=f"ai-ext-{suffix}", ai_mode="external"
    )
    template = Organization(
        name=f"AI template {suffix}", slug=f"ai-tpl-{suffix}", ai_mode="template"
    )
    db.add_all([external, template])
    db.commit()
    db.refresh(external)
    db.refresh(template)
    external_id, template_id = external.id, template.id

    try:
        findings = [
            {
                "ruleId": "PROTO-01",
                "title": "Weak protocol",
                "severity": "critical",
                "description": "TLS protocol needs remediation.",
                "recommendation": "Disable weak TLS.",
            }
        ]
        set_tenant_session(db, external_id)
        external_text, external_source = scan_service.generate_tenant_recommendation(
            db, 40, findings, "external.example"
        )
        set_tenant_session(db, template_id)
        template_text, template_source = scan_service.generate_tenant_recommendation(
            db, 40, findings, "template.example"
        )
        assert external_source == "ai"
        assert "PROTO-01" in external_text
        assert template_source == "template"
        assert "template.example" in template_text
        assert len(calls) == 1
    finally:
        set_system_session(db)
        db.query(Organization).filter(
            Organization.id.in_((external_id, template_id))
        ).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_admin_ai_mode_change_is_audited():
    db = SessionLocal()
    organization = db.query(Organization).first()
    old_mode = organization.ai_mode
    organization_id = organization.id
    organization.ai_mode = "external"
    db.commit()
    db.close()

    try:
        with TestClient(app) as client:
            response = client.put("/api/settings/ai-mode", json={"mode": "template"})
        assert response.status_code == 200, response.text
        assert response.json()["mode"] == "template"
        db = SessionLocal()
        try:
            event = db.query(AuditLog).filter(
                AuditLog.action == "organization.ai_mode_changed",
                AuditLog.organization_id == organization_id,
            ).order_by(AuditLog.ts.desc()).first()
            assert event is not None
            assert event.meta["new_mode"] == "template"
        finally:
            db.close()
    finally:
        db = SessionLocal()
        organization = db.get(Organization, organization_id)
        if organization is not None:
            organization.ai_mode = old_mode
        db.query(AuditLog).filter(
            AuditLog.action == "organization.ai_mode_changed",
            AuditLog.organization_id == organization_id,
        ).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_non_admin_cannot_change_organization_ai_mode():
    from tls_analyzer.api.services.auth_service import create_access_token

    db = SessionLocal()
    organization = db.query(Organization).first()
    user = User(
        email=f"ai-mode-user-{uuid4().hex}@example.test",
        name="AI mode user",
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
            response = client.put(
                "/api/settings/ai-mode",
                headers={"Authorization": f"Bearer {token}"},
                json={"mode": "external"},
            )
        assert response.status_code == 403
    finally:
        db = SessionLocal()
        db.query(User).filter(User.id == user_id).delete(synchronize_session=False)
        db.commit()
        db.close()
