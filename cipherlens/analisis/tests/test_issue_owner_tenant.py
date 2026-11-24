"""No se puede asignar un issue a un usuario/equipo de otra organizacion."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from tls_analyzer.api import models
from tls_analyzer.api.config import settings
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.services import auth_service
from tls_analyzer.api.tenancy import set_system_session


def test_issue_owner_must_belong_to_current_organization(monkeypatch):
    monkeypatch.setattr(settings, "disable_api_auth", False)
    suffix = uuid4().hex[:8]
    db = SessionLocal()
    set_system_session(db)
    try:
        org_a = models.Organization(
            name=f"Owner A {suffix}", slug=f"owner-a-{suffix}", status="active"
        )
        org_b = models.Organization(
            name=f"Owner B {suffix}", slug=f"owner-b-{suffix}", status="active"
        )
        db.add_all([org_a, org_b])
        db.commit()
        db.refresh(org_a)
        db.refresh(org_b)

        admin_a = models.User(
            email=f"owner-admin-{suffix}@example.com",
            name="Admin A",
            password_hash="x",
            role="admin",
            organization_id=org_a.id,
        )
        local_user = models.User(
            email=f"owner-local-{suffix}@example.com",
            name="Local",
            password_hash="x",
            role="user",
            organization_id=org_a.id,
        )
        foreign_user = models.User(
            email=f"owner-foreign-{suffix}@example.com",
            name="Foreign",
            password_hash="x",
            role="user",
            organization_id=org_b.id,
        )
        local_team = models.Team(
            name=f"Local Team {suffix}", organization_id=org_a.id
        )
        foreign_team = models.Team(
            name=f"Foreign Team {suffix}", organization_id=org_b.id
        )
        db.add_all([admin_a, local_user, foreign_user, local_team, foreign_team])
        db.commit()
        service = models.Service(
            host=f"owner-{suffix}.example.com",
            port=443,
            organization_id=org_a.id,
        )
        db.add(service)
        db.commit()
        issue = models.Issue(
            service_id=service.id,
            rule_id="CERT-01",
            title="Expirado",
            severity="critical",
            organization_id=org_a.id,
        )
        db.add(issue)
        db.commit()
        token = auth_service.create_access_token(admin_a.id, "admin")
        org_ids = [org_a.id, org_b.id]
        issue_id = issue.id
        service_id = service.id
        team_ids = [local_team.id, foreign_team.id]
        user_ids = [admin_a.id, local_user.id, foreign_user.id]
        foreign_user_id = foreign_user.id
        foreign_team_id = foreign_team.id
        local_user_id = local_user.id
        local_team_id = local_team.id
    finally:
        db.close()

    headers = {"Authorization": f"Bearer {token}"}
    try:
        with TestClient(app) as client:
            foreign_user_resp = client.patch(
                f"/api/issues/{issue_id}",
                json={"ownerUserId": foreign_user_id},
                headers=headers,
            )
            foreign_team_resp = client.patch(
                f"/api/issues/{issue_id}",
                json={"ownerTeamId": foreign_team_id},
                headers=headers,
            )
            bulk_resp = client.post(
                "/api/issues/assign",
                json={
                    "issueIds": [issue_id],
                    "ownerUserId": foreign_user_id,
                },
                headers=headers,
            )
            local_resp = client.patch(
                f"/api/issues/{issue_id}",
                json={"ownerUserId": local_user_id},
                headers=headers,
            )
            local_team_resp = client.patch(
                f"/api/issues/{issue_id}",
                json={"ownerTeamId": local_team_id},
                headers=headers,
            )
        assert foreign_user_resp.status_code == 422
        assert foreign_team_resp.status_code == 422
        assert bulk_resp.status_code == 422
        assert local_resp.status_code == 200
        assert local_team_resp.status_code == 200
    finally:
        cleanup = SessionLocal()
        set_system_session(cleanup)
        try:
            cleanup.query(models.IssueHistory).filter(
                models.IssueHistory.issue_id == issue_id
            ).delete(synchronize_session=False)
            cleanup.query(models.Issue).filter(
                models.Issue.id == issue_id
            ).delete(synchronize_session=False)
            cleanup.query(models.Service).filter(
                models.Service.id == service_id
            ).delete(synchronize_session=False)
            cleanup.query(models.Team).filter(
                models.Team.id.in_(team_ids)
            ).delete(synchronize_session=False)
            cleanup.query(models.User).filter(
                models.User.id.in_(user_ids)
            ).delete(synchronize_session=False)
            cleanup.query(models.Organization).filter(
                models.Organization.id.in_(org_ids)
            ).delete(synchronize_session=False)
            cleanup.commit()
        finally:
            cleanup.close()
