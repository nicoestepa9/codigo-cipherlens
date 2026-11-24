"""Tests de permisos por rol (admin/lead/user) sobre issues y equipos."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tls_analyzer.api.config import settings
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import (
    Issue,
    Organization,
    Service,
    Team,
    TeamMember,
    User,
)
from tls_analyzer.api.services import auth_service, team_service, user_service

PASSWORD = "Sup3rSecret!pass"


@pytest.fixture()
def auth_on(monkeypatch):
    monkeypatch.setattr(settings, "disable_api_auth", False)
    monkeypatch.setattr(settings, "auth_rate_limit_per_minute", 10000)
    yield


@pytest.fixture(autouse=True)
def _clean():
    db = SessionLocal()
    try:
        db.query(Issue).delete()
        db.query(TeamMember).delete()
        db.query(Team).delete()
        db.query(Service).delete()
        db.commit()
    finally:
        db.close()
    yield


def _org(db) -> Organization:
    org = db.query(Organization).order_by(Organization.id).first()
    if org is None:
        org = Organization(name="CryptoGuard")
        db.add(org)
        db.flush()
    return org


def _user(db, email: str, role: str) -> User:
    u = user_service.get_by_email(db, email)
    if u is None:
        u = user_service.create_user(
            db, email=email, name=email, password=PASSWORD,
            role=role, organization_id=_org(db).id,
        )
        db.commit()
        db.refresh(u)
    return u


def _headers(user: User) -> dict[str, str]:
    token = auth_service.create_access_token(user.id, user.role)
    return {"Authorization": f"Bearer {token}"}


def _service(db, host="example.com") -> Service:
    s = Service(host=host, port=443, name=host, ip_address="1.2.3.4")
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


_RULE_SEQ = iter(range(1, 10000))


def _issue(db, service: Service, *, owner_user_id=None, owner_team_id=None, status="open") -> Issue:
    issue = Issue(
        service_id=service.id, rule_id=f"R{next(_RULE_SEQ)}", title="t", severity="high",
        source_document="80052", status=status,
        owner_user_id=owner_user_id, owner_team_id=owner_team_id,
    )
    db.add(issue)
    db.commit()
    db.refresh(issue)
    return issue


def test_user_cannot_assign_issue():
    db = SessionLocal()
    try:
        user = _user(db, "u1@example.com", "user")
        other = _user(db, "u2@example.com", "user")
        svc = _service(db)
        issue = _issue(db, svc, owner_user_id=user.id, status="assigned")
        headers = _headers(user)
        iid, oid = issue.id, other.id
    finally:
        db.close()

    with TestClient(app) as client:
        resp = client.patch(f"/api/issues/{iid}", json={"ownerUserId": oid}, headers=headers)
        assert resp.status_code == 403


def test_user_can_change_status_and_comment_own_issue():
    db = SessionLocal()
    try:
        user = _user(db, "u3@example.com", "user")
        svc = _service(db)
        issue = _issue(db, svc, owner_user_id=user.id, status="assigned")
        headers = _headers(user)
        iid = issue.id
    finally:
        db.close()

    with TestClient(app) as client:
        resp = client.patch(f"/api/issues/{iid}", json={"status": "in_progress"}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "in_progress"

        resp = client.post(f"/api/issues/{iid}/comment", json={"comment": "trabajando"}, headers=headers)
        assert resp.status_code == 200


def test_user_cannot_work_on_unassigned_issue():
    db = SessionLocal()
    try:
        user = _user(db, "u4@example.com", "user")
        svc = _service(db)
        issue = _issue(db, svc, owner_user_id=None, status="open")
        headers = _headers(user)
        iid = issue.id
    finally:
        db.close()

    with TestClient(app) as client:
        assert client.patch(f"/api/issues/{iid}", json={"status": "in_progress"}, headers=headers).status_code == 403
        assert client.post(f"/api/issues/{iid}/comment", json={"comment": "x"}, headers=headers).status_code == 403
        assert client.get(f"/api/issues/{iid}", headers=headers).status_code == 403


def test_lead_assigns_only_team_members():
    db = SessionLocal()
    try:
        lead = _user(db, "lead1@example.com", "lead")
        m1 = _user(db, "m1@example.com", "user")
        m2 = _user(db, "m2@example.com", "user")
        outsider = _user(db, "out1@example.com", "user")
        team = team_service.create(db, name="Team Lead", description="", member_ids_in=None, organization_id=_org(db).id)
        team_service.add_member(db, team, m1.id)
        team_service.add_member(db, team, m2.id)
        team_service.add_member(db, team, lead.id, is_lead=True)
        db.commit()
        svc = _service(db)
        issue = _issue(db, svc, owner_user_id=m1.id, status="assigned")
        headers = _headers(lead)
        iid = issue.id
        m2id, outid, team_id = m2.id, outsider.id, team.id
    finally:
        db.close()

    with TestClient(app) as client:
        ok = client.patch(f"/api/issues/{iid}", json={"ownerUserId": m2id}, headers=headers)
        assert ok.status_code == 200
        assert ok.json()["ownerUserId"] == m2id

        bad = client.patch(f"/api/issues/{iid}", json={"ownerUserId": outid}, headers=headers)
        assert bad.status_code == 403

        bad_team = client.patch(f"/api/issues/{iid}", json={"ownerTeamId": team_id}, headers=headers)
        assert bad_team.status_code == 403


def test_lead_and_user_list_scope():
    db = SessionLocal()
    try:
        lead = _user(db, "lead2@example.com", "lead")
        member = _user(db, "m3@example.com", "user")
        outsider = _user(db, "out2@example.com", "user")
        team = team_service.create(db, name="Team Two", description="", member_ids_in=None, organization_id=_org(db).id)
        team_service.add_member(db, team, member.id)
        team_service.add_member(db, team, lead.id, is_lead=True)
        db.commit()
        svc = _service(db)
        i_member = _issue(db, svc, owner_user_id=member.id, status="assigned")
        i_lead = _issue(db, svc, owner_user_id=lead.id, status="assigned")
        i_out = _issue(db, svc, owner_user_id=outsider.id, status="assigned")
        lead_h, member_h = _headers(lead), _headers(member)
    finally:
        db.close()

    with TestClient(app) as client:
        resp = client.get("/api/issues", headers=lead_h)
        assert resp.status_code == 200
        lead_ids = {i["id"] for i in resp.json()["items"]}
        assert i_member.id in lead_ids and i_lead.id in lead_ids
        assert i_out.id not in lead_ids

        resp = client.get("/api/issues", headers=member_h)
        assert resp.status_code == 200
        member_ids = {i["id"] for i in resp.json()["items"]}
        assert member_ids == {i_member.id}


def test_user_member_sees_and_works_team_assigned_issue():
    db = SessionLocal()
    try:
        member = _user(db, "team_member@example.com", "user")
        outsider = _user(db, "team_outsider@example.com", "user")
        team = team_service.create(
            db, name="Team Work", description="", member_ids_in=None,
            organization_id=_org(db).id,
        )
        team_service.add_member(db, team, member.id)
        db.commit()
        svc = _service(db)
        i_team = _issue(db, svc, owner_team_id=team.id, status="assigned")
        i_direct = _issue(db, svc, owner_user_id=member.id, status="assigned")
        member_h, outsider_h = _headers(member), _headers(outsider)
    finally:
        db.close()

    with TestClient(app) as client:
        mine = client.get("/api/issues?mine=true", headers=member_h)
        assert mine.status_code == 200
        assert {i["id"] for i in mine.json()["items"]} == {i_team.id, i_direct.id}

        listing = client.get("/api/issues", headers=member_h)
        assert listing.status_code == 200
        assert i_team.id in {i["id"] for i in listing.json()["items"]}

        assert client.get(f"/api/issues/{i_team.id}", headers=member_h).status_code == 200
        worked = client.patch(
            f"/api/issues/{i_team.id}", json={"status": "in_progress"}, headers=member_h
        )
        assert worked.status_code == 200
        assert worked.json()["status"] == "in_progress"
        assert client.post(
            f"/api/issues/{i_team.id}/comment", json={"comment": "trabajando"}, headers=member_h
        ).status_code == 200

        outsider_mine = client.get("/api/issues?mine=true", headers=outsider_h)
        assert outsider_mine.status_code == 200
        assert i_team.id not in {i["id"] for i in outsider_mine.json()["items"]}
        assert client.get(f"/api/issues/{i_team.id}", headers=outsider_h).status_code == 403


def test_lead_sees_team_assigned_issue():
    db = SessionLocal()
    try:
        lead = _user(db, "lead_team@example.com", "lead")
        outsider = _user(db, "lead_other@example.com", "lead")
        team = team_service.create(
            db, name="Team Owners", description="", member_ids_in=None,
            organization_id=_org(db).id,
        )
        other = team_service.create(
            db, name="Team Elsewhere", description="", member_ids_in=None,
            organization_id=_org(db).id,
        )
        team_service.add_member(db, team, lead.id, is_lead=True)
        team_service.add_member(db, other, outsider.id, is_lead=True)
        db.commit()
        svc = _service(db)
        i_team = _issue(db, svc, owner_team_id=team.id, status="assigned")
        lead_h, out_h = _headers(lead), _headers(outsider)
    finally:
        db.close()

    with TestClient(app) as client:
        # El lead del equipo ve, en el listado, el issue asignado a su equipo.
        resp = client.get("/api/issues", headers=lead_h)
        assert resp.status_code == 200
        assert i_team.id in {i["id"] for i in resp.json()["items"]}

        # Y puede abrir el detalle.
        det = client.get(f"/api/issues/{i_team.id}", headers=lead_h)
        assert det.status_code == 200

        # Un lead de otro equipo no lo ve ni en el listado ni en el detalle.
        resp2 = client.get("/api/issues", headers=out_h)
        assert i_team.id not in {i["id"] for i in resp2.json()["items"]}
        assert client.get(f"/api/issues/{i_team.id}", headers=out_h).status_code == 403


def test_user_can_read_settings_but_not_modify_admin_settings(auth_on):
    db = SessionLocal()
    try:
        user = _user(db, "settings_reader@example.com", "user")
        headers = _headers(user)
    finally:
        db.close()

    with TestClient(app) as client:
        assert client.get("/api/settings/organization", headers=headers).status_code == 200
        assert client.get("/api/settings/compliance-windows", headers=headers).status_code == 200
        assert client.get("/api/settings/thresholds", headers=headers).status_code == 200

        thresholds = {
            "daysBeforeExpiry": [30, 7],
            "notifyOnCriticalFinding": True,
            "notifyOnCompliance": True,
            "criticalDays": 7,
            "warningDays": 30,
        }
        assert client.put("/api/settings/thresholds", json=thresholds, headers=headers).status_code == 403
        assert client.put(
            "/api/settings/sla",
            json={"criticalDays": 3, "highDays": 9, "mediumDays": 21},
            headers=headers,
        ).status_code == 403


def test_operator_is_restricted_to_platform_routes(auth_on):
    db = SessionLocal()
    try:
        operator = User(
            email=f"platform-operator-{uuid4().hex[:8]}@example.com",
            name="Platform Operator",
            password_hash="x",
            role="operator",
            organization_id=_org(db).id,
        )
        db.add(operator)
        db.commit()
        db.refresh(operator)
        headers = _headers(operator)
    finally:
        db.close()

    with TestClient(app) as client:
        assert client.get("/api/organizations", headers=headers).status_code == 200
        assert client.get("/api/users/me", headers=headers).status_code == 200

        restricted_paths = (
            "/api/settings/thresholds",
            "/api/settings/organization",
            "/api/assets",
            "/api/dashboard",
            "/api/discovery",
            "/api/scans",
            "/api/alerts",
        )
        for path in restricted_paths:
            response = client.get(path, headers=headers)
            assert response.status_code == 403, f"{path}: {response.text}"


def test_operator_create_organization_requires_admin(auth_on):
    suffix = uuid4().hex[:8]
    slug = f"operator-org-{suffix}"
    operator_email = f"operator-{suffix}@example.com"
    admin_email = f"admin-{suffix}@example.com"

    db = SessionLocal()
    try:
        operator = _user(db, operator_email, "operator")
        headers = _headers(operator)
    finally:
        db.close()

    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/organizations",
                json={
                    "name": "Organizacion sin admin",
                    "slug": slug,
                    "admin_email": "",
                    "admin_name": "",
                    "admin_password": "",
                },
                headers=headers,
            )
            assert response.status_code == 422

            response = client.post(
                "/api/organizations",
                json={
                    "name": "Organizacion con admin",
                    "slug": slug,
                    "admin_email": admin_email,
                    "admin_name": "Admin Inicial",
                    "admin_password": PASSWORD,
                },
                headers=headers,
            )
            assert response.status_code == 200, response.text
            org_id = response.json()["id"]

        db = SessionLocal()
        try:
            admin = user_service.get_by_email(db, admin_email)
            assert admin is not None
            assert admin.role == "admin"
            assert admin.organization_id == org_id
        finally:
            db.close()
    finally:
        db = SessionLocal()
        try:
            db.query(User).filter(
                User.email.in_([operator_email, admin_email])
            ).delete(synchronize_session=False)
            db.query(Organization).filter(Organization.slug == slug).delete(
                synchronize_session=False
            )
            db.commit()
        finally:
            db.close()


def test_lead_team_management_scope():
    db = SessionLocal()
    try:
        lead = _user(db, "lead3@example.com", "lead")
        member = _user(db, "m4@example.com", "user")
        team = team_service.create(db, name="Team Three", description="", member_ids_in=None, organization_id=_org(db).id)
        other = team_service.create(db, name="Team Other", description="", member_ids_in=None, organization_id=_org(db).id)
        team_service.add_member(db, team, lead.id, is_lead=True)
        db.commit()
        lead_h = _headers(lead)
        team_id, other_id, member_id = team.id, other.id, member.id
    finally:
        db.close()

    with TestClient(app) as client:
        assert client.post("/api/teams", json={"name": "Nuevo"}, headers=lead_h).status_code == 403

        ok = client.post(f"/api/teams/{team_id}/members", json={"userId": member_id}, headers=lead_h)
        assert ok.status_code == 200
        assert member_id in ok.json()["memberIds"]

        bad = client.post(f"/api/teams/{other_id}/members", json={"userId": member_id}, headers=lead_h)
        assert bad.status_code == 403

        listed = client.get("/api/teams", headers=lead_h)
        assert listed.status_code == 200
        assert {t["id"] for t in listed.json()} == {team_id}

        resp = client.post(
            f"/api/teams/{team_id}/members",
            json={"userId": member_id, "isLead": True},
            headers=lead_h,
        )
        assert resp.status_code == 200
        assert member_id not in (resp.json().get("leadIds") or [])


def test_delete_user_removes_team_memberships():
    db = SessionLocal()
    try:
        admin = _user(db, "admin_del@example.com", "admin")
        member = _user(db, "u_del@example.com", "user")
        team = team_service.create(
            db, name="Team Delete", description="", member_ids_in=None,
            organization_id=_org(db).id,
        )
        team_service.add_member(db, team, member.id)
        db.commit()
        member_id = member.id
        admin_h = _headers(admin)
    finally:
        db.close()

    with TestClient(app) as client:
        resp = client.delete(f"/api/users/{member_id}", headers=admin_h)
        assert resp.status_code in (200, 204)

    db = SessionLocal()
    try:
        remaining = (
            db.query(TeamMember).filter(TeamMember.user_id == member_id).count()
        )
        assert remaining == 0
    finally:
        db.close()
