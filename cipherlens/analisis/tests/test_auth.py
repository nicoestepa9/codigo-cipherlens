"""Tests de la capa de autenticacion (Parte 1) con auth global habilitada."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from uuid import uuid4

from tls_analyzer.api.config import settings
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.deps import hash_api_key
from tls_analyzer.api.main import app
from tls_analyzer.api.models import (
    Agent, ApiKey, AuditLog, Organization, RefreshToken, User,
)
from tls_analyzer.api.services import auth_service, user_service
from tls_analyzer.api.tenancy import set_system_session

PASSWORD = "Sup3rSecret!pass"


@pytest.fixture()
def auth_on(monkeypatch):
    """Activa auth global durante el test y lo restaura al final."""
    monkeypatch.setattr(settings, "disable_api_auth", False)
    monkeypatch.setattr(settings, "auth_rate_limit_per_minute", 10000)
    monkeypatch.setattr(settings, "login_max_failures", 5)
    yield


def _make_user(role: str, email: str) -> str:
    db = SessionLocal()
    try:
        org = db.query(Organization).order_by(Organization.id).first()
        if org is None:
            org = Organization(name="CryptoGuard")
            db.add(org)
            db.flush()
        u = user_service.get_by_email(db, email)
        if u is None:
            u = user_service.create_user(
                db,
                email=email,
                name=email,
                password=PASSWORD,
                role=role,
                organization_id=org.id,
            )
        db.commit()
        return u.id
    finally:
        db.close()


def _login(client: TestClient, email: str, password: str = PASSWORD):
    return client.post("/api/auth/login", json={"email": email, "password": password})


def test_login_fails_generic_message(auth_on):
    _make_user("admin", "admin1@example.com")
    with TestClient(app) as client:
        resp = _login(client, "admin1@example.com", "wrong")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Credenciales invalidas"


def test_login_unknown_user_same_message(auth_on):
    with TestClient(app) as client:
        resp = _login(client, "nobody@example.com", "whatever")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Credenciales invalidas"


def test_login_success_and_me(auth_on):
    _make_user("admin", "admin2@example.com")
    with TestClient(app) as client:
        resp = _login(client, "admin2@example.com")
        assert resp.status_code == 200
        body = resp.json()
        assert body["accessToken"] and body["refreshToken"]
        headers = {"Authorization": f"Bearer {body['accessToken']}"}
        me = client.get("/api/users/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["email"] == "admin2@example.com"
        assert me.json()["role"] == "admin"


def test_disabled_organization_blocks_password_login_refresh_and_api_key(auth_on):
    suffix = uuid4().hex
    db = SessionLocal()
    set_system_session(db)
    try:
        org = Organization(
            name=f"Disabled {suffix}", slug=f"disabled-{suffix}", status="disabled"
        )
        db.add(org)
        db.flush()
        user = user_service.create_user(
            db,
            email=f"disabled-{suffix}@example.com",
            name="Disabled user",
            password=PASSWORD,
            role="admin",
            organization_id=org.id,
        )
        api_key = ApiKey(
            name="disabled test key",
            key_hash=hash_api_key("disabled-key"),
            role="user",
            user_id=user.id,
            organization_id=org.id,
        )
        db.add(api_key)
        db.flush()
        agent_key = ApiKey(
            name="disabled agent key",
            key_hash=hash_api_key("disabled-agent-key"),
            role="agent",
            organization_id=org.id,
        )
        db.add(agent_key)
        db.flush()
        agent = Agent(
            name="Disabled agent",
            organization_id=org.id,
            api_key_id=agent_key.id,
        )
        db.add(agent)

        active_org = Organization(
            name=f"Active {suffix}", slug=f"active-{suffix}", status="active"
        )
        db.add(active_org)
        db.flush()
        active_user = user_service.create_user(
            db,
            email=f"active-{suffix}@example.com",
            name="Active user",
            password=PASSWORD,
            role="admin",
            organization_id=active_org.id,
        )
        active_key = ApiKey(
            name="active test key",
            key_hash=hash_api_key("active-key"),
            role="user",
            user_id=active_user.id,
            organization_id=active_org.id,
        )
        db.add(active_key)
        refresh_token = auth_service.issue_refresh_token(db, user)
        db.commit()
        org_id, user_id, key_id = org.id, user.id, api_key.id
        agent_id, agent_key_id = agent.id, agent_key.id
        active_org_id, active_user_id, active_key_id = (
            active_org.id, active_user.id, active_key.id
        )
    finally:
        db.close()

    try:
        with TestClient(app) as client:
            login = client.post(
                "/api/auth/login",
                json={"email": f"disabled-{suffix}@example.com", "password": PASSWORD},
            )
            assert login.status_code == 401
            refresh = client.post(
                "/api/auth/refresh", json={"refreshToken": refresh_token}
            )
            assert refresh.status_code == 401
            api_key_result = client.get(
                "/api/users/me", headers={"X-API-Key": "disabled-key"}
            )
            assert api_key_result.status_code == 401
            agent_ingest = client.post(
                "/api/agent/heartbeat",
                headers={"X-API-Key": "disabled-agent-key"},
                json={"schemaVersion": 1, "agentVersion": "test"},
            )
            assert agent_ingest.status_code == 401
            active_login = client.post(
                "/api/auth/login",
                json={
                    "email": f"active-{suffix}@example.com",
                    "password": PASSWORD,
                },
            )
            assert active_login.status_code == 200
            active_key_result = client.get(
                "/api/users/me", headers={"X-API-Key": "active-key"}
            )
            assert active_key_result.status_code == 200
            assert active_key_result.json()["email"] == f"active-{suffix}@example.com"
    finally:
        cleanup = SessionLocal()
        set_system_session(cleanup)
        try:
            cleanup.query(Agent).filter(Agent.id == agent_id).delete()
            cleanup.query(ApiKey).filter(
                ApiKey.id.in_([key_id, agent_key_id, active_key_id])
            ).delete(synchronize_session=False)
            cleanup.query(ApiKey).filter(ApiKey.id == key_id).delete()
            cleanup.query(RefreshToken).filter(
                RefreshToken.user_id.in_([user_id, active_user_id])
            ).delete(synchronize_session=False)
            cleanup.query(AuditLog).filter(AuditLog.organization_id == org_id).delete()
            cleanup.query(AuditLog).filter(
                AuditLog.organization_id == active_org_id
            ).delete(synchronize_session=False)
            cleanup.query(User).filter(
                User.id.in_([user_id, active_user_id])
            ).delete(synchronize_session=False)
            cleanup.query(Organization).filter(
                Organization.id.in_([org_id, active_org_id])
            ).delete(synchronize_session=False)
            cleanup.commit()
        finally:
            cleanup.close()


def test_login_reports_and_password_change_clears_forced_change(auth_on):
    suffix = uuid4().hex
    db = SessionLocal()
    try:
        org = db.query(Organization).order_by(Organization.id).first()
        user = user_service.create_user(
            db,
            email=f"forced-{suffix}@example.com",
            name="Forced change user",
            password=PASSWORD,
            role="admin",
            organization_id=org.id,
            must_change_password=True,
        )
        db.commit()
        user_id = user.id
    finally:
        db.close()

    try:
        with TestClient(app) as client:
            first = _login(client, f"forced-{suffix}@example.com")
            assert first.status_code == 200
            assert first.json()["mustChangePassword"] is True
            headers = {"Authorization": f"Bearer {first.json()['accessToken']}"}
            changed = client.post(
                "/api/users/me/password",
                headers=headers,
                json={"currentPassword": PASSWORD, "newPassword": "Changed!12345"},
            )
            assert changed.status_code == 200
            second = _login(client, f"forced-{suffix}@example.com", "Changed!12345")
            assert second.status_code == 200
            assert second.json()["mustChangePassword"] is False
    finally:
        cleanup = SessionLocal()
        try:
            cleanup.query(AuditLog).filter(AuditLog.actor_user_id == user_id).delete()
            cleanup.query(RefreshToken).filter(
                RefreshToken.user_id == user_id
            ).delete(synchronize_session=False)
            cleanup.query(User).filter(User.id == user_id).delete()
            cleanup.commit()
        finally:
            cleanup.close()


def test_refresh_rotation_and_reuse_revokes_chain(auth_on):
    _make_user("lead", "an1@example.com")
    with TestClient(app) as client:
        first = _login(client, "an1@example.com").json()
        old_refresh = first["refreshToken"]

        resp = client.post("/api/auth/refresh", json={"refreshToken": old_refresh})
        assert resp.status_code == 200
        rotated = resp.json()
        assert rotated["refreshToken"] != old_refresh

        # Reuso del token viejo: debe fallar y revocar la cadena
        reuse = client.post("/api/auth/refresh", json={"refreshToken": old_refresh})
        assert reuse.status_code == 401

        # El token nuevo tambien quedo revocado por la cadena
        after = client.post(
            "/api/auth/refresh", json={"refreshToken": rotated["refreshToken"]}
        )
        assert after.status_code == 401


def test_role_enforcement_forbidden(auth_on):
    _make_user("admin", "adm3@example.com")
    _make_user("user", "view3@example.com")
    with TestClient(app) as client:
        admin_token = _login(client, "adm3@example.com").json()["accessToken"]
        view_token = _login(client, "view3@example.com").json()["accessToken"]

        ok = client.get(
            "/api/users", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert ok.status_code == 200

        forbidden = client.get(
            "/api/users", headers={"Authorization": f"Bearer {view_token}"}
        )
        assert forbidden.status_code == 403


def test_missing_credentials_401(auth_on):
    with TestClient(app) as client:
        resp = client.get("/api/users/me")
        assert resp.status_code == 401


def test_global_auth_blocks_any_route(auth_on):
    with TestClient(app) as client:
        assert client.get("/api/dashboard").status_code == 401
        assert client.get("/api/alerts").status_code == 401
        # rutas publicas siguen abiertas
        assert client.get("/health").status_code == 200


def test_audit_log_records_login(auth_on):
    _make_user("admin", "adm4@example.com")
    with TestClient(app) as client:
        _login(client, "adm4@example.com")
        token = _login(client, "adm4@example.com").json()["accessToken"]
        resp = client.get(
            "/api/audit-log", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        actions = [r["action"] for r in resp.json()]
        assert "auth.login" in actions


def test_password_change_requires_current(auth_on):
    uid = _make_user("lead", "an5@example.com")
    with TestClient(app) as client:
        token = _login(client, "an5@example.com").json()["accessToken"]
        headers = {"Authorization": f"Bearer {token}"}

        bad = client.post(
            "/api/users/me/password",
            json={"currentPassword": "nope", "newPassword": "x"},
            headers=headers,
        )
        assert bad.status_code == 400

        good = client.post(
            "/api/users/me/password",
            json={"currentPassword": PASSWORD, "newPassword": "N3wPass!word"},
            headers=headers,
        )
        assert good.status_code == 200

    db = SessionLocal()
    try:
        u = db.get(User, uid)
        assert auth_service.verify_password("N3wPass!word", u.password_hash)
    finally:
        db.close()


def test_delete_me_anonymizes(auth_on):
    uid = _make_user("user", "del1@example.com")
    with TestClient(app) as client:
        token = _login(client, "del1@example.com").json()["accessToken"]
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.delete("/api/users/me", headers=headers)
        assert resp.status_code == 200

    db = SessionLocal()
    try:
        u = db.get(User, uid)
        assert u.deleted_at is not None
        assert u.name == "Usuario eliminado"
        assert u.password_hash is None
        assert u.is_active is False
        assert u.email.endswith("@deleted.invalid")
        # La auditoria se conserva
        assert (
            db.query(AuditLog).filter(AuditLog.actor_user_id == uid).count() > 0
        )
    finally:
        db.close()


def test_cannot_delete_last_admin(auth_on):
    uid = _make_user("admin", "lastadmin@example.com")

    # Aislar escenario: la DB en memoria es compartida entre tests, por lo que
    # desactivamos temporalmente los demas admins para simular "unico admin".
    db = SessionLocal()
    others: list[User] = []
    try:
        others = (
            db.query(User)
            .filter(User.role == "admin", User.id != uid, User.is_active.is_(True))
            .all()
        )
        for u in others:
            u.is_active = False
        db.commit()
    finally:
        db.close()

    try:
        with TestClient(app) as client:
            token = _login(client, "lastadmin@example.com").json()["accessToken"]
            headers = {"Authorization": f"Bearer {token}"}
            resp = client.delete("/api/users/me", headers=headers)
            assert resp.status_code == 409

        db = SessionLocal()
        try:
            u = db.get(User, uid)
            assert u.deleted_at is None
            assert u.is_active is True
        finally:
            db.close()
    finally:
        db = SessionLocal()
        try:
            for u in others:
                u.is_active = True
            db.commit()
        finally:
            db.close()


def test_api_key_cannot_be_admin(auth_on):
    _make_user("admin", "adm6@example.com")
    with TestClient(app) as client:
        token = _login(client, "adm6@example.com").json()["accessToken"]
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.post(
            "/api/api-keys",
            json={"name": "ci", "role": "admin"},
            headers=headers,
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "lead"


def test_disabled_flag_restores_open_access():
    # Sin auth: sigue abierto (flag)
    with TestClient(app) as client:
        resp = client.get("/api/dashboard")
        assert resp.status_code == 200


AUTH_DEP_NAMES = {"require_auth", "require_role", "require_api_key", "get_auth_context"}
PUBLIC_PREFIXES = ("/api/auth/", "/docs", "/redoc")
PUBLIC_PATHS = {"/", "/health", "/openapi.json"}


def _dependant_has_auth(dependant) -> bool:
    for dep in dependant.dependencies:
        fn = getattr(dep, "call", None)
        name = getattr(fn, "__name__", "")
        if name in AUTH_DEP_NAMES:
            return True
        if _dependant_has_auth(dep):
            return True
    return False


def test_every_route_is_allowlisted_or_authenticated():
    """Toda ruta debe estar en la allowlist o exigir credenciales (dep o middleware)."""
    open_routes: list[str] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        if path is None or not path.startswith("/"):
            continue
        if path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES):
            continue
        # Rutas de sistema (redoc/docs/openapi) incluidas arriba
        methods = getattr(route, "methods", set()) or set()
        if not methods or methods <= {"HEAD", "OPTIONS"}:
            continue
        dependant = getattr(route, "dependant", None)
        if dependant is None or not _dependant_has_auth(dependant):
            open_routes.append(f"{sorted(methods)} {path}")
    assert open_routes == [], f"Rutas sin auth ni allowlist: {open_routes}"
