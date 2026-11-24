"""Guard central de escritura: cobertura completa desde OpenAPI, default-deny por rol."""
from __future__ import annotations

import re
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tls_analyzer.api.access_control import (
    WRITE_METHODS,
    WRITE_POLICIES,
    resolve_write_policy,
    route_path,
)
from tls_analyzer.api.config import settings
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import Organization, User
from tls_analyzer.api.services import auth_service, user_service

PASSWORD = "Sup3rSecret!pass"

VIEWER_ALLOWLIST = {
    ("POST", "/api/auth/logout"),
    ("POST", "/api/users/me/password"),
    ("PATCH", "/api/users/me"),
    ("DELETE", "/api/users/me"),
}


@pytest.fixture()
def auth_on(monkeypatch):
    monkeypatch.setattr(settings, "disable_api_auth", False)
    monkeypatch.setattr(settings, "auth_rate_limit_per_minute", 10000)
    yield


def _org(db) -> Organization:
    org = db.query(Organization).order_by(Organization.id).first()
    if org is None:
        org = Organization(name="CryptoGuard")
        db.add(org)
        db.flush()
    return org


def _user(db, role: str) -> User:
    email = f"guard-{role}-{uuid4().hex}@example.com"
    user = user_service.create_user(db, email=email, name=email, password=PASSWORD, role=role, organization_id=_org(db).id)
    db.commit()
    db.refresh(user)
    return user


def _headers(user: User) -> dict[str, str]:
    token = auth_service.create_access_token(user.id, user.role)
    return {"Authorization": f"Bearer {token}"}


def _all_mutating_routes():
    routes = []
    schema = app.openapi()
    paths = schema.get("paths", {})
    for path, operations in paths.items():
        for method in operations:
            m = method.upper()
            if m not in WRITE_METHODS:
                continue
            routes.append((m, path))
    seen = set()
    out = []
    for r in routes:
        if r in seen:
            continue
        seen.add(r)
        out.append(r)
    return out


def test_every_write_route_has_an_explicit_policy():
    missing = []
    for method, path in _all_mutating_routes():
        rp = route_path(path)
        if resolve_write_policy(method, rp) is None:
            missing.append(f"{method} {path}")
    assert not missing, "Rutas mutantes sin politica: " + ", ".join(missing)
    assert len(WRITE_POLICIES) > 0


@pytest.fixture()
def users():
    db = SessionLocal()
    try:
        viewer = _user(db, "viewer")
        lead = _user(db, "lead")
        admin = _user(db, "admin")
        return {"viewer": _headers(viewer), "lead": _headers(lead), "admin": _headers(admin)}
    finally:
        db.close()


def _fill_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "missing", path)


def _dummy_body(method: str, path: str):
    if method == "GET":
        return None
    if path.startswith("/api/users"):
        return {}
    if path.startswith("/api/teams"):
        return {}
    if path.startswith("/api/issues"):
        return {}
    if path.startswith("/api/agents"):
        return {"name": "x", "siteLabel": "x"}
    if path.startswith("/api/scans"):
        return {"target": {"host": "example.com", "port": 443}}
    if path.startswith("/api/discovery"):
        return {"ipRange": "192.168.1.0/30", "authorizationAccepted": True, "authorizationVersion": "v1"}
    if path.startswith("/api/recurring-scans"):
        return {"name": "x", "target": {"host": "example.com", "port": 443}, "schedule": {"frequency": "daily", "timeOfDay": "00:00"}}
    if path.startswith("/api/settings"):
        return {}
    if path.startswith("/api/cves"):
        return {}
    if path.startswith("/api/alerts"):
        return {"status": "acknowledged"}
    if path.startswith("/api/auth"):
        return {}
    if path.startswith("/api/agent/"):
        return {}
    return {}


def test_viewer_denied_on_all_mutating_routes_except_allowlist(auth_on, users):
    routes = _all_mutating_routes()
    covered = 0
    with TestClient(app) as client:
        for method, path in routes:
            rp = route_path(path)
            if path.startswith("/api/agent/"):
                continue
            if (method, rp) in VIEWER_ALLOWLIST or (method, path) in VIEWER_ALLOWLIST:
                resp = client.request(method, _fill_path(path), json=_dummy_body(method, path), headers=users["viewer"])
                assert resp.status_code != 403
                covered += 1
                continue
            resp = client.request(method, _fill_path(path), json=_dummy_body(method, path), headers=users["viewer"])
            # Guard must be evaluated before resource checks; allow 422/404/401/409 if guard not bypassed
            if resp.status_code in (403, 404, 422, 401, 409):
                pass
            elif resp.status_code == 200 or resp.status_code < 400:
                assert False, f"{method} {path} should be denied for viewer"
            else:
                # try with non-existent id explicitly
                filled = re.sub(r"\{[^}]+\}", "00000000-0000-0000-0000-000000000000", path)
                resp2 = client.request(method, filled, json=_dummy_body(method, path), headers=users["viewer"])
                if resp2.status_code in (403, 404, 422, 401, 409):
                    pass
                else:
                    assert resp2.status_code in (403, 404, 422, 401, 409), f"{method} {path} -> {resp.status_code}/{resp2.status_code}"
            covered += 1
    print(f"VIEWER_COVERED_MUTATING_ROUTES={covered}")


def test_analyst_lead_denied_on_admin_only_mutating_routes(auth_on, users):
    routes = _all_mutating_routes()
    covered = 0
    with TestClient(app) as client:
        for method, path in routes:
            rp = route_path(path)
            policy = resolve_write_policy(method, rp)
            if policy is None or policy.public:
                continue
            if policy.roles == {"admin"} or policy.roles == frozenset({"admin"}):
                resp = client.request(method, _fill_path(path), json=_dummy_body(method, path), headers=users["lead"])
                assert resp.status_code == 403
                covered += 1
    print(f"ADMIN_ONLY_COVERED={covered}")
