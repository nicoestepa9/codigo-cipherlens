"""Router de autenticacion: login, refresh, logout y bootstrap inicial."""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..models import Organization, User
from ..schemas import LoginRequest, TokenPair, UserOut
from ..services import auth_service, user_service

router = APIRouter(prefix="/api/auth", tags=["auth"])

REFRESH_COOKIE = "cg_refresh"

_hits: dict[str, deque[float]] = defaultdict(deque)


def _rate_limit(ip: str) -> None:
    if settings.disable_api_auth:
        return
    limit = settings.auth_rate_limit_per_minute
    now = time.monotonic()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests")
    q.append(now)


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "unknown"


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        httponly=True,
        secure=False,
        samesite="Lax",
        path="/",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_COOKIE, path="/api/auth")


def _issue_pair(db, user: User, request: Request) -> TokenPair:
    access = auth_service.create_access_token(user.id, user.role)
    refresh = auth_service.issue_refresh_token(
        db,
        user,
        user_agent=request.headers.get("user-agent"),
        ip=_client_ip(request),
    )
    return TokenPair(
        accessToken=access,
        refreshToken=refresh,
        mustChangePassword=user.must_change_password,
    )


@router.post("/login", response_model=TokenPair)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    _rate_limit(_client_ip(request))
    user = auth_service.authenticate(db, payload.email, payload.password)
    if user is None:
        known_user = (
            db.query(User)
            .filter(User.email == payload.email.lower().strip())
            .first()
        )
        auth_service.audit(
            db,
            "auth.login_failed",
            organization_id=getattr(known_user, "organization_id", None) if known_user else None,
            actor_type="anonymous",
            entity_type="user",
            entity_id=payload.email.lower().strip(),
            ip=_client_ip(request),
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Credenciales invalidas")
    if getattr(user, "role", None) == "operator":
        pair = _issue_pair(db, user, request)
        auth_service.audit(
            db,
            "auth.login",
            actor_user_id=user.id,
            organization_id=getattr(user, "organization_id", None),
            entity_type="user",
            entity_id=user.id,
            ip=_client_ip(request),
        )
        db.commit()
        _set_refresh_cookie(response, pair.refreshToken)
        return pair
    if getattr(user, "organization_id", None) is None:
        auth_service.audit(
            db,
            "auth.login_blocked",
            actor_user_id=user.id,
            organization_id=None,
            entity_type="user",
            entity_id=user.id,
            ip=_client_ip(request),
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Organizacion deshabilitada")
    organization = db.get(Organization, user.organization_id)
    if organization is None or organization.status != "active":
        auth_service.audit(
            db,
            "auth.login_blocked",
            actor_user_id=user.id,
            organization_id=user.organization_id,
            entity_type="user",
            entity_id=user.id,
            ip=_client_ip(request),
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Organizacion deshabilitada")
    pair = _issue_pair(db, user, request)
    auth_service.audit(
        db,
        "auth.login",
        actor_user_id=user.id,
        organization_id=user.organization_id,
        entity_type="user",
        entity_id=user.id,
        ip=_client_ip(request),
    )
    db.commit()
    _set_refresh_cookie(response, pair.refreshToken)
    return pair


@router.post("/refresh", response_model=TokenPair)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    refreshToken: str | None = Body(default=None, embed=True, alias="refreshToken"),
):
    _rate_limit(_client_ip(request))
    raw = refreshToken or request.cookies.get(REFRESH_COOKIE)
    if not raw:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    result = auth_service.rotate_refresh_token(
        db,
        raw,
        user_agent=request.headers.get("user-agent"),
        ip=_client_ip(request),
    )
    if result is None:
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user, new_raw = result
    access = auth_service.create_access_token(user.id, user.role)
    db.commit()
    _set_refresh_cookie(response, new_raw)
    return TokenPair(
        accessToken=access,
        refreshToken=new_raw,
        mustChangePassword=user.must_change_password,
    )


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    refreshToken: str | None = Body(default=None, embed=True, alias="refreshToken"),
):
    raw = refreshToken or request.cookies.get(REFRESH_COOKIE)
    if raw:
        auth_service.revoke_refresh_token(db, raw)
    db.commit()
    _clear_refresh_cookie(response)
    return {"status": "ok"}


def ensure_default_organization(
    db, organization_id: int | None = None
) -> Organization:
    """Resolve the current tenant; use first organization only in system scope."""
    if organization_id is None:
        from ..tenancy import TENANT_MODE

        if db.info.get("tenant_mode") == TENANT_MODE:
            organization_id = db.info.get("organization_id")
    if organization_id is not None:
        org = db.get(Organization, organization_id)
        if org is None:
            raise HTTPException(status_code=404, detail="Organizacion no encontrada")
        return org
    org = db.query(Organization).order_by(Organization.id).first()
    if org is None:
        org = Organization(name="CryptoGuard", slug="default", status="active")
        db.add(org)
        db.flush()
    return org


def ensure_bootstrap_admin(db) -> User | None:
    """Crea el admin inicial si no hay usuarios y hay credenciales configuradas."""
    if db.query(User).count() > 0:
        return None
    email = settings.bootstrap_admin_email.strip()
    password = settings.bootstrap_admin_password
    if not email or not password:
        return None
    org = ensure_default_organization(db)
    user = user_service.create_user(
        db,
        email=email,
        name="Administrador",
        password=password,
        role="admin",
        organization_id=org.id,
    )
    auth_service.audit(
        db,
        "auth.bootstrap_admin",
        actor_type="system",
        entity_type="user",
        entity_id=user.id,
        organization_id=user.organization_id,
    )
    return user


@router.post("/bootstrap", response_model=UserOut)
def bootstrap(db: Session = Depends(get_db)):
    """Crea el primer admin si no existe ningun usuario. Idempotente."""
    if db.query(User).count() > 0:
        raise HTTPException(status_code=409, detail="Bootstrap ya realizado")
    email = settings.bootstrap_admin_email.strip()
    password = settings.bootstrap_admin_password
    if not email or not password:
        raise HTTPException(
            status_code=400,
            detail="Configure BOOTSTRAP_ADMIN_EMAIL y BOOTSTRAP_ADMIN_PASSWORD",
        )
    user = ensure_bootstrap_admin(db)
    if user is None:
        raise HTTPException(status_code=409, detail="Bootstrap ya realizado")
    db.commit()
    return user_service.to_out(user)
