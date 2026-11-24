"""Dependencias FastAPI: auth (API key / JWT) y helpers."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

import jwt
from fastapi import Header, HTTPException

from .access_control import canonical_role
from .config import settings
from .db import SessionLocal
from .models import Agent, ApiKey, TeamMember, User

ROLE_RANK = {"viewer": -1, "user": 0, "analyst": 1, "lead": 1, "admin": 2, "operator": 3}


def member_team_ids(db, user_id: str | None) -> list[str]:
    """IDs de todos los equipos a los que pertenece el usuario."""
    if not user_id:
        return []
    rows = (
        db.query(TeamMember.team_id)
        .filter(TeamMember.user_id == user_id)
        .all()
    )
    return sorted({r[0] for r in rows})


def led_team_ids(db, user_id: str | None) -> list[str]:
    """IDs de los equipos que el usuario lidera (membresia con is_lead)."""
    if not user_id:
        return []
    rows = (
        db.query(TeamMember.team_id)
        .filter(TeamMember.user_id == user_id, TeamMember.is_lead.is_(True))
        .all()
    )
    return [r[0] for r in rows]


def is_lead_of_team(db, user_id: str | None, team_id: str | None) -> bool:
    if not user_id or not team_id:
        return False
    return (
        db.query(TeamMember)
        .filter(
            TeamMember.user_id == user_id,
            TeamMember.team_id == team_id,
            TeamMember.is_lead.is_(True),
        )
        .first()
        is not None
    )


def led_team_member_ids(db, user_id: str | None) -> list[str]:
    """IDs de usuarios que pertenecen a algun equipo liderado por el usuario."""
    team_ids = led_team_ids(db, user_id)
    if not team_ids:
        return []
    rows = (
        db.query(TeamMember.user_id)
        .filter(TeamMember.team_id.in_(team_ids))
        .all()
    )
    return sorted({r[0] for r in rows})


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    return f"cg_{secrets.token_urlsafe(32)}"


def api_key_prefix(key: str) -> str:
    return key[:8] + "..."


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class AuthContext:
    user_id: str | None
    role: str
    actor_type: str  # user|api_key|disabled|agent
    agent_id: str | None = None
    organization_id: int | None = None


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(status_code=401, detail=detail)


def _authenticate_api_key(db, raw_key: str) -> AuthContext:
    key = (
        db.query(ApiKey)
        .filter(ApiKey.key_hash == hash_api_key(raw_key), ApiKey.revoked.is_(False))
        .first()
    )
    if not key:
        raise _unauthorized("Invalid or revoked API key")
    if key.expires_at is not None and _as_utc(key.expires_at) <= _utcnow():
        raise _unauthorized("API key expired")
    key.last_used_at = _utcnow()
    # Rol especial 'agent': la key pertenece a un agente on-premise enrolado.
    if key.role == "agent":
        agent = db.query(Agent).filter(Agent.api_key_id == key.id).first()
        if agent is None or agent.status != "active":
            raise _unauthorized("Agent revoked or not enrolled")
        org_id = agent.organization_id
        if org_id is None or (
            key.organization_id is not None and key.organization_id != org_id
        ):
            raise _unauthorized("Agent without organization")
        from .models import Organization

        org = db.get(Organization, org_id)
        if org is None or getattr(org, "status", "active") != "active":
            raise _unauthorized("Organization disabled")
        return AuthContext(
            user_id=None,
            role="agent",
            actor_type="api_key",
            agent_id=agent.id,
            organization_id=org_id,
        )
    role = canonical_role(key.role)
    role = role if role in ROLE_RANK else "user"
    if role == "admin":
        role = "lead"  # las API keys nunca son admin
    org_id = getattr(key, "organization_id", None)
    if key.user_id:
        user = db.get(User, key.user_id)
        if user is None or not user.is_active or user.deleted_at is not None:
            raise _unauthorized("User inactive or deleted")
        user_org_id = user.organization_id
        if user_org_id is None or (
            org_id is not None and org_id != user_org_id
        ):
            raise _unauthorized("User without organization")
        org_id = user_org_id
        from .models import Organization

        org = db.get(Organization, org_id)
        if org is None or getattr(org, "status", "active") != "active":
            raise _unauthorized("Organization disabled")
        return AuthContext(
            user_id=user.id,
            role=role,
            actor_type="api_key",
            organization_id=org_id,
        )
    # Key sin user pero con org -> permitir con rol
    if org_id is None:
        from .models import Organization

        org = db.query(Organization).first()
        if org:
            org_id = org.id
    if org_id is None:
        raise _unauthorized("Invalid API key")
    from .models import Organization

    org = db.get(Organization, org_id)
    if org is None or getattr(org, "status", "active") != "active":
        raise _unauthorized("Organization disabled")
    return AuthContext(user_id=None, role=role, actor_type="api_key", organization_id=org_id)


def _authenticate_bearer(db, token: str) -> AuthContext:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise _unauthorized("Invalid or expired token")
    if payload.get("type") != "access":
        raise _unauthorized("Invalid token type")
    user_id = payload.get("sub")
    if not user_id:
        raise _unauthorized("Invalid token")
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.deleted_at is not None:
        raise _unauthorized("User inactive or deleted")
    role = canonical_role(user.role)
    if role == "operator":
        from . import tenancy

        tenancy.set_system_session(db)
        return AuthContext(
            user_id=user.id,
            role=role,
            actor_type="user",
            organization_id=None,
        )
    if getattr(user, "organization_id", None) is None:
        raise _unauthorized("User without organization")
    from .models import Organization

    org = db.get(Organization, user.organization_id)
    if org is None or getattr(org, "status", "active") != "active":
        raise _unauthorized("Organization disabled")
    return AuthContext(
        user_id=user.id,
        role=role,
        actor_type="user",
        organization_id=user.organization_id,
    )


def get_auth_context(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AuthContext:
    """Resuelve el contexto de autenticacion (Bearer JWT o X-API-Key).

    Si DISABLE_API_AUTH=true, devuelve un contexto admin sin validar.
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        db = SessionLocal()
        try:
            from . import tenancy

            tenancy.set_system_session(db)
            ctx = _authenticate_bearer(db, token)
            if getattr(ctx, "role", None) == "operator":
                tenancy.set_system_session(db)
            elif ctx.organization_id is not None:
                tenancy.set_tenant_session(db, ctx.organization_id)
            else:
                tenancy.set_system_session(db)
            db.commit()
            return ctx
        finally:
            db.close()

    if x_api_key:
        db = SessionLocal()
        try:
            from . import tenancy

            tenancy.set_system_session(db)
            ctx = _authenticate_api_key(db, x_api_key)
            if ctx.organization_id is not None:
                tenancy.set_tenant_session(db, ctx.organization_id)
            else:
                tenancy.set_system_session(db)
            db.commit()
            return ctx
        finally:
            db.close()

    if settings.disable_api_auth:
        # Solo permitido con ENV=dev (ya validado en config). Usar organizacion por defecto.
        from .config import settings as _s

        if getattr(_s, "env", "production").lower() != "dev":
            raise _unauthorized("Missing credentials")
        db = SessionLocal()
        try:
            from . import tenancy
            from .models import Organization, User

            tenancy.set_system_session(db)
            org = db.query(Organization).first()
            if org is None:
                org = Organization(name="Default Org", slug="default", status="active")
                db.add(org)
                db.commit()
                db.refresh(org)
            # Buscar admin por defecto si existe
            user = db.query(User).filter(User.organization_id == org.id).first()
            return AuthContext(
                user_id=user.id if user else None,
                role="admin",
                actor_type="disabled",
                organization_id=org.id,
            )
        finally:
            db.close()

    raise _unauthorized("Missing credentials")


def require_auth(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AuthContext:
    return get_auth_context(x_api_key=x_api_key, authorization=authorization)


def require_role(*roles: str):
    """Factory de dependencia que exige uno de los roles indicados."""

    allowed = set(roles)

    def dependency(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        authorization: str | None = Header(default=None, alias="Authorization"),
    ) -> AuthContext:
        ctx = get_auth_context(x_api_key=x_api_key, authorization=authorization)
        if ctx.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return ctx

    return dependency


def require_operator(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AuthContext:
    """Exige un usuario operador de plataforma (sin scope de organizaci��n)."""
    from . import tenancy
    import jwt

    # DB-authoritative check for operators
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        db = SessionLocal()
        try:
            tenancy.set_system_session(db)
            try:
                payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
            except Exception:
                raise HTTPException(status_code=401, detail="Invalid or expired token")
            if payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Invalid token type")
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(status_code=401, detail="Invalid token")
            user = db.get(User, user_id)
            if user is None or not user.is_active or getattr(user, "deleted_at", None) is not None:
                raise HTTPException(status_code=401, detail="Inactive or unknown user")
            role = canonical_role(getattr(user, "role", ""))
            if role == "operator":
                return AuthContext(
                    user_id=user.id,
                    role="operator",
                    actor_type="user",
                    organization_id=None,
                )
            raise HTTPException(status_code=403, detail="Operator role required")
        finally:
            db.close()

    # Fallback to normal auth context
    db = SessionLocal()
    try:
        tenancy.set_system_session(db)
        ctx = get_auth_context(x_api_key=x_api_key, authorization=authorization)
        if getattr(ctx, "role", None) == "operator":
            try:
                ctx.organization_id = None
            except Exception:
                pass
            return ctx
        raise HTTPException(status_code=403, detail="Operator role required")
    finally:
        db.close()


def require_agent(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AuthContext:
    """Dependencia de los endpoints de ingesta: exige un agente enrolado."""
    ctx = get_auth_context(x_api_key=x_api_key, authorization=authorization)
    if ctx.role != "agent" or not ctx.agent_id:
        raise HTTPException(status_code=403, detail="Agent credentials required")
    return ctx


def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None, alias="Authorization"),
) -> AuthContext:
    """Compatibilidad: protege endpoints aceptando API key o Bearer JWT."""
    return get_auth_context(x_api_key=x_api_key, authorization=authorization)
