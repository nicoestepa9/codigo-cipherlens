"""Servicio de autenticacion: password hashing, JWT y refresh tokens opacos."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2 import exceptions as argon_exc

from ..config import settings
from ..models import AuditLog, Organization, RefreshToken, User
from ..tenancy import SYSTEM_TENANT_MODE, get_session_org_id

ph = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
)

_DUMMY_HASH = ph.hash("dummy-password-for-timing-equalization")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Verifica password. Si el hash es None, iguala tiempos (evita user enumeration)."""
    if not password_hash:
        try:
            ph.verify(_DUMMY_HASH, password)
        except Exception:
            pass
        return False
    try:
        ph.verify(password_hash, password)
        return True
    except argon_exc.VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return ph.check_needs_rehash(password_hash)
    except Exception:
        return False


def _hash_refresh(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_access_token(sub: str, role: str) -> str:
    now = _utcnow()
    payload = {
        "sub": sub,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
        "type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str) -> Any:
    return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])


def issue_refresh_token(
    db,
    user: User,
    *,
    user_agent: str | None = None,
    ip: str | None = None,
    replaced_by_id: str | None = None,
) -> str:
    """Genera un refresh token opaco, guarda su hash y lo devuelve en claro."""
    raw = secrets.token_urlsafe(64)
    expires = _utcnow() + timedelta(days=settings.refresh_token_days)
    row = RefreshToken(
        user_id=user.id,
        organization_id=getattr(user, "organization_id", None),
        token_hash=_hash_refresh(raw),
        expires_at=expires,
        user_agent=user_agent[:512] if user_agent else None,
        ip=ip,
    )
    db.add(row)
    db.flush()
    if replaced_by_id:
        prev = db.get(RefreshToken, replaced_by_id)
        if prev:
            prev.replaced_by_id = row.id
    return raw


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def rotate_refresh_token(
    db,
    raw_token: str,
    *,
    user_agent: str | None = None,
    ip: str | None = None,
) -> tuple[User, str] | None:
    """Valida y rota un refresh token. Devuelve (user, nuevo_raw) o None."""
    token_hash = _hash_refresh(raw_token)
    row = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .first()
    )
    if row is None:
        return None
    now = _utcnow()
    if row.revoked_at is not None:
        # Reuso de token ya rotado: revocar toda la cadena del usuario.
        _revoke_all_for_user(db, row.user_id, when=now)
        return None
    if _as_utc(row.expires_at) < now:
        row.revoked_at = now
        return None
    user = db.get(User, row.user_id)
    if user is None or not user.is_active or user.deleted_at is not None:
        row.revoked_at = now
        return None
    organization = db.get(Organization, user.organization_id)
    if organization is None or organization.status != "active":
        row.revoked_at = now
        return None
    row.revoked_at = now
    new_raw = issue_refresh_token(
        db, user, user_agent=user_agent, ip=ip, replaced_by_id=row.id
    )
    return user, new_raw


def _revoke_all_for_user(db, user_id: str, *, when: datetime | None = None) -> None:
    when = when or _utcnow()
    db.query(RefreshToken).filter(
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at.is_(None),
    ).update({RefreshToken.revoked_at: when})


def revoke_refresh_token(db, raw_token: str) -> None:
    token_hash = _hash_refresh(raw_token)
    row = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .first()
    )
    if row is not None and row.revoked_at is None:
        row.revoked_at = _utcnow()


def revoke_all_user_tokens(db, user_id: str) -> None:
    _revoke_all_for_user(db, user_id)


def authenticate(db, email: str, password: str) -> User | None:
    """Verifica credenciales con proteccion de timing y bloqueo por intentos."""
    user = db.query(User).filter(User.email == email.lower().strip()).first()
    now = _utcnow()
    if user is None:
        # Equal-time: verificar contra hash dummy para no filtrar existencia.
        verify_password(password, _DUMMY_HASH)
        return None
    if user.deleted_at is not None or not user.is_active:
        verify_password(password, user.password_hash or _DUMMY_HASH)
        return None
    if user.locked_until is not None and _as_utc(user.locked_until) > now:
        verify_password(password, user.password_hash or _DUMMY_HASH)
        return None
    if not user.password_hash or not verify_password(password, user.password_hash):
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= settings.login_max_failures:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.failed_login_count = 0
        return None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    return user


def audit(
    db,
    action: str,
    *,
    actor_user_id: str | None = None,
    actor_type: str = "user",
    entity_type: str | None = None,
    entity_id: str | None = None,
    ip: str | None = None,
    meta: dict | None = None,
    organization_id: int | None = None,
) -> None:
    mode = db.info.get("tenant_mode")
    scoped_org_id = (
        get_session_org_id(db) if mode != SYSTEM_TENANT_MODE else None
    )
    org_id = organization_id or scoped_org_id
    actor = db.get(User, actor_user_id) if actor_user_id else None
    if org_id is None and actor is not None:
        org_id = actor.organization_id
    if org_id is None and entity_type == "user" and entity_id and "@" in entity_id:
        # Login failure for a known account is scoped to that account. Unknown
        # identities are not written to an arbitrary tenant's audit trail.
        known_user = db.query(User).filter(User.email == entity_id.lower()).first()
        if known_user is not None:
            org_id = known_user.organization_id
    if org_id is None:
        logging.getLogger(__name__).warning(
            "Skipped tenant audit event without organization context: %s", action
        )
        return
    if scoped_org_id is not None and scoped_org_id != org_id:
        raise ValueError("Audit organization does not match the current tenant")
    if actor is not None and actor.organization_id != org_id:
        raise ValueError("Audit actor does not belong to the target organization")
    db.add(
        AuditLog(
            actor_user_id=actor_user_id,
            actor_type=actor_type,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            ip=ip,
            meta=meta,
            organization_id=org_id,
        )
    )
