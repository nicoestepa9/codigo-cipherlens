"""Servicio de usuarios: CRUD, roles, borrado anonimizado y proteccion de ultimo admin."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

from ..models import ApiKey, TeamMember, User
from . import auth_service

VALID_ROLES = ("admin", "lead", "user", "viewer", "operator")
ANON_DOMAIN = "deleted.invalid"
ANON_NAME = "Usuario eliminado"


class UserServiceError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def active_admin_count(db, *, exclude_id: str | None = None) -> int:
    q = db.query(func.count(User.id)).filter(
        User.role == "admin",
        User.is_active.is_(True),
        User.deleted_at.is_(None),
    )
    if exclude_id:
        q = q.filter(User.id != exclude_id)
    return int(q.scalar() or 0)


def _ensure_not_last_admin(db, user: User, *, changing_role: str | None = None, deactivating: bool = False) -> None:
    if user.role != "admin" or not user.is_active or user.deleted_at is not None:
        return
    would_lose = (changing_role is not None and changing_role != "admin") or deactivating
    if would_lose and active_admin_count(db, exclude_id=user.id) == 0:
        raise UserServiceError(409, "No se puede quitar el ultimo administrador activo")


def get_by_email(db, email: str) -> User | None:
    return db.query(User).filter(User.email == email.lower().strip()).first()


def get(db, user_id: str) -> User | None:
    return db.get(User, user_id)


def list_users(db, *, include_deleted: bool = False, organization_id: int | None = None) -> list[User]:
    q = db.query(User)
    if not include_deleted:
        q = q.filter(User.deleted_at.is_(None))
    if organization_id is not None:
        q = q.filter(User.organization_id == organization_id)
    return q.order_by(User.created_at.desc()).all()


def create_user(
    db,
    *,
    email: str,
    name: str,
    password: str,
    role: str = "user",
    organization_id: int,
    must_change_password: bool = False,
) -> User:
    email = email.lower().strip()
    if role not in VALID_ROLES:
        raise UserServiceError(400, f"Rol invalido: {role}")
    if get_by_email(db, email) is not None:
        raise UserServiceError(409, "Ya existe un usuario con ese email")
    user = User(
        organization_id=organization_id,
        email=email,
        name=name or email,
        password_hash=auth_service.hash_password(password),
        role=role,
        is_active=True,
        must_change_password=must_change_password,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        if "email" not in str(getattr(exc, "orig", exc)).lower():
            raise
        raise UserServiceError(
            409, "Ya existe un usuario con ese email"
        ) from exc
    return user


def update_user(db, user: User, *, name=None, role=None, is_active=None) -> User:
    if role is not None and role not in VALID_ROLES:
        raise UserServiceError(400, f"Rol invalido: {role}")
    _ensure_not_last_admin(
        db,
        user,
        changing_role=role,
        deactivating=(is_active is False),
    )
    if name is not None:
        user.name = name
    if role is not None:
        user.role = role
    if is_active is not None:
        user.is_active = is_active
    return user


def change_password(db, user: User, current: str, new: str) -> None:
    if not user.password_hash or not auth_service.verify_password(current, user.password_hash):
        raise UserServiceError(400, "Password actual incorrecta")
    user.password_hash = auth_service.hash_password(new)
    user.must_change_password = False
    auth_service.revoke_all_user_tokens(db, user.id)


def anonymize_and_delete(db, user: User) -> None:
    _ensure_not_last_admin(db, user, deactivating=True)
    anon_email = f"deleted-{uuid.uuid4()}@{ANON_DOMAIN}"
    user.email = anon_email
    user.name = ANON_NAME
    user.password_hash = None
    user.is_active = False
    user.deleted_at = _utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    auth_service.revoke_all_user_tokens(db, user.id)
    db.query(ApiKey).filter(ApiKey.user_id == user.id).update(
        {ApiKey.revoked: True}
    )

    # Parte 2: quitar al usuario de todos los equipos.
    db.query(TeamMember).filter(TeamMember.user_id == user.id).delete(
        synchronize_session=False
    )

    # Parte 2: los issues cuyo owner era este usuario quedan sin responsable,
    # con evento owner_removed en el historial y alerta issue_owner_removed.
    from . import issue_service

    affected = issue_service.remove_owner_from_issues(db, user.id)
    if affected:
        issue_service.raise_owner_removed_alerts(db, affected)


def to_out(user: User) -> dict:
    def _iso(dt):
        d = _as_utc(dt)
        return d.isoformat() if d else None

    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "isActive": user.is_active and user.deleted_at is None,
        "mustChangePassword": user.must_change_password,
        "createdAt": _iso(user.created_at),
        "lastLoginAt": _iso(user.last_login_at),
        "organization_id": user.organization_id,
    }
