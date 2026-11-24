"""Router de usuarios y auditoria (Parte 1)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import AuthContext, require_auth, require_role
from ..models import AuditLog, User
from ..schemas import (
    AuditLogOut,
    PasswordChange,
    UserCreate,
    UserDirectoryEntry,
    UserOut,
    UserUpdate,
)
from ..services import auth_service, user_service
from .auth import ensure_default_organization

router = APIRouter(prefix="/api", tags=["users"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _iso(dt) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        from datetime import timezone

        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _get_scoped_user(db: Session, user_id: str, ctx: AuthContext) -> User:
    user = user_service.get(db, user_id)
    if user is None or (
        ctx.organization_id is not None
        and user.organization_id != ctx.organization_id
    ):
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(
    includeDeleted: bool = Query(False),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    return [user_service.to_out(u) for u in user_service.list_users(
        db, include_deleted=includeDeleted, organization_id=ctx.organization_id
    )]


@router.get("/users/directory", response_model=list[UserDirectoryEntry])
def directory(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    if ctx.role == "admin" or ctx.role == "lead":
        # Los leads pueden ver el directorio para incorporar miembros a su equipo.
        allowed: set[str] | None = None
    else:
        allowed = {ctx.user_id} if ctx.user_id else set()
    users = user_service.list_users(db, organization_id=ctx.organization_id)
    return [
        {"id": u.id, "name": u.name, "email": u.email, "role": u.role, "organization_id": u.organization_id}
        for u in users
        if u.is_active and (allowed is None or u.id in allowed)
    ]


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    payload: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    org = ensure_default_organization(db, ctx.organization_id)
    try:
        user = user_service.create_user(
            db,
            email=payload.email,
            name=payload.name,
            password=payload.password,
            role=payload.role,
            organization_id=org.id,
        )
    except user_service.UserServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    auth_service.audit(
        db,
        "user.create",
        actor_user_id=ctx.user_id,
        entity_type="user",
        entity_id=user.id,
        ip=_client_ip(request),
        meta={"role": user.role},
    )
    db.commit()
    return user_service.to_out(user)


@router.get("/users/me", response_model=UserOut)
def get_me(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    if ctx.user_id is None:
        raise HTTPException(status_code=404, detail="No hay usuario asociado")
    user = user_service.get(db, ctx.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return user_service.to_out(user)


@router.patch("/users/me", response_model=UserOut)
def update_me(
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    if ctx.user_id is None:
        raise HTTPException(status_code=400, detail="No aplicable a API keys")
    user = user_service.get(db, ctx.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    user.name = payload.name if payload.name is not None else user.name
    auth_service.audit(
        db, "user.update_self", actor_user_id=ctx.user_id, entity_type="user",
        entity_id=user.id, ip=_client_ip(request),
    )
    db.commit()
    return user_service.to_out(user)


@router.post("/users/me/password")
def change_my_password(
    payload: PasswordChange,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    if ctx.user_id is None:
        raise HTTPException(status_code=400, detail="No aplicable a API keys")
    user = user_service.get(db, ctx.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    try:
        user_service.change_password(db, user, payload.currentPassword, payload.newPassword)
    except user_service.UserServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    auth_service.audit(
        db, "user.password_change", actor_user_id=ctx.user_id, entity_type="user",
        entity_id=user.id, ip=_client_ip(request),
    )
    db.commit()
    return {"status": "ok"}


@router.delete("/users/me")
def delete_me(
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    if ctx.user_id is None:
        raise HTTPException(status_code=400, detail="No aplicable a API keys")
    user = user_service.get(db, ctx.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    try:
        user_service.anonymize_and_delete(db, user)
    except user_service.UserServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    auth_service.audit(
        db, "user.delete_self", actor_user_id=ctx.user_id, entity_type="user",
        entity_id=user.id, ip=_client_ip(request),
    )
    db.commit()
    return {"status": "ok"}


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    user = _get_scoped_user(db, user_id, ctx)
    return user_service.to_out(user)


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    payload: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    user = _get_scoped_user(db, user_id, ctx)
    try:
        user_service.update_user(
            db,
            user,
            name=payload.name,
            role=payload.role,
            is_active=payload.isActive,
        )
    except user_service.UserServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    auth_service.audit(
        db, "user.update", actor_user_id=ctx.user_id, entity_type="user",
        entity_id=user.id, ip=_client_ip(request),
        meta={"role": user.role, "isActive": user.is_active},
    )
    db.commit()
    return user_service.to_out(user)


@router.delete("/users/{user_id}")
def delete_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    user = _get_scoped_user(db, user_id, ctx)
    try:
        user_service.anonymize_and_delete(db, user)
    except user_service.UserServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)
    auth_service.audit(
        db, "user.delete", actor_user_id=ctx.user_id, entity_type="user",
        entity_id=user.id, ip=_client_ip(request),
    )
    db.commit()
    return {"status": "ok"}


@router.get("/audit-log", response_model=list[AuditLogOut])
def audit_log(
    action: str | None = Query(None),
    actorUserId: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if actorUserId:
        q = q.filter(AuditLog.actor_user_id == actorUserId)
    rows = q.order_by(AuditLog.ts.desc()).offset(offset).limit(limit).all()
    return [
        {
            "id": r.id,
            "ts": _iso(r.ts),
            "actorUserId": r.actor_user_id,
            "actorType": r.actor_type,
            "action": r.action,
            "entityType": r.entity_type,
            "entityId": r.entity_id,
            "ip": r.ip,
            "metadata": r.meta,
        }
        for r in rows
    ]
