'''Endpoints para gestion de organizaciones (solo operadores de plataforma).'''

from __future__ import annotations

import secrets
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..db import SessionLocal
from ..deps import AuthContext, require_operator
from ..services import user_service
from ..tenancy import set_system_session


def get_system_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        set_system_session(db)
        yield db
    finally:
        db.close()


router = APIRouter(prefix='/api/organizations', tags=['organizations'])


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=64, pattern=r'^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$')
    status: str = Field(default='active')
    admin_email: str = Field(min_length=1)
    admin_name: str = Field(min_length=1)
    admin_password: str = Field(min_length=1)


class OrganizationUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    ai_mode: str | None = None
    max_agents: int | None = None
    max_cloud_scans_per_hour: int | None = None
    max_recurring_scans: int | None = None


class OrganizationOut(BaseModel):
    id: int
    name: str
    slug: str
    status: str
    ai_mode: str | None = None
    max_agents: int | None = None
    max_cloud_scans_per_hour: int | None = None
    max_recurring_scans: int | None = None

    class Config:
        from_attributes = True


@router.get('', response_model=list[OrganizationOut])
def list_organizations(
    _: AuthContext = Depends(require_operator),
    db: Session = Depends(get_system_db),
):
    set_system_session(db)
    orgs = db.query(models.Organization).order_by(models.Organization.id).all()
    return orgs


@router.post('', response_model=OrganizationOut)
def create_organization(
    payload: OrganizationCreate,
    _ctx: AuthContext = Depends(require_operator),
    db: Session = Depends(get_system_db),
):
    set_system_session(db)
    existing = db.query(models.Organization).filter(models.Organization.slug == payload.slug).first()
    if existing:
        raise HTTPException(status_code=409, detail='Organization slug already exists')
    org = models.Organization(
        name=payload.name,
        slug=payload.slug,
        status=payload.status or 'active',
    )
    db.add(org)
    db.flush()
    try:
        user_service.create_user(
            db,
            email=payload.admin_email,
            name=payload.admin_name,
            password=payload.admin_password,
            role='admin',
            organization_id=org.id,
        )
    except user_service.UserServiceError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    db.refresh(org)
    return org


@router.get('/{org_id}', response_model=OrganizationOut)
def get_organization(
    org_id: int,
    _: AuthContext = Depends(require_operator),
    db: Session = Depends(get_system_db),
):
    set_system_session(db)
    org = db.get(models.Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail='Organization not found')
    return org


@router.patch('/{org_id}', response_model=OrganizationOut)
def update_organization(
    org_id: int,
    payload: OrganizationUpdate,
    _: AuthContext = Depends(require_operator),
    db: Session = Depends(get_system_db),
):
    set_system_session(db)
    org = db.get(models.Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail='Organization not found')
    for field in ('name', 'status', 'ai_mode', 'max_agents', 'max_cloud_scans_per_hour', 'max_recurring_scans'):
        value = getattr(payload, field)
        if value is not None:
            setattr(org, field, value)
    db.commit()
    db.refresh(org)
    return org


@router.post('/{org_id}/disable', response_model=OrganizationOut)
def disable_organization(
    org_id: int,
    _: AuthContext = Depends(require_operator),
    db: Session = Depends(get_system_db),
):
    set_system_session(db)
    org = db.get(models.Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail='Organization not found')
    org.status = 'disabled'
    db.commit()
    db.refresh(org)
    return org


@router.post('/{org_id}/enable', response_model=OrganizationOut)
def enable_organization(
    org_id: int,
    _: AuthContext = Depends(require_operator),
    db: Session = Depends(get_system_db),
):
    set_system_session(db)
    org = db.get(models.Organization, org_id)
    if not org:
        raise HTTPException(status_code=404, detail='Organization not found')
    org.status = 'active'
    db.commit()
    db.refresh(org)
    return org


@router.delete('/{org_id}')
def purge_organization(
    org_id: int,
    _: AuthContext = Depends(require_operator),
    db: Session = Depends(get_system_db),
):
    set_system_session(db)
    from ...cli import _purge_organization

    try:
        _purge_organization(db, org_id)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return {'status': 'purged', 'organization_id': org_id}

