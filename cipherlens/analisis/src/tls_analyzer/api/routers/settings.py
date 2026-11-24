"""Router de settings: umbrales de alertas y estado del modo IA."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Literal
from sqlalchemy.orm import Session

from ..config import settings
from ..deps import AuthContext, require_auth, require_api_key, require_operator, require_role
from ..models import ComplianceWindow, Organization
from ..schemas import (
    ComplianceWindowIn,
    ComplianceWindowOut,
    OrganizationSettingsOut,
    SlaSettingsIn,
    ThresholdOut,
    ThresholdUpdate,
)
from ..services import alert_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["settings"])


class AiStatusOut(BaseModel):
    """Estado del modo de IA configurado (4.5)."""

    provider: str
    anonymization: str
    externalLlm: bool


class AiModeUpdate(BaseModel):
    mode: Literal["external", "template"]


class AiModeOut(BaseModel):
    mode: Literal["external", "template"]


@router.get("/settings/thresholds", response_model=ThresholdOut)
def get_thresholds(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    return alert_service.get_thresholds(db, organization_id=ctx.organization_id)


@router.put("/settings/thresholds", response_model=ThresholdOut)
def update_thresholds(
    payload: ThresholdUpdate,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    return alert_service.update_thresholds(db, payload.model_dump(), organization_id=ctx.organization_id)


@router.get("/settings/ai-status", response_model=AiStatusOut)
def get_ai_status(_: None = Depends(require_api_key)):
    """Expone el modo de IA activo para que el frontend lo muestre.

    ``externalLlm`` es True solo cuando hay un proveedor externo configurado
    (anthropic/gemini) con clave presente. En ``template`` no se realiza
    ninguna llamada HTTP saliente.
    """
    provider = settings.ai_provider.lower()
    external = bool(settings.ai_api_key) and provider in {"anthropic", "gemini"}
    return AiStatusOut(
        provider=provider,
        anonymization=settings.ai_anonymization,
        externalLlm=external,
    )


def _organization_out(organization: Organization) -> OrganizationSettingsOut:
    return OrganizationSettingsOut(
        id=organization.id,
        name=organization.name,
        slug=organization.slug,
        status=organization.status,
        aiMode=organization.ai_mode,
        maxAgents=organization.max_agents,
        maxCloudScansPerHour=organization.max_cloud_scans_per_hour,
        maxRecurringScans=organization.max_recurring_scans,
        slaDaysCritical=(
            organization.sla_days_critical
            if organization.sla_days_critical is not None
            else settings.sla_days_critical
        ),
        slaDaysHigh=(
            organization.sla_days_high
            if organization.sla_days_high is not None
            else settings.sla_days_high
        ),
        slaDaysMedium=(
            organization.sla_days_medium
            if organization.sla_days_medium is not None
            else settings.sla_days_medium
        ),
    )


@router.get("/settings/organization", response_model=OrganizationSettingsOut)
def get_organization(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    """Return the caller's tenant metadata."""
    from ..tenancy import set_system_session
    set_system_session(db)
    org = db.get(Organization, ctx.organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organización no encontrada.")
    return _organization_out(org)


@router.put("/settings/sla", response_model=OrganizationSettingsOut)
def update_sla_settings(
    payload: SlaSettingsIn,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    """Update the tenant's SLA day targets (admin only)."""
    if ctx.organization_id is None:
        raise HTTPException(status_code=401, detail="Organización no disponible.")
    organization = db.get(Organization, ctx.organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="Organización no encontrada.")
    old = {
        "criticalDays": organization.sla_days_critical,
        "highDays": organization.sla_days_high,
        "mediumDays": organization.sla_days_medium,
    }
    organization.sla_days_critical = payload.criticalDays
    organization.sla_days_high = payload.highDays
    organization.sla_days_medium = payload.mediumDays
    from ..services import auth_service

    auth_service.audit(
        db,
        "organization.sla_changed",
        actor_user_id=ctx.user_id,
        actor_type=ctx.actor_type,
        entity_type="organization",
        entity_id=str(organization.id),
        ip=request.client.host if request.client else None,
        meta={
            "old": old,
            "new": payload.model_dump(),
        },
        organization_id=organization.id,
    )
    db.commit()
    db.refresh(organization)
    return _organization_out(organization)


def _compliance_window_out(window: ComplianceWindow) -> ComplianceWindowOut:
    return ComplianceWindowOut(
        id=window.id,
        name=window.name,
        framework=window.framework,
        auditDate=window.audit_date,
        scopeFilter=list(window.scope_filter or []),
    )


@router.get(
    "/settings/compliance-windows", response_model=list[ComplianceWindowOut]
)
def list_compliance_windows(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    windows = (
        db.query(ComplianceWindow)
        .filter(ComplianceWindow.organization_id == ctx.organization_id)
        .order_by(ComplianceWindow.audit_date, ComplianceWindow.name)
        .all()
    )
    return [_compliance_window_out(window) for window in windows]


@router.put(
    "/settings/compliance-windows", response_model=list[ComplianceWindowOut]
)
def replace_compliance_windows(
    payload: list[ComplianceWindowIn],
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    """Replace the tenant's compliance windows atomically (admin only)."""
    if ctx.organization_id is None:
        raise HTTPException(status_code=401, detail="Organización no disponible.")
    if len(payload) > 100:
        raise HTTPException(status_code=422, detail="Too many compliance windows.")
    for existing in db.query(ComplianceWindow).all():
        db.delete(existing)
    windows = [
        ComplianceWindow(
            organization_id=ctx.organization_id,
            name=item.name,
            framework=item.framework,
            audit_date=item.auditDate,
            scope_filter=list(item.scopeFilter),
        )
        for item in payload
    ]
    db.add_all(windows)
    from ..services import auth_service

    auth_service.audit(
        db,
        "organization.compliance_windows_replaced",
        actor_user_id=ctx.user_id,
        actor_type=ctx.actor_type,
        entity_type="organization",
        entity_id=str(ctx.organization_id),
        ip=request.client.host if request.client else None,
        meta={"count": len(windows)},
        organization_id=ctx.organization_id,
    )
    db.commit()
    for window in windows:
        db.refresh(window)
    return [_compliance_window_out(window) for window in windows]


@router.put("/settings/ai-mode", response_model=AiModeOut)
def update_ai_mode(
    payload: AiModeUpdate,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    """Change the current organization AI egress policy (admin only)."""
    if ctx.organization_id is None:
        raise HTTPException(status_code=401, detail="Organización no disponible.")
    organization = db.get(Organization, ctx.organization_id)
    if organization is None:
        raise HTTPException(status_code=404, detail="Organización no encontrada.")
    old_mode = organization.ai_mode
    if old_mode != payload.mode:
        organization.ai_mode = payload.mode
        from ..services import auth_service

        auth_service.audit(
            db,
            "organization.ai_mode_changed",
            actor_user_id=ctx.user_id,
            actor_type=ctx.actor_type,
            entity_type="organization",
            entity_id=str(organization.id),
            ip=request.client.host if request.client else None,
            meta={"old_mode": old_mode, "new_mode": payload.mode},
            organization_id=organization.id,
        )
        db.commit()
    return AiModeOut(mode=organization.ai_mode)
