"""Router de servicios (inventario)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..deps import AuthContext, require_api_key, require_auth, require_role
from ..schemas import Paged, ServiceOwnerPatch, ServiceOut
from ..services import service_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["services"])


@router.get("/services", response_model=Paged[ServiceOut])
def list_services(
    search: str | None = None,
    status: str | None = None,
    scope: str | None = None,
    tlsVersion: str | None = None,
    agentId: str | None = None,
    siteLabel: str | None = None,
    page: int = Query(1, ge=1),
    pageSize: int = Query(12, ge=1, le=100),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return service_service.list_services(
        db, search=search, status=status, scope=scope,
        tls_version=tlsVersion, agent_id=agentId, site_label=siteLabel,
        page=page, page_size=pageSize,
    )


@router.get("/services/{service_id}", response_model=ServiceOut)
def get_service(
    service_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    service = service_service.get_service(db, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return service


@router.get("/services/{service_id}/owner")
def get_service_owner(
    service_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    from ..models import Service

    service = db.get(Service, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")
    return {
        "serviceId": service.id,
        "ownerUserId": service.default_owner_user_id,
        "ownerTeamId": service.default_owner_team_id,
    }


@router.patch("/services/{service_id}/owner")
def set_service_owner(
    service_id: str,
    payload: ServiceOwnerPatch,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    from ..models import Service, Team, User

    service = db.get(Service, service_id)
    if service is None:
        raise HTTPException(status_code=404, detail="Service not found")

    owner_user_id = payload.ownerUserId
    owner_team_id = payload.ownerTeamId
    if owner_user_id and db.get(User, owner_user_id) is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    if owner_team_id and db.get(Team, owner_team_id) is None:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")

    service.default_owner_user_id = owner_user_id
    service.default_owner_team_id = owner_team_id
    db.commit()
    return {
        "serviceId": service.id,
        "ownerUserId": service.default_owner_user_id,
        "ownerTeamId": service.default_owner_team_id,
    }
