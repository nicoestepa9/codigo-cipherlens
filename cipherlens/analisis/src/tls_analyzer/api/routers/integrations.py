"""Router de integraciones, API keys y documentación de endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from ..deps import AuthContext, require_api_key, require_role
from ..schemas import ApiEndpointOut, ApiKeyCreate, ApiKeyCreated, ApiKeyOut, IntegrationOut
from ..services import integration_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["integrations"])


@router.get("/integrations", response_model=list[IntegrationOut])
def list_integrations(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return integration_service.list_integrations(db)


@router.get("/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return integration_service.list_api_keys(db)


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201)
def create_api_key(
    payload: ApiKeyCreate,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_role("admin")),
):
    dto, _plain = integration_service.create_api_key(
        db,
        payload.name,
        role=payload.role,
        expires_in_days=payload.expiresInDays,
        user_id=ctx.user_id,
    )
    return dto


@router.delete("/api-keys/{key_id}", status_code=204)
def revoke_api_key(
    key_id: str,
    db: Session = Depends(get_db),
    _: AuthContext = Depends(require_role("admin")),
):
    if not integration_service.revoke_api_key(db, key_id):
        raise HTTPException(status_code=404, detail="API key not found")
    return Response(status_code=204)


@router.get("/docs", response_model=list[ApiEndpointOut])
def get_api_endpoints(
    _: Session = Depends(get_db),
    __: None = Depends(require_api_key),
):
    return integration_service.api_endpoints()
