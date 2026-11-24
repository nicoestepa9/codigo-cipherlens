"""Router de certificados: inventario, detalle, expiración e issuers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..deps import AuthContext, require_api_key
from ..schemas import CertificateDetailOut, CertificateInfoOut, ExpirationStatsOut, Paged
from ..services import certificate_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["certificates"])


@router.get("/certificates", response_model=Paged[CertificateInfoOut])
def list_certificates(
    search: str | None = None,
    status: str | None = None,
    issuer: str | None = None,
    origin: str | None = None,
    agentId: str | None = None,
    siteLabel: str | None = None,
    page: int = Query(1, ge=1),
    pageSize: int = Query(12, ge=1, le=100),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    return certificate_service.list_certificates(
        db, search=search, status=status, issuer=issuer, origin=origin,
        agent_id=agentId, site_label=siteLabel,
        page=page, page_size=pageSize,
        organization_id=ctx.organization_id,
    )


@router.get("/certificates/expiration-stats", response_model=ExpirationStatsOut)
def expiration_stats(
    criticalDays: int | None = Query(None, ge=0, le=3650),
    warningDays: int | None = Query(None, ge=0, le=3650),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    return certificate_service.expiration_stats(
        db,
        critical_days=criticalDays,
        warning_days=warningDays,
        organization_id=ctx.organization_id,
    )


@router.get("/certificates/issuers")
def list_issuers(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return certificate_service.issuers(db)


@router.get("/certificates/{cert_id}", response_model=CertificateDetailOut)
def get_certificate(
    cert_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    detail = certificate_service.get_certificate_detail(
        db, cert_id, organization_id=ctx.organization_id
    )
    if detail is None:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return detail
