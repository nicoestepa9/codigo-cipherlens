"""Router de vulnerabilidades."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..deps import require_api_key
from ..schemas import FindingOut, Paged, VulnerabilityStatsOut
from ..services import vulnerability_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["vulnerabilities"])


@router.get("/vulnerabilities", response_model=Paged[FindingOut])
def list_vulnerabilities(
    severity: str | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return vulnerability_service.list_findings(
        db, severity=severity, search=search, page=page, page_size=pageSize,
    )


@router.get("/vulnerabilities/stats", response_model=VulnerabilityStatsOut)
def vulnerability_stats(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return vulnerability_service.vulnerability_stats(db)
