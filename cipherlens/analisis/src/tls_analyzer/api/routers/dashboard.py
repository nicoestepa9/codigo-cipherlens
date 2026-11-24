"""Router del dashboard."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..deps import AuthContext, require_api_key
from ..schemas import DashboardSummaryOut
from ..services import dashboard_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard", response_model=DashboardSummaryOut)
def get_dashboard(
    agentId: str | None = Query(None),
    siteLabel: str | None = Query(None),
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    try:
        return dashboard_service.dashboard_summary(
            db,
            agent_id=agentId,
            site_label=siteLabel,
            organization_id=ctx.organization_id,
        )
    except Exception:
        return dashboard_service.dashboard_summary(
            db, agent_id=None, site_label=None, organization_id=ctx.organization_id
        )
