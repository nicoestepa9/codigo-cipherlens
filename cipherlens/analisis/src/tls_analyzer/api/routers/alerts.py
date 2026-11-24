"""Router de alertas."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..deps import require_api_key
from ..schemas import AlertOut, AlertStatusUpdate
from ..services import alert_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(
    type: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    return alert_service.list_alerts(db, type_=type, severity=severity, status=status)


@router.put("/alerts/{alert_id}/status", response_model=AlertOut)
def update_alert_status(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    alert = alert_service.set_alert_status(db, alert_id, payload.status)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
