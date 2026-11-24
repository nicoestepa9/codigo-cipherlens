"""Router de scans recurrentes (programados)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from ..cloud_guardrails import (
    OrganizationQuotaExceeded,
    enforce_recurring_scan_quota,
    require_cloud_authorization,
    resolve_cloud_scan_target,
)
from ..db import get_db
from ..deps import AuthContext, require_api_key
from ..schemas import (
    HistoryEntryOut,
    Paged,
    RecurringScanCreate,
    RecurringScanDetailOut,
    RecurringScanOut,
    RecurringScanPatch,
)
from ..services import recurring_scan_service

router = APIRouter(prefix="/api", tags=["recurring-scans"])


@router.post("/recurring-scans", response_model=RecurringScanOut, status_code=201)
def create_recurring_scan(
    payload: RecurringScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    host, port = payload.host, payload.port
    target = f"{host}:{port}"
    if payload.agentId:
        if ctx.role not in {"lead", "admin"}:
            raise HTTPException(status_code=403, detail="Insufficient role")
    else:
        require_cloud_authorization(
            db,
            request,
            ctx,
            accepted=payload.authorizationAccepted,
            version=payload.authorizationVersion,
            operation="recurring_scan.create",
            target=target,
        )
        host, port, _ = resolve_cloud_scan_target(
            db, request, ctx, payload.host, payload.port
        )
        payload.host = host
        payload.port = port
    try:
        enforce_recurring_scan_quota(db, request, ctx, target=f"{host}:{port}")
    except OrganizationQuotaExceeded as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    try:
        row = recurring_scan_service.create_recurring_scan(db, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Agent not found") from exc
    return recurring_scan_service.to_dto(row)


@router.get("/recurring-scans", response_model=list[RecurringScanOut])
def list_recurring_scans(
    enabled: bool | None = Query(default=None),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    rows = recurring_scan_service.list_recurring_scans(db, enabled=enabled)
    return [recurring_scan_service.to_dto(r) for r in rows]


@router.get("/recurring-scans/{scan_id}", response_model=RecurringScanDetailOut)
def get_recurring_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    row = recurring_scan_service.get_recurring_scan(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Recurring scan not found")
    dto = recurring_scan_service.to_dto(row)
    dto["recentScans"] = recurring_scan_service.recent_scans(db, scan_id)
    return dto


@router.get("/recurring-scans/{scan_id}/scans", response_model=Paged[HistoryEntryOut])
def list_recurring_scan_runs(
    scan_id: int,
    page: int = Query(default=1, ge=1),
    pageSize: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    row = recurring_scan_service.get_recurring_scan(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Recurring scan not found")
    items, total = recurring_scan_service.list_recurring_scan_runs(
        db, scan_id, page=page, page_size=pageSize
    )
    return {"items": items, "total": total, "page": page, "pageSize": pageSize}


@router.patch("/recurring-scans/{scan_id}", response_model=RecurringScanOut)
def update_recurring_scan(
    scan_id: int,
    payload: RecurringScanPatch,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    row = recurring_scan_service.get_recurring_scan(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Recurring scan not found")
    target_host = payload.host if payload.host is not None else row.host
    target_port = payload.port if payload.port is not None else row.port
    target = f"{target_host}:{target_port}"
    next_agent_id = (
        payload.agentId
        if "agentId" in payload.model_fields_set
        else row.agent_id
    )
    if next_agent_id:
        if ctx.role not in {"lead", "admin"}:
            raise HTTPException(status_code=403, detail="Insufficient role")
    else:
        require_cloud_authorization(
            db,
            request,
            ctx,
            accepted=payload.authorizationAccepted,
            version=payload.authorizationVersion,
            operation="recurring_scan.update",
            target=target,
        )
        host, port, _ = resolve_cloud_scan_target(
            db, request, ctx, target_host, target_port
        )
        payload.host = host
        payload.port = port
    try:
        row = recurring_scan_service.update_recurring_scan(db, row, payload)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail="Agent not found") from exc
    return recurring_scan_service.to_dto(row)


@router.delete("/recurring-scans/{scan_id}", status_code=204)
def delete_recurring_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    row = recurring_scan_service.get_recurring_scan(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Recurring scan not found")
    recurring_scan_service.delete_recurring_scan(db, row)


@router.post("/recurring-scans/{scan_id}/run-now", response_model=RecurringScanOut)
def run_now(
    scan_id: int,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    row = recurring_scan_service.get_recurring_scan(db, scan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Recurring scan not found")
    # ejecuta en su propia sesion para no interferir con la del request
    recurring_scan_service._execute_scheduled_scan(scan_id, row.organization_id)
    updated = recurring_scan_service.get_recurring_scan(db, scan_id)
    if updated is None:
        raise HTTPException(status_code=404, detail="Recurring scan not found")
    # refrescar: la corrida commitea en otra sesion y el identity map puede
    # quedar con atributos viejos (lastRunAt/nextRunAt) tras el read inicial.
    db.refresh(updated)
    return recurring_scan_service.to_dto(updated)
