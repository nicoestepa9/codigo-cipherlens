"""Router de scans: ejecutar analisis y consultar resultados."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..cloud_guardrails import (
    OrganizationQuotaExceeded,
    enforce_cloud_scan_quota,
    record_cloud_scan_start,
    require_cloud_authorization,
    resolve_cloud_scan_target,
)
from ..deps import AuthContext, require_api_key, require_auth
from ..schemas import (
    AiRecommendationOut,
    AgentTaskAcceptedOut,
    Paged,
    ScanRequest,
    ScanResultOut,
    HistoryEntryOut,
)
from ..services import agent_task_service
from ..services import scan_service
from ...cloud_network import parse_scan_target
from ..db import get_db

router = APIRouter(prefix="/api", tags=["scans"])


@router.post(
    "/scans",
    response_model=ScanResultOut,
    responses={202: {"model": AgentTaskAcceptedOut}},
)
def run_scan(
    payload: ScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_auth),
):
    if payload.executor and payload.executor.type == "agent":
        if ctx.role not in {"lead", "admin"}:
            raise HTTPException(status_code=403, detail="Insufficient role")
        try:
            host, port = parse_scan_target(payload.target, payload.port)
            options = (
                payload.options.model_dump(exclude_none=True)
                if payload.options
                else {}
            )
            task = agent_task_service.create_task(
                db,
                agent_id=payload.executor.agentId or "",
                task_type="scan",
                payload={
                    "target": {"host": host, "port": port},
                    "options": options,
                },
                requested_by_user_id=ctx.user_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="Agent not found") from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return JSONResponse(
            {"taskId": task.id, "status": task.status}, status_code=202
        )

    require_cloud_authorization(
        db,
        request,
        ctx,
        accepted=payload.authorizationAccepted,
        version=payload.authorizationVersion,
        operation="scan",
        target=payload.target,
    )
    host, port, pinned_target = resolve_cloud_scan_target(
        db, request, ctx, payload.target, payload.port
    )
    try:
        enforce_cloud_scan_quota(
            db, request, ctx, action="cloud_scan.started", target=payload.target
        )
    except OrganizationQuotaExceeded as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    record_cloud_scan_start(
        db,
        request,
        ctx,
        action="cloud_scan.started",
        target=payload.target,
    )
    result = scan_service.run_scan(
        db,
        host,
        port=port,
        options=payload.options.model_dump() if payload.options else None,
        pinned_target=pinned_target,
    )
    return result


@router.get("/scans", response_model=Paged[HistoryEntryOut])
def list_scans(
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=100),
    search: str | None = None,
    agentId: str | None = None,
    siteLabel: str | None = None,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    items, total = scan_service.list_scans(
        db, page=page, page_size=pageSize, search=search,
        agent_id=agentId, site_label=siteLabel,
    )
    return {"items": items, "total": total, "page": page, "pageSize": pageSize}


@router.get("/scans/{scan_id}", response_model=ScanResultOut)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    result = scan_service.get_scan_result_dto(db, scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.get("/scans/{scan_id}/ai-recommendation", response_model=AiRecommendationOut)
def get_ai_recommendation(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    from ..models import Scan

    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.ai_recommendation:
        return {"recommendation": scan.ai_recommendation, "source": "stored"}
    findings_dtos = []
    for f in scan.findings:
        findings_dtos.append({
            "severity": f.severity, "title": f.title,
            "description": f.description, "recommendation": f.recommendation,
            "affectedHost": f.affected_host,
        })
    text, source = scan_service.generate_tenant_recommendation(
        db, scan.score or 0, findings_dtos, scan.host
    )
    scan.ai_recommendation = text
    db.commit()
    return {"recommendation": text, "source": source}
