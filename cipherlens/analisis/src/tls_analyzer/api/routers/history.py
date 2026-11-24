"""Router de historial de scans."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..deps import require_api_key
from ..schemas import HistoryEntryOut, Paged, ScanResultOut
from ..services import scan_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["history"])


@router.get("/history", response_model=Paged[HistoryEntryOut])
def list_history(
    page: int = Query(1, ge=1),
    pageSize: int = Query(20, ge=1, le=100),
    search: str | None = None,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    items, total = scan_service.list_scans(db, page=page, page_size=pageSize, search=search)
    return {"items": items, "total": total, "page": page, "pageSize": pageSize}


@router.get("/history/{scan_id}/result", response_model=ScanResultOut)
def get_history_result(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    result = scan_service.get_scan_result_dto(db, scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result
