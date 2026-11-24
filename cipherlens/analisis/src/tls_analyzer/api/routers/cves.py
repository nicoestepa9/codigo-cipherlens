"""Router de CVEs: consultar detalle, CVEs de un scan, forzar refresh."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..deps import require_api_key
from ..schemas import CveReferenceOut, CveLiveMatchOut, Paged
from ..services import cve_service
from ..db import get_db

router = APIRouter(prefix="/api", tags=["cves"])


@router.get("/cves/{cve_id}")
def get_cve_detail(
    cve_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    """Detalle de un CVE desde la caché local."""
    detail = cve_service.get_cve_detail(db, cve_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found in local cache")
    return detail


@router.get("/scans/{scan_id}/cves")
def get_scan_cves(
    scan_id: str,
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    """CVEs asociados a un scan (estáticos + NVD live)."""
    from ..models import Scan
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return cve_service.get_scan_cve_matches(db, scan_id)


@router.post("/cves/refresh")
def refresh_cves(
    db: Session = Depends(get_db),
    _: None = Depends(require_api_key),
):
    """Fuerza actualización de la caché de CVEs (job administrativo)."""
    updated = cve_service.refresh_cve_cache(db)
    return {"updated": updated, "status": "completed"}
