"""Router de activos: listado y creación de activos inventariados."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..deps import AuthContext, require_api_key
from ..models import Asset
from ..schemas import AssetOut, AssetCreateIn
from ..db import get_db

router = APIRouter(prefix="/api", tags=["assets"])


@router.get("/assets", response_model=list[AssetOut])
def list_assets(
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    """List all assets for the current organization."""
    assets = db.query(Asset).filter(
        Asset.organization_id == ctx.organization_id
    ).all()
    return assets


@router.post("/assets", response_model=AssetOut)
def create_asset(
    asset_in: AssetCreateIn,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    """Create a new asset (typically from discovery)."""
    port = asset_in.port if asset_in.port is not None else 443
    # La identidad de un asset es (ip_address, hostname, port): el mismo host en
    # distintos puertos son activos distintos.
    existing = db.query(Asset).filter(
        Asset.organization_id == ctx.organization_id,
        Asset.ip_address == asset_in.ip_address,
        func.coalesce(Asset.hostname, "") == asset_in.hostname,
        Asset.port == port,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail="Asset already exists")

    # Determine source: if ip_address or hostname provided, it's from discovery
    source = "discovery" if asset_in.ip_address else "manual"

    db_asset = Asset(
        ip_address=asset_in.ip_address,
        hostname=asset_in.hostname,
        port=port,
        service=asset_in.service,
        tls_version=asset_in.tls_version,
        scope=asset_in.scope,
        inventory_status=asset_in.inventory_status,
        source=source,
        organization_id=ctx.organization_id,
    )
    db.add(db_asset)
    db.commit()
    db.refresh(db_asset)
    return db_asset


@router.delete("/assets/{asset_id}", response_model=dict)
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    ctx: AuthContext = Depends(require_api_key),
):
    """Delete an asset by ID."""
    db_asset = db.query(Asset).filter(
        Asset.id == asset_id,
        Asset.organization_id == ctx.organization_id
    ).first()
    if db_asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(db_asset)
    db.commit()
    return {"detail": "Asset deleted successfully"}
