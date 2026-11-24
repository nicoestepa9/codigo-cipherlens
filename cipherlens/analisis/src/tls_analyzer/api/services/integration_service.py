"""Servicio de integraciones y API keys."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..deps import generate_api_key, hash_api_key
from ..models import ApiKey, Integration


def list_integrations(db: Session) -> list[dict]:
    rows = db.query(Integration).all()
    return [
        {
            "id": i.id,
            "name": i.name,
            "type": i.type,
            "description": i.description,
            "status": i.status,
            "lastSyncAt": i.last_sync_at.isoformat() if i.last_sync_at else None,
        }
        for i in rows
    ]


def _key_to_dto(k: ApiKey) -> dict:
    return {
        "id": k.id,
        "name": k.name,
        "prefix": k.prefix,
        "createdAt": k.created_at.isoformat() if k.created_at else "",
        "lastUsedAt": k.last_used_at.isoformat() if k.last_used_at else None,
        "revoked": k.revoked,
        "role": getattr(k, "role", "lead"),
        "expiresAt": k.expires_at.isoformat() if getattr(k, "expires_at", None) else None,
    }


def list_api_keys(db: Session) -> list[dict]:
    rows = db.query(ApiKey).order_by(ApiKey.created_at.desc()).all()
    return [_key_to_dto(k) for k in rows]


def create_api_key(
    db: Session,
    name: str,
    *,
    role: str = "lead",
    expires_in_days: int | None = None,
    user_id: str | None = None,
) -> tuple[dict, str]:
    if role not in ("viewer", "lead", "user"):
        role = "lead"  # las API keys nunca son admin
    plain = generate_api_key()
    expires_at = None
    if expires_in_days is not None and expires_in_days > 0:
        from datetime import timedelta

        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    key = ApiKey(
        name=name or "default",
        key_hash=hash_api_key(plain),
        prefix=plain[:8] + "...",
        role=role,
        expires_at=expires_at,
        user_id=user_id,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    dto = _key_to_dto(key)
    dto["key"] = plain
    return dto, plain


def revoke_api_key(db: Session, key_id: str) -> bool:
    key = db.get(ApiKey, key_id)
    if key is None:
        return False
    key.revoked = True
    db.commit()
    return True


def touch_key(db: Session, key_id: str) -> None:
    key = db.get(ApiKey, key_id)
    if key is not None:
        key.last_used_at = datetime.now(timezone.utc)
        db.commit()


_API_ENDPOINTS = [
    {"method": "POST", "path": "/api/scans", "description": "Run a TLS analysis against a target", "example": "curl -X POST /api/scans -H 'X-API-Key: cg_...' -d '{\"target\":\"example.com\"}'"},
    {"method": "GET", "path": "/api/scans", "description": "List scan history (paginated)", "example": "curl /api/scans?page=1&pageSize=20"},
    {"method": "GET", "path": "/api/scans/{id}", "description": "Get a scan result by id", "example": "curl /api/scans/<id>"},
    {"method": "GET", "path": "/api/certificates", "description": "List certificates with filters", "example": "curl '/api/certificates?status=expiring&days=15'"},
    {"method": "GET", "path": "/api/certificates/{id}", "description": "Certificate detail + chain + related services", "example": "curl /api/certificates/<id>"},
    {"method": "GET", "path": "/api/services", "description": "List services inventory", "example": "curl /api/services?status=critical"},
    {"method": "GET", "path": "/api/services/{id}", "description": "Service detail (asset, cert, findings)", "example": "curl /api/services/<id>"},
    {"method": "GET", "path": "/api/dashboard", "description": "Aggregated security overview", "example": "curl /api/dashboard"},
    {"method": "GET", "path": "/api/vulnerabilities", "description": "List findings with filters", "example": "curl '/api/vulnerabilities?severity=critical'"},
    {"method": "GET", "path": "/api/vulnerabilities/stats", "description": "Vulnerability statistics", "example": "curl /api/vulnerabilities/stats"},
    {"method": "GET", "path": "/api/alerts", "description": "List alerts", "example": "curl /api/alerts?status=unread"},
    {"method": "PUT", "path": "/api/alerts/{id}/status", "description": "Mark alert as read/resolved/ignored", "example": "curl -X PUT /api/alerts/<id>/status -d '{\"status\":\"resolved\"}'"},
    {"method": "POST", "path": "/api/discovery", "description": "Start a network discovery job", "example": "curl -X POST /api/discovery -d '{\"ipRange\":\"10.0.0.0/24\",\"ports\":[443,8080]}'"},
    {"method": "GET", "path": "/api/discovery/{id}", "description": "Discovery job status/progress", "example": "curl /api/discovery/<id>"},
    {"method": "GET", "path": "/api/discovery/{id}/results", "description": "Discovery results of a job", "example": "curl /api/discovery/<id>/results"},
    {"method": "GET", "path": "/api/discovery/results", "description": "All discovery results", "example": "curl /api/discovery/results"},
    {"method": "GET", "path": "/api/discovery/summary", "description": "Discovery summary counts", "example": "curl /api/discovery/summary"},
    {"method": "POST", "path": "/api/api-keys", "description": "Generate an API key (shown once)", "example": "curl -X POST /api/api-keys -d '{\"name\":\"ci\"}'"},
    {"method": "GET", "path": "/api/settings/thresholds", "description": "Read alert thresholds", "example": "curl /api/settings/thresholds"},
    {"method": "PUT", "path": "/api/settings/thresholds", "description": "Update alert thresholds", "example": "curl -X PUT /api/settings/thresholds -d '{\"daysBeforeExpiry\":[30,15,7]}'"},
]


def api_endpoints() -> list[dict]:
    return list(_API_ENDPOINTS)
