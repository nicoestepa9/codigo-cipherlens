"""Admission controls shared by cloud scan and discovery routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress

from fastapi import HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..cloud_network import (
    CLOUD_SCAN_AUTHORIZATION_TEXT,
    CLOUD_SCAN_AUTHORIZATION_VERSION,
    NonPublicTargetError,
    PinnedTarget,
    is_public_address,
    parse_scan_target,
    resolve_target_addresses,
)
from .access_control import OPERATIONAL_ROLES, canonical_role
from .config import settings
from .deps import AuthContext
from .models import Agent, AuditLog, Organization, RecurringScan

class OrganizationQuotaExceeded(Exception):
    """Raised when a tenant-specific resource quota rejects an operation."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _request_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _audit(
    db: Session,
    request: Request,
    ctx: AuthContext,
    action: str,
    *,
    entity_type: str | None = None,
    entity_id: str | None = None,
    meta: dict | None = None,
) -> None:
    db.add(
        AuditLog(
            actor_user_id=ctx.user_id,
            actor_type=ctx.actor_type,
            action=action,
            entity_type=entity_type,
            entity_id=(entity_id or "")[:128] or None,
            ip=_request_ip(request),
            meta=meta or {},
            organization_id=ctx.organization_id,
        )
    )


def require_cloud_authorization(
    db: Session,
    request: Request,
    ctx: AuthContext,
    *,
    accepted: bool,
    version: str | None,
    operation: str,
    target: str,
) -> None:
    if ctx.role == "agent" or ctx.actor_type == "agent":
        raise HTTPException(
            status_code=403,
            detail="Las credenciales de agente no pueden iniciar escaneos cloud.",
        )
    if canonical_role(ctx.role) not in OPERATIONAL_ROLES:
        raise HTTPException(status_code=403, detail="Insufficient role")
    if not accepted or version != CLOUD_SCAN_AUTHORIZATION_VERSION:
        raise HTTPException(
            status_code=422,
            detail=(
                "Se requiere aceptar la declaración de autorización vigente "
                f"({CLOUD_SCAN_AUTHORIZATION_VERSION})."
            ),
        )
    _audit(
        db,
        request,
        ctx,
        "cloud_scan.authorization_accepted",
        entity_type="cloud_target",
        entity_id=target,
        meta={
            "operation": operation,
            "version": CLOUD_SCAN_AUTHORIZATION_VERSION,
            "text": CLOUD_SCAN_AUTHORIZATION_TEXT,
        },
    )
    db.commit()


def resolve_cloud_scan_target(
    db: Session,
    request: Request,
    ctx: AuthContext,
    target: str,
    default_port: int | None,
) -> tuple[str, int, PinnedTarget]:
    try:
        host, port = parse_scan_target(target, default_port)
        addresses = resolve_target_addresses(
            host,
            enforce_public=settings.cloud_scan_block_private,
        )
    except NonPublicTargetError as exc:
        _audit(
            db,
            request,
            ctx,
            "cloud_scan.destination_blocked",
            entity_type="cloud_target",
            entity_id=target,
            meta={"reason": str(exc)},
        )
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return host, port, PinnedTarget(
        address=addresses[0],
        enforce_public=settings.cloud_scan_block_private,
    )


def resolve_cloud_discovery_targets(
    db: Session,
    request: Request,
    ctx: AuthContext,
    *,
    ip_range: str,
    domains: list[str],
    scan_internal: bool,
) -> list[dict[str, str | None]]:
    """Resolve and pin every cloud discovery destination before queuing work."""
    try:
        if scan_internal:
            raise NonPublicTargetError(
                "El discovery cloud solo admite objetivos públicos; para objetivos "
                "internos usá un agente."
            )
        limit = settings.cloud_discovery_max_hosts
        targets: list[dict[str, str | None]] = []
        seen: set[str] = set()
        tokens = [
            token.strip()
            for token in (ip_range or "").replace(",", " ").split()
            if token.strip()
        ]
        for token in tokens:
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise NonPublicTargetError(
                    f"Rango de discovery inválido: {token}."
                ) from exc
            if network.num_addresses > limit + 2:
                raise NonPublicTargetError(
                    f"El discovery supera CLOUD_DISCOVERY_MAX_HOSTS ({limit})."
                )
            if settings.cloud_scan_block_private:
                for address in network:
                    if not is_public_address(str(address)):
                        raise NonPublicTargetError(
                            "El CIDR contiene direcciones internas o reservadas; "
                            "para objetivos internos usá un agente."
                        )
            for address in network.hosts():
                value = str(address)
                if value not in seen:
                    targets.append({"ip": value, "hostname": None})
                    seen.add(value)
                    if len(targets) > limit:
                        raise NonPublicTargetError(
                            f"El discovery supera CLOUD_DISCOVERY_MAX_HOSTS ({limit})."
                        )

        for domain in domains:
            name = (domain or "").strip()
            if not name:
                continue
            addresses = resolve_target_addresses(
                name,
                enforce_public=settings.cloud_scan_block_private,
            )
            for address in addresses:
                if address not in seen:
                    targets.append({"ip": address, "hostname": name})
                    seen.add(address)
                    if len(targets) > limit:
                        raise NonPublicTargetError(
                            f"El discovery supera CLOUD_DISCOVERY_MAX_HOSTS ({limit})."
                        )
        if not targets:
            raise NonPublicTargetError("El discovery no contiene objetivos válidos.")
        return targets
    except NonPublicTargetError as exc:
        _audit(
            db,
            request,
            ctx,
            "cloud_discovery.destination_blocked",
            entity_type="cloud_target",
            entity_id=(ip_range or ", ".join(domains)),
            meta={"reason": str(exc)},
        )
        db.commit()
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def record_cloud_scan_start(
    db: Session,
    request: Request,
    ctx: AuthContext,
    *,
    action: str,
    target: str,
) -> None:
    _audit(
        db,
        request,
        ctx,
        action,
        entity_type="cloud_target",
        entity_id=target,
    )
    db.commit()


def _organization_quota(db: Session, organization_id: int, field: str, default: int) -> int:
    organization = db.get(Organization, organization_id)
    if organization is None:
        raise HTTPException(status_code=401, detail="Organización no disponible.")
    return int(getattr(organization, field, 0) or default)


def _reject_quota(
    db: Session,
    request: Request,
    ctx: AuthContext,
    *,
    action: str,
    entity_type: str,
    entity_id: str | None,
    status_code: int,
    detail: str,
) -> None:
    _audit(
        db,
        request,
        ctx,
        action,
        entity_type=entity_type,
        entity_id=entity_id,
        meta={"reason": detail, "status": status_code},
    )
    db.commit()
    raise OrganizationQuotaExceeded(status_code, detail)


def enforce_cloud_scan_quota(
    db: Session,
    request: Request,
    ctx: AuthContext,
    *,
    action: str,
    target: str,
) -> None:
    if ctx.organization_id is None:
        raise HTTPException(status_code=401, detail="Organización no disponible.")
    limit = _organization_quota(
        db,
        ctx.organization_id,
        "max_cloud_scans_per_hour",
        settings.default_max_cloud_scans_per_hour,
    )
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    used = (
        db.query(func.count(AuditLog.id))
        .filter(
            AuditLog.action.in_(
                (
                    "cloud_scan.started",
                    "cloud_discovery.started",
                    "cloud_scan.scheduled_started",
                )
            ),
            AuditLog.ts >= since,
        )
        .scalar()
        or 0
    )
    if used >= limit:
        _reject_quota(
            db,
            request,
            ctx,
            action="cloud_scan.quota_rejected",
            entity_type="cloud_target",
            entity_id=target,
            status_code=429,
            detail="Se alcanzó la cuota de escaneos cloud por hora de la organización.",
        )


def enforce_agent_quota(
    db: Session,
    request: Request,
    ctx: AuthContext,
    *,
    name: str,
) -> None:
    if ctx.organization_id is None:
        raise HTTPException(status_code=401, detail="Organización no disponible.")
    limit = _organization_quota(
        db,
        ctx.organization_id,
        "max_agents",
        settings.default_max_agents,
    )
    count = (
        db.query(func.count(Agent.id))
        .filter(Agent.status == "active")
        .scalar()
        or 0
    )
    if count >= limit:
        _reject_quota(
            db,
            request,
            ctx,
            action="agent.quota_rejected",
            entity_type="agent",
            entity_id=name,
            status_code=409,
            detail="La organización alcanzó su límite de agentes.",
        )


def enforce_recurring_scan_quota(
    db: Session,
    request: Request,
    ctx: AuthContext,
    *,
    target: str,
) -> None:
    if ctx.organization_id is None:
        raise HTTPException(status_code=401, detail="Organización no disponible.")
    limit = _organization_quota(
        db,
        ctx.organization_id,
        "max_recurring_scans",
        settings.default_max_recurring_scans,
    )
    count = db.query(func.count(RecurringScan.id)).scalar() or 0
    if count >= limit:
        _reject_quota(
            db,
            request,
            ctx,
            action="recurring_scan.quota_rejected",
            entity_type="recurring_scan",
            entity_id=target,
            status_code=409,
            detail="La organización alcanzó su límite de escaneos recurrentes.",
        )
