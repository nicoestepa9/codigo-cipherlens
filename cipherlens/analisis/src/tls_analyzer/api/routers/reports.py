"""Router de reportes para Grafana (Parte 6.2). Solo lectura, planos."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BeforeValidator
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import AuthContext, require_role
from ..services import report_service

router = APIRouter(prefix="/api/reports", tags=["reports"])

# viewer o superior (viewer < user < lead < admin); una key de rol "agent" queda afuera (403).
_require = require_role("viewer", "user", "lead", "admin")

_CACHE = "private, max-age=60"


def _cache(resp: Response) -> None:
    resp.headers["Cache-Control"] = _CACHE


def _filter_id(value: str | None) -> str | None:
    return None if value in ("", "__all__") else value


ReportFilter = Annotated[str | None, BeforeValidator(_filter_id)]


def _parse_dt(value: Optional[str], name: str) -> Optional[datetime]:
    if value in (None, ""):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(422, detail=f"fecha invalida en '{name}': {value}")


def _range(from_, to, bucket):
    try:
        start, end, _ = report_service.parse_range(
            _parse_dt(from_, "from"), _parse_dt(to, "to"), bucket
        )
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc))
    return start, end


@router.get(
    "/score-history",
    summary="Historial de score TLS por bucket",
    description=(
        "Serie temporal del score de scans **completed**, agrupada por dia o "
        "semana (UTC). Cada punto: `{ts, avgScore, minScore, scans}`. Los "
        "buckets sin datos devuelven `scans=0` y score `null` (sin huecos). "
        "Filtros opcionales `agentId`, `serviceId`, `teamId`."
    ),
)
def score_history(
    from_: Optional[str] = Query(None, alias="from", description="RFC 3339 UTC; default: to-90d"),
    to: Optional[str] = Query(None, description="RFC 3339 UTC; default: ahora"),
    bucket: str = Query("day", description="day|week"),
    agentId: ReportFilter = None,
    serviceId: ReportFilter = None,
    teamId: ReportFilter = None,
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    start, end = _range(from_, to, bucket)
    _cache(resp)
    return report_service.score_history(
        db, start, end, bucket, agent_id=agentId, service_id=serviceId, team_id=teamId
    )


@router.get(
    "/issues-trend",
    summary="Aperturas, resoluciones y abiertos por bucket",
    description=(
        "Por bucket y severidad: `{ts, severity, opened, resolved, openAtEnd}`. "
        "`opened`/`resolved` se derivan de `IssueHistory`; `openAtEnd` es el "
        "estado al cierre del bucket (un issue reabierto vuelve a contar como "
        "abierto). `risk_accepted` y `false_positive` no cuentan como abiertos. "
        "Filtro opcional `severity` (default: todas)."
    ),
)
def issues_trend(
    from_: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = None,
    bucket: str = Query("day", description="day|week"),
    severity: Optional[str] = Query(None, description="critical|high|medium|low|info|all"),
    agentId: ReportFilter = None,
    serviceId: ReportFilter = None,
    teamId: ReportFilter = None,
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    start, end = _range(from_, to, bucket)
    _cache(resp)
    return report_service.issues_trend(
        db, start, end, bucket, severity=severity,
        agent_id=agentId, service_id=serviceId, team_id=teamId,
    )


@router.get(
    "/certificates-by-expiry",
    summary="Certificados agrupados por vencimiento",
    description=(
        "`[{bucket, count}]` con `expired`, `<=7d`, `8-30d`, `31-90d`, `>90d`. "
        "Pensado para gauges de Grafana."
    ),
)
def certificates_by_expiry(
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    _cache(resp)
    return report_service.certificates_by_expiry(db)


@router.get(
    "/issues-by-owner",
    summary="Issues abiertos por responsable",
    description=(
        "`[{ownerType, ownerId, ownerName, open, overdue, critical, high}]`. "
        "`ownerType` es `user`/`team`/`none`. Solo se expone el nombre mostrado "
        "(nunca el email); un owner eliminado aparece como \"Usuario eliminado\". "
        "Filtros: `status`, `overdue`, `agentId`, `serviceId`, `teamId`."
    ),
)
def issues_by_owner(
    status: Optional[str] = Query(None, description="estado exacto; default: abiertos"),
    overdue: Optional[bool] = Query(None, description="solo vencidos (due_at < ahora)"),
    agentId: ReportFilter = None,
    serviceId: ReportFilter = None,
    teamId: ReportFilter = None,
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    _cache(resp)
    return report_service.issues_by_owner(
        db, status=status, overdue=overdue,
        agent_id=agentId, service_id=serviceId, team_id=teamId,
    )


@router.get(
    "/issues-by-status",
    summary="Issues por estado",
    description="`[{status, count}]` incluyendo los estados con cero.",
)
def issues_by_status(
    agentId: ReportFilter = None,
    serviceId: ReportFilter = None,
    teamId: ReportFilter = None,
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    _cache(resp)
    return report_service.issues_by_status(
        db, agent_id=agentId, service_id=serviceId, team_id=teamId
    )


@router.get(
    "/shadow-it-trend",
    summary="Tendencia de Shadow IT por bucket",
    description=(
        "`[{ts, shadowIt, inventoried}]` a partir de los resultados de discovery "
        "de agentes on-premise. Filtro opcional `agentId`."
    ),
)
def shadow_it_trend(
    from_: Optional[str] = Query(None, alias="from"),
    to: Optional[str] = None,
    bucket: str = Query("day", description="day|week"),
    agentId: ReportFilter = None,
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    start, end = _range(from_, to, bucket)
    _cache(resp)
    return report_service.shadow_it_trend(db, start, end, bucket, agent_id=agentId)


@router.get(
    "/agents-status",
    summary="Estado de los agentes on-premise",
    description=(
        "`[{agentId, name, siteLabel, status, lastSeenAt, services, online}]` "
        "para el panel de infraestructura."
    ),
)
def agents_status(
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    _cache(resp)
    return report_service.agents_status(db)


@router.get(
    "/summary",
    summary="Métricas agregadas puntuales",
    description=(
        "`[{metric, value}]`: totalServices, criticalOpen, highOpen, overdue, "
        "unassigned, certsExpiring30d, avgScore. Filtros opcionales `agentId`, "
        "`serviceId`, `teamId`."
    ),
)
def summary(
    agentId: ReportFilter = None,
    serviceId: ReportFilter = None,
    teamId: ReportFilter = None,
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    _cache(resp)
    return report_service.summary(
        db, agent_id=agentId, service_id=serviceId, team_id=teamId
    )


@router.get(
    "/dimensions",
    summary="Dimensiones para variables del dashboard",
    description=(
        "`{agents: [...], teams: [...], services: [...]}` para poblar variables "
        "dinámicas en Grafana."
    ),
)
def dimensions(
    db: Session = Depends(get_db),
    resp: Response = None,
    _ctx: AuthContext = Depends(_require),
):
    _cache(resp)
    return report_service.dimensions(db)
