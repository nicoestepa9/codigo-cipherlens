"""Endpoints de reporte para Grafana (Parte 6.2).

Arreglos JSON planos, marcas RFC 3339 UTC, pensados para el plugin Infinity.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (
    Agent,
    Certificate,
    DiscoveryJob,
    DiscoveryResult,
    Issue,
    IssueHistory,
    Scan,
    Service,
    Team,
    User,
)

OPEN_STATUSES = ("open", "assigned", "in_progress")
RESOLVED_LIKE = ("resolved", "verified", "risk_accepted", "false_positive")
# risk_accepted y false_positive nunca cuentan como abiertos.

SEVERITIES = ("critical", "high", "medium", "low", "info")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return _as_utc(dt).isoformat().replace("+00:00", "Z")


def parse_range(
    from_: Optional[datetime],
    to: Optional[datetime],
    bucket: str = "day",
) -> tuple[datetime, datetime, int]:
    """Valida rango y bucket. Devuelve (from, to, dias). Lanza ValueError."""
    if bucket not in ("day", "week"):
        raise ValueError("bucket invalido: use 'day' o 'week'")

    now = _utcnow()
    end = _as_utc(to) if to else now
    start = _as_utc(from_) if from_ else end - timedelta(days=90)

    if start >= end:
        raise ValueError("from debe ser menor que to")
    days = (end - start).days + 1
    if days > settings.reports_max_range_days:
        raise ValueError(
            f"rango maximo {settings.reports_max_range_days} dias; recibido {days}"
        )
    return start, end, days


def _bucket_starts(start: datetime, end: datetime, bucket: str) -> list[datetime]:
    """Alinea los inicios de bucket. week = lunes UTC. No genera huecos."""
    step = timedelta(days=1) if bucket == "day" else timedelta(days=7)
    # Alinear al inicio del dia/semana.
    cur = datetime(start.year, start.month, start.day, tzinfo=timezone.utc)
    if bucket == "week":
        cur = cur - timedelta(days=cur.weekday())
    out: list[datetime] = []
    while cur <= end:
        out.append(cur)
        cur = cur + step
        if len(out) >= settings.reports_max_buckets:
            break
    if len(out) >= settings.reports_max_buckets:
        raise ValueError(
            f"excede el maximo de {settings.reports_max_buckets} buckets; "
            "use un rango menor o bucket='week'"
        )
    return out


def _bucket_end(cur: datetime, bucket: str, end: datetime) -> datetime:
    step = timedelta(days=1) if bucket == "day" else timedelta(days=7)
    nxt = cur + step
    return min(nxt, end)


# ---------------------------------------------------------------- score-history

def score_history(
    db: Session,
    from_dt: datetime,
    to_dt: datetime,
    bucket: str,
    *,
    agent_id: Optional[str] = None,
    service_id: Optional[str] = None,
    team_id: Optional[str] = None,
) -> list[dict]:
    q = db.query(
        Scan.started_at, Scan.score
    ).filter(
        Scan.status == "completed",
        Scan.started_at >= from_dt,
        Scan.started_at <= to_dt,
    )
    if agent_id:
        q = q.filter(Scan.agent_id == agent_id)
    if service_id:
        q = q.filter(Scan.service_id == service_id)
    if team_id:
        q = q.filter(Scan.service_id.in_(
            db.query(Service.id).filter(
                Service.default_owner_team_id == team_id
            )
        ))

    rows = q.all()
    starts = _bucket_starts(from_dt, to_dt, bucket)
    buckets: list[dict] = []
    for cur in starts:
        nxt = _bucket_end(cur, bucket, to_dt)
        scores = [r[1] for r in rows if r[0] and cur <= _as_utc(r[0]) < nxt and r[1] is not None]
        if scores:
            buckets.append({
                "ts": _iso(cur),
                "avgScore": round(sum(scores) / len(scores), 2),
                "minScore": min(scores),
                "scans": len(scores),
            })
        else:
            buckets.append({"ts": _iso(cur), "avgScore": None, "minScore": None, "scans": 0})
    return buckets


# ----------------------------------------------------------------- issues-trend

def issues_trend(
    db: Session,
    from_dt: datetime,
    to_dt: datetime,
    bucket: str,
    *,
    severity: Optional[str] = None,
    agent_id: Optional[str] = None,
    service_id: Optional[str] = None,
    team_id: Optional[str] = None,
) -> list[dict]:
    """Tendencia de issues por bucket.

    - opened/resolved por bucket: derivados de IssueHistory (to_value).
    - openAtEnd: estado al cierre del bucket reconstruido desde IssueHistory
      (un issue reabierto vuelve a contar como abierto). Los estados
      ``risk_accepted`` y ``false_positive`` nunca cuentan como abiertos.
    """
    sev_filter = [severity] if severity and severity != "all" else list(SEVERITIES)

    # Issue ids filtrados (para acotar los joins).
    iq = db.query(Issue.id, Issue.severity, Issue.first_seen_at, Issue.status)
    if service_id:
        iq = iq.filter(Issue.service_id == service_id)
    if agent_id or team_id:
        sq = db.query(Service.id)
        if agent_id:
            sq = sq.filter(Service.agent_id == agent_id)
        if team_id:
            sq = sq.filter(Service.default_owner_team_id == team_id)
        iq = iq.filter(Issue.service_id.in_(sq))
    issues = iq.all()
    issue_ids = [i[0] for i in issues if i[1] in sev_filter]
    sev_by_id = {i[0]: i[1] for i in issues}

    # Historial de transiciones en el rango, agrupado por issue.
    hq = db.query(IssueHistory.issue_id, IssueHistory.to_value, IssueHistory.ts).filter(
        IssueHistory.ts >= from_dt, IssueHistory.ts <= to_dt
    )
    if issue_ids:
        hq = hq.filter(IssueHistory.issue_id.in_(issue_ids))
    events: dict[str, list[tuple[datetime, str]]] = {}
    hist = hq.all()
    for issue_id, to_value, ts in hist:
        if ts is None:
            continue
        events.setdefault(issue_id, []).append((_as_utc(ts), to_value or ""))
    for ev in events.values():
        ev.sort(key=lambda e: e[0])

    def _open_at_end(sev: str, nxt: datetime) -> int:
        total = 0
        for iid, isev, first, status in issues:
            if isev != sev or iid not in issue_ids:
                continue
            if first is not None and _as_utc(first) > nxt:
                continue
            latest: Optional[str] = None
            for ts, to_value in events.get(iid, ()):
                if ts <= nxt:
                    latest = to_value
            if latest is not None:
                is_open = latest in OPEN_STATUSES
            else:
                is_open = status in OPEN_STATUSES
            if is_open:
                total += 1
        return total

    starts = _bucket_starts(from_dt, to_dt, bucket)
    out: list[dict] = []
    for cur in starts:
        nxt = _bucket_end(cur, bucket, to_dt)
        for sev in sev_filter:
            opened = 0
            resolved = 0
            for issue_id, to_value, ts in hist:
                if not ts or not (cur <= _as_utc(ts) < nxt):
                    continue
                if sev_by_id.get(issue_id) != sev:
                    continue
                if to_value in OPEN_STATUSES:
                    opened += 1
                elif to_value in RESOLVED_LIKE:
                    resolved += 1
            out.append({
                "ts": _iso(cur),
                "severity": sev,
                "opened": opened,
                "resolved": resolved,
                "openAtEnd": _open_at_end(sev, nxt),
            })
    return out


# ---------------------------------------------------- certificates-by-expiry

def certificates_by_expiry(db: Session) -> list[dict]:
    rows = db.query(Certificate.days_until_expiry, Certificate.is_expired).all()
    buckets = {"expired": 0, "<=7d": 0, "8-30d": 0, "31-90d": 0, ">90d": 0}
    for days, expired in rows:
        if expired or days < 0:
            buckets["expired"] += 1
        elif days <= 7:
            buckets["<=7d"] += 1
        elif days <= 30:
            buckets["8-30d"] += 1
        elif days <= 90:
            buckets["31-90d"] += 1
        else:
            buckets[">90d"] += 1
    return [{"bucket": k, "count": v} for k, v in buckets.items()]


# ---------------------------------------------------------------- issues-by-owner

def _owner_name(db: Session, user_id: Optional[str], team_id: Optional[str]) -> tuple[str, str, Optional[str]]:
    if user_id:
        u = db.get(User, user_id)
        if u is None:
            return "user", "Usuario eliminado", None
        return "user", getattr(u, "name", None) or getattr(u, "username", None) or "Usuario eliminado", user_id
    if team_id:
        t = db.get(Team, team_id)
        if t is None:
            return "team", "Equipo eliminado", None
        return "team", t.name, team_id
    return "none", "Sin owner", None


def issues_by_owner(
    db: Session,
    *,
    status: Optional[str] = None,
    overdue: Optional[bool] = None,
    agent_id: Optional[str] = None,
    service_id: Optional[str] = None,
    team_id: Optional[str] = None,
) -> list[dict]:
    q = db.query(Issue)
    if status and status != "all":
        q = q.filter(Issue.status == status)
    else:
        q = q.filter(Issue.status.notin_(("resolved", "verified", "false_positive")))
    if service_id:
        q = q.filter(Issue.service_id == service_id)
    if agent_id or team_id:
        sq = db.query(Service.id)
        if agent_id:
            sq = sq.filter(Service.agent_id == agent_id)
        if team_id:
            sq = sq.filter(Service.default_owner_team_id == team_id)
        q = q.filter(Issue.service_id.in_(sq))
    rows = q.all()
    now = _utcnow()

    agg: dict[tuple, dict] = {}
    for issue in rows:
        if overdue and not (issue.due_at and _as_utc(issue.due_at) < now):
            continue
        owner_type, owner_name, owner_id = _owner_name(
            db, issue.owner_user_id, issue.owner_team_id
        )
        key = (owner_type, owner_id, owner_name)
        entry = agg.setdefault(
            key,
            {"ownerType": owner_type, "ownerId": owner_id, "ownerName": owner_name,
             "open": 0, "overdue": 0, "critical": 0, "high": 0},
        )
        entry["open"] += 1
        if issue.due_at and _as_utc(issue.due_at) < now:
            entry["overdue"] += 1
        if issue.severity == "critical":
            entry["critical"] += 1
        elif issue.severity == "high":
            entry["high"] += 1

    out = sorted(agg.values(), key=lambda e: (-e["critical"], -e["high"], -e["open"]))
    return out


# ---------------------------------------------------------------- issues-by-status

def issues_by_status(db: Session, *, agent_id: Optional[str] = None,
                     service_id: Optional[str] = None, team_id: Optional[str] = None) -> list[dict]:
    q = db.query(Issue.status, func.count(Issue.id))
    if service_id:
        q = q.filter(Issue.service_id == service_id)
    if agent_id or team_id:
        sq = db.query(Service.id)
        if agent_id:
            sq = sq.filter(Service.agent_id == agent_id)
        if team_id:
            sq = sq.filter(Service.default_owner_team_id == team_id)
        q = q.filter(Issue.service_id.in_(sq))
    counts = {row[0]: row[1] for row in q.group_by(Issue.status).all()}
    # Devuelve todos los estados conocidos, con ceros.
    all_statuses = ("open", "assigned", "in_progress", "resolved", "verified",
                    "risk_accepted", "false_positive")
    return [{"status": s, "count": counts.get(s, 0)} for s in all_statuses]


# -------------------------------------------------------------- shadow-it-trend

def shadow_it_trend(
    db: Session,
    from_dt: datetime,
    to_dt: datetime,
    bucket: str,
    *,
    agent_id: Optional[str] = None,
) -> list[dict]:
    q = db.query(DiscoveryResult.first_seen, DiscoveryResult.inventory_status).join(
        DiscoveryJob, DiscoveryResult.discovery_job_id == DiscoveryJob.id
    ).filter(DiscoveryResult.first_seen >= from_dt, DiscoveryResult.first_seen <= to_dt)
    if agent_id:
        q = q.filter(DiscoveryJob.agent_id == agent_id)
    rows = q.all()

    starts = _bucket_starts(from_dt, to_dt, bucket)
    out: list[dict] = []
    for cur in starts:
        nxt = _bucket_end(cur, bucket, to_dt)
        shadow = 0
        inventoried = 0
        for first_seen, status in rows:
            if not first_seen or not (cur <= _as_utc(first_seen) < nxt):
                continue
            if status == "shadow_it":
                shadow += 1
            elif status == "inventoried":
                inventoried += 1
        out.append({"ts": _iso(cur), "shadowIt": shadow, "inventoried": inventoried})
    return out


# ---------------------------------------------------------------- agents-status

def agents_status(db: Session) -> list[dict]:
    rows = db.query(Agent).order_by(Agent.created_at.desc()).all()
    counts: dict[str, int] = {}
    for agent_id, in db.query(Service.agent_id).filter(Service.agent_id.isnot(None)).all():
        counts[agent_id] = counts.get(agent_id, 0) + 1
    from . import agent_service as _as

    out: list[dict] = []
    for a in rows:
        out.append({
            "agentId": a.id,
            "name": a.name,
            "siteLabel": a.site_label or "",
            "status": a.status,
            "lastSeenAt": _iso(a.last_seen_at),
            "services": counts.get(a.id, 0),
            "online": _as.is_online(a),
        })
    return out


# --------------------------------------------------------------------- summary

def summary(db: Session, *, agent_id: Optional[str] = None,
            service_id: Optional[str] = None, team_id: Optional[str] = None) -> list[dict]:
    now = _utcnow()

    sq = db.query(Service.id)
    if agent_id:
        sq = sq.filter(Service.agent_id == agent_id)
    if team_id:
        sq = sq.filter(Service.default_owner_team_id == team_id)
    service_ids = [r[0] for r in sq.all()] if (agent_id or team_id) else None

    iq = db.query(Issue)
    if service_id:
        iq = iq.filter(Issue.service_id == service_id)
    if service_ids is not None:
        iq = iq.filter(Issue.service_id.in_(service_ids))
    issues = iq.all()

    total_services = db.query(func.count(Service.id)).scalar() if service_ids is None else len(service_ids)

    critical_open = sum(1 for i in issues if i.severity == "critical" and i.status in OPEN_STATUSES)
    high_open = sum(1 for i in issues if i.severity == "high" and i.status in OPEN_STATUSES)
    overdue = sum(
        1 for i in issues
        if i.status in OPEN_STATUSES and i.due_at and _as_utc(i.due_at) < now
    )
    unassigned = sum(
        1 for i in issues if i.status in OPEN_STATUSES and not i.owner_user_id and not i.owner_team_id
    )
    certs_expiring_30 = db.query(func.count(Certificate.id)).filter(
        Certificate.is_expired == False,  # noqa: E712
        Certificate.days_until_expiry <= 30,
    ).scalar()

    scan_q = db.query(Scan.score).filter(Scan.status == "completed", Scan.score.isnot(None))
    if service_id:
        scan_q = scan_q.filter(Scan.service_id == service_id)
    if agent_id:
        scan_q = scan_q.filter(Scan.agent_id == agent_id)
    scores = [r[0] for r in scan_q.all()]
    avg_score = round(sum(scores) / len(scores), 2) if scores else None

    return [
        {"metric": "totalServices", "value": total_services},
        {"metric": "criticalOpen", "value": critical_open},
        {"metric": "highOpen", "value": high_open},
        {"metric": "overdue", "value": overdue},
        {"metric": "unassigned", "value": unassigned},
        {"metric": "certsExpiring30d", "value": certs_expiring_30},
        {"metric": "avgScore", "value": avg_score},
    ]


# ---------------------------------------------------------------- dimensions

def dimensions(db: Session) -> dict:
    agents = [{"agentId": a.id, "name": a.name, "siteLabel": a.site_label or ""}
              for a in db.query(Agent).order_by(Agent.name).all()]
    teams = [{"teamId": t.id, "name": t.name} for t in db.query(Team).order_by(Team.name).all()]
    services = [{"serviceId": s.id, "host": s.host, "port": s.port}
                for s in db.query(Service).order_by(Service.host).all()]
    return {"agents": agents, "teams": teams, "services": services}
