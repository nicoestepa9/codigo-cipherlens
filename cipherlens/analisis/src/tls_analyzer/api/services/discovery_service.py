"""Servicio de discovery: jobs en background, resultados e inventario."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ...discovery import (
    DiscoveredService,
    DiscoveryCancelled,
    estimate_target_count,
    is_internal_ip,
    parse_targets,
    run_discovery_sync,
)
from ..db import SessionLocal
from ..models import Asset, DiscoveryJob, DiscoveryResult, Organization
from ..tenancy import (
    SYSTEM_TENANT_MODE,
    get_session_org_id,
    set_system_session,
    set_tenant_session,
)

logger = logging.getLogger(__name__)

# Tope de hosts por job. Medido en produccion: con 128 de concurrencia cada tanda
# de 128 hosts tarda ~5.7s, asi que 8192 hosts quedan en ~6 min, por debajo del
# timeout de 10 min del frontend. Un /16 son 65534 hosts (~48 min reales), que
# sincronizado con el polling se terminaba abandonando.
MAX_TARGETS = 8192

# Jobs con cancelacion pedida. Vive en memoria (no como columna) porque el worker
# que lo consulta es el mismo proceso que la pide; la fila en la DB ya queda en
# 'cancelled', que es el estado que le importa al cliente.
_cancel_requested: set[str] = set()
_cancel_lock = threading.Lock()


class DiscoveryTargetTooLarge(ValueError):
    """El request expande a mas hosts de los que MAX_TARGETS permite."""

    def __init__(self, estimated: int) -> None:
        self.estimated = estimated
        super().__init__(
            f"Range too large: expands to about {estimated:,} hosts "
            f"(max {MAX_TARGETS:,}). Use a smaller CIDR, e.g. /19 or narrower."
        )

_PORT_NAMES = {
    443: ("https", "HTTPS"), 8443: ("https", "HTTPS"), 4443: ("https", "HTTPS"),
    8080: ("http", "HTTP"), 8000: ("http", "HTTP"), 80: ("http", "HTTP"),
    22: ("ssh", "SSH"), 5432: ("postgresql", "PostgreSQL"), 3306: ("mysql", "MySQL"),
    9200: ("elasticsearch", "Elasticsearch"), 6379: ("redis", "Redis"),
}


def create_job(db: Session, data: dict) -> DiscoveryJob:
    ip_range = data.get("ipRange", "") or ""
    domains = list(data.get("domains") or [])

    estimated = estimate_target_count(ip_range, domains)
    if estimated > MAX_TARGETS:
        raise DiscoveryTargetTooLarge(estimated)

    job = DiscoveryJob(
        cidr_or_targets=[ip_range],
        port_list=list(data.get("ports") or [443]),
        domains=domains,
        resolved_targets=data.get("resolvedTargets"),
        scan_internal=bool(data.get("scanInternal", False)),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def request_cancel(job_id: str, organization_id: int | None = None) -> bool:
    """Pide cancelar un job en vuelo. Devuelve False si ya estaba terminado."""
    db = SessionLocal()
    try:
        if organization_id is None:
            if db.info.get("tenant_mode") == SYSTEM_TENANT_MODE:
                stub = db.get(DiscoveryJob, job_id)
                if stub is None:
                    return False
                organization_id = stub.organization_id
            else:
                organization_id = get_session_org_id(db)
        set_tenant_session(db, organization_id)
        job = db.get(DiscoveryJob, job_id)
        if job is None or job.status not in ("queued", "running"):
            return False
        with _cancel_lock:
            _cancel_requested.add(job_id)
        job.status = "cancelled"
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("Discovery job %s cancelled by user", job_id)
        return True
    finally:
        db.close()


def _cancel_was_requested(job_id: str) -> bool:
    with _cancel_lock:
        return job_id in _cancel_requested


def _result_to_dto(
    r: DiscoveryResult,
    agent_id: str | None = None,
    site_label: str | None = None,
) -> dict:
    inventoried = r.inventory_status == "inventoried"
    return {
        "id": r.id,
        "ipAddress": r.ip_address,
        "hostname": r.hostname,
        "port": r.port,
        "service": r.service,
        "serviceName": r.service_name,
        "hasTls": r.has_tls,
        "tlsVersion": r.tls_version,
        "osFingerprint": r.os_fingerprint,
        "inventoried": inventoried,
        "shadowIt": not inventoried,
        "scope": r.scope,
        "firstSeen": r.first_seen.isoformat() if r.first_seen else "",
        "lastSeen": r.last_seen.isoformat() if r.last_seen else "",
        "agentId": agent_id,
        "siteLabel": site_label,
    }


def _match_asset(
    db: Session, ip: str, hostname: str | None, port: int
) -> Asset | None:
    """Busca el asset con la misma identidad (ip + puerto).

    La identidad incluye el puerto: el mismo host en puertos distintos son
    activos distintos. No se matchea por hostname solo, porque dos IPs distintas
    pueden resolver al mismo hostname.
    """
    if ip:
        return (
            db.query(Asset)
            .filter(Asset.ip_address == ip, Asset.port == port)
            .first()
        )
    if hostname:
        return (
            db.query(Asset)
            .filter(Asset.hostname == hostname, Asset.port == port)
            .first()
        )
    return None


def _upsert_result(db: Session, job: DiscoveryJob, svc: DiscoveredService) -> None:
    existing = (
        db.query(DiscoveryResult)
        .filter(
            DiscoveryResult.discovery_job_id == job.id,
            DiscoveryResult.ip_address == svc.ip_address,
            DiscoveryResult.port == svc.port,
        )
        .first()
    )
    asset = _match_asset(db, svc.ip_address, svc.hostname, svc.port)
    inventory_status = "inventoried" if asset else "shadow_it"
    matched_asset_id = asset.id if asset else None
    if asset is not None and svc.tls_version:
        asset.tls_version = svc.tls_version
    service, service_name = _PORT_NAMES.get(svc.port, (svc.service, svc.service_name))
    now = datetime.now(timezone.utc)

    if existing:
        existing.service = service or svc.service
        existing.service_name = service_name or svc.service_name
        existing.has_tls = svc.has_tls
        existing.tls_version = svc.tls_version
        existing.os_fingerprint = svc.os_fingerprint
        existing.inventory_status = inventory_status
        existing.matched_asset_id = matched_asset_id
        existing.scope = svc.scope
        existing.last_seen = now
        if not existing.hostname and svc.hostname:
            existing.hostname = svc.hostname
    else:
        db.add(DiscoveryResult(
            discovery_job_id=job.id,
            ip_address=svc.ip_address,
            hostname=svc.hostname,
            port=svc.port,
            service=service or svc.service,
            service_name=service_name or svc.service_name,
            has_tls=svc.has_tls,
            tls_version=svc.tls_version,
            os_fingerprint=svc.os_fingerprint,
            inventory_status=inventory_status,
            matched_asset_id=matched_asset_id,
            scope=svc.scope,
            first_seen=now,
            last_seen=now,
        ))
    db.flush()


def reap_orphaned_jobs() -> int:
    """Cierra como fallidos los jobs que quedaron 'queued'/'running' al reiniciar.

    Los jobs corren en daemon threads: si el proceso muere a mitad de un scan, el
    hilo se pierde con el y el job queda indefinidamente en 'running' (no hay nadie
    que lo termine nunca mas). Al arrancar de nuevo se marcan como fallidos para que
    no se acumulen estados zombis en la base.
    """
    system_db = SessionLocal()
    try:
        set_system_session(system_db)
        organization_ids = [
            row[0]
            for row in system_db.query(Organization.id).order_by(Organization.id).all()
        ]
    finally:
        system_db.close()

    total = 0
    for organization_id in organization_ids:
        db = SessionLocal()
        try:
            set_tenant_session(db, organization_id)
            stale = (
                db.query(DiscoveryJob)
                .filter(DiscoveryJob.status.in_(("queued", "running")))
                .all()
            )
            now = datetime.now(timezone.utc)
            for job in stale:
                job.status = "failed"
                job.error = "Interrupted by server restart"
                job.completed_at = now
            db.commit()
            total += len(stale)
        finally:
            db.close()
    if total:
        logger.info(
            "Reaped %d orphaned discovery job(s) across tenant scopes", total
        )
    return total


def run_job(job_id: str, organization_id: int | None = None) -> None:
    """Ejecuta un discovery job (corre en background tras la respuesta HTTP)."""
    db = SessionLocal()
    try:
        if organization_id is None:
            if db.info.get("tenant_mode") == SYSTEM_TENANT_MODE:
                stub = db.get(DiscoveryJob, job_id)
                if stub is None:
                    return
                organization_id = stub.organization_id
            else:
                organization_id = get_session_org_id(db)
        set_tenant_session(db, organization_id)
        job = db.get(DiscoveryJob, job_id)
        if job is None:
            return
        # El usuario puede cancelar entre que se crea el job y que arranca este
        # hilo (la fila todavia esta en 'queued'). Si se sigue, pisariamos el
        # 'cancelled' con 'running' y quedaria un zombie que nadie termina.
        if _cancel_was_requested(job_id) or job.status == "cancelled":
            logger.info("Discovery job %s was cancelled before it started", job_id)
            return
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        job.error = None
        db.commit()

        ip_range = (job.cidr_or_targets or [""])[0]
        ports = job.port_list or [443]
        is_cloud_job = job.agent_id is None
        resolved_targets = None
        if is_cloud_job:
            if not job.resolved_targets:
                raise ValueError("Cloud discovery job has no pinned targets")
            resolved_targets = [
                (str(target["ip"]), target.get("hostname"))
                for target in job.resolved_targets
            ]
            if any(not ip for ip, _hostname in resolved_targets):
                raise ValueError("Cloud discovery job has an invalid pinned target")
            targets = resolved_targets
        elif job.resolved_targets:
            resolved_targets = [
                (str(target["ip"]), target.get("hostname"))
                for target in job.resolved_targets
            ]
            if any(not ip for ip, _hostname in resolved_targets):
                raise ValueError("Discovery job has an invalid pinned target")
            targets = resolved_targets
        else:
            targets = parse_targets(ip_range, job.domains or [])
        total = len(targets)

        last_persisted = -1

        def _progress(done: int, total_: int) -> None:
            # El callback corre en el event loop: commitear en cada host bloquearia
            # el loop. Se persiste solo cuando el porcentaje cambia, lo que acota
            # los commits a uno por cada punto de porcentaje.
            nonlocal last_persisted
            percent = int((done / total_) * 100) if total_ else 100
            job.progress = percent
            if percent != last_persisted:
                last_persisted = percent
                db.commit()

        found = run_discovery_sync(
            ip_range=ip_range,
            domains=job.domains or [],
            ports=ports,
            scan_internal=job.scan_internal,
            timeout=1.5,
            progress_cb=_progress,
            cancel_check=lambda: _cancel_was_requested(job_id),
            resolved_targets=resolved_targets,
            enforce_public=is_cloud_job,
        )

        for svc in found:
            _upsert_result(db, job, svc)

        shadow = (
            db.query(DiscoveryResult)
            .filter(
                DiscoveryResult.discovery_job_id == job.id,
                DiscoveryResult.inventory_status == "shadow_it",
            )
            .count()
        )
        job.total_found = len(found)
        job.shadow_it_count = shadow
        job.progress = 100
        job.status = "completed"
        job.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("Discovery job %s completed: %d services", job_id, len(found))
    except DiscoveryCancelled:
        # Se fuerza 'cancelled' por si el scan llego a completarse justo cuando se
        # pidio la cancelacion: el resultado parcial se descarta igual.
        job = db.get(DiscoveryJob, job_id)
        if job is not None and job.status != "cancelled":
            job.status = "cancelled"
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
        logger.info("Discovery job %s stopped on user cancel", job_id)
    except Exception as exc:  # pragma: no cover - errores de red/escaneo
        logger.exception("Discovery job %s failed: %s", job_id, exc)
        job = db.get(DiscoveryJob, job_id)
        if job is not None:
            job.status = "failed"
            job.error = str(exc)[:500]
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        # Libera el marcador en memoria para que no crezca sin limite.
        with _cancel_lock:
            _cancel_requested.discard(job_id)
        db.close()


def get_job(db: Session, job_id: str) -> Optional[dict]:
    job = db.get(DiscoveryJob, job_id)
    if job is None:
        return None
    return {
        "id": job.id,
        "status": job.status,
        "progress": job.progress,
        "totalFound": job.total_found,
        "shadowItCount": job.shadow_it_count,
        "startedAt": job.started_at.isoformat() if job.started_at else None,
        "completedAt": job.completed_at.isoformat() if job.completed_at else None,
        "error": job.error,
    }


def get_job_results(
    db: Session, job_id: str, agent_id: str | None = None, site_label: str | None = None
) -> list[dict]:
    from ..models import Agent, DiscoveryJob

    q = db.query(DiscoveryResult).filter(DiscoveryResult.discovery_job_id == job_id)
    if agent_id or site_label:
        q = q.join(DiscoveryJob, DiscoveryJob.id == DiscoveryResult.discovery_job_id).join(
            Agent, Agent.id == DiscoveryJob.agent_id
        )
        if agent_id:
            q = q.filter(DiscoveryJob.agent_id == agent_id)
        if site_label:
            q = q.filter(Agent.site_label.ilike(f"%{site_label.strip()}%"))
    rows = q.order_by(DiscoveryResult.port, DiscoveryResult.ip_address).all()
    job = db.get(DiscoveryJob, job_id)
    agent = db.get(Agent, job.agent_id) if job and job.agent_id else None
    return [
        _result_to_dto(r, job.agent_id if job else None, agent.site_label if agent else None)
        for r in rows
    ]


def get_all_results(db: Session, agent_id: str | None = None, site_label: str | None = None) -> list[dict]:
    from ..models import Agent, DiscoveryJob

    q = (
        db.query(DiscoveryResult, DiscoveryJob.agent_id, Agent.site_label)
        .join(DiscoveryJob, DiscoveryJob.id == DiscoveryResult.discovery_job_id)
        .outerjoin(Agent, Agent.id == DiscoveryJob.agent_id)
    )
    if agent_id or site_label:
        if agent_id:
            q = q.filter(DiscoveryJob.agent_id == agent_id)
        if site_label:
            q = q.filter(Agent.site_label.ilike(f"%{site_label.strip()}%"))
    rows = q.order_by(DiscoveryResult.last_seen.desc()).all()
    return [_result_to_dto(r, row_agent_id, row_site_label) for r, row_agent_id, row_site_label in rows]


def summary(db: Session, agent_id: str | None = None, site_label: str | None = None) -> dict:
    from ..models import Agent, DiscoveryJob

    q = db.query(DiscoveryResult)
    if agent_id or site_label:
        q = q.join(DiscoveryJob, DiscoveryJob.id == DiscoveryResult.discovery_job_id).join(
            Agent, Agent.id == DiscoveryJob.agent_id
        )
        if agent_id:
            q = q.filter(DiscoveryJob.agent_id == agent_id)
        if site_label:
            q = q.filter(Agent.site_label.ilike(f"%{site_label.strip()}%"))
    results = q.all()
    inventoried = sum(1 for r in results if r.inventory_status == "inventoried")
    shadow = sum(1 for r in results if r.inventory_status == "shadow_it")
    with_tls = sum(1 for r in results if r.has_tls)
    internal = sum(1 for r in results if r.scope == "internal")
    external = sum(1 for r in results if r.scope == "external")
    return {
        "total": len(results),
        "inventoried": inventoried,
        "shadowIt": shadow,
        "withTls": with_tls,
        "internal": internal,
        "external": external,
    }
