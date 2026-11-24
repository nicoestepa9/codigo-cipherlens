"""Servicio de scans: orquesta el motor, persiste y alimenta el inventario."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from ... import analysis
from ... import cve_mapping
from ...ai_recommendations import generate_recommendation as _generate_recommendation
from ...cloud_network import PinnedTarget
try:
    from ... import serializers
except Exception:  # pragma: no cover
    serializers = None
from ...alerts_engine import generate_scan_alerts
from ...discovery import is_internal_ip
from ...scanner import ScanResult as EngineScanResult
from ..config import settings
from ..models import Agent, Asset, Certificate, Finding, Organization, Scan, Service
from ..tenancy import get_session_org_id
from . import cve_service
from . import issue_service


def _get_default_org_id(db: Session) -> int:
    org_id = get_session_org_id(db)
    if org_id is None:
        raise RuntimeError("System scan persistence requires an explicit tenant session")
    return int(org_id)


def generate_tenant_recommendation(
    db: Session, score: int, findings: list[dict], host: str
) -> tuple[str, str]:
    """Generate AI text under the current tenant's explicit egress policy."""
    organization_id = get_session_org_id(db)
    organization = (
        db.get(Organization, organization_id) if organization_id is not None else None
    )
    mode = getattr(organization, "ai_mode", "template")
    if mode not in {"external", "template"}:
        mode = "template"
    return _generate_recommendation(
        score,
        findings,
        host,
        ai_mode=mode,
    )


def _as_analysis(result) -> analysis.AnalysisResult:
    """Acepta un AnalysisResult o un ScanResult del motor (compatibilidad)."""
    if isinstance(result, analysis.AnalysisResult):
        return result
    engine: EngineScanResult = result
    h = engine.handshake.to_dict() if engine.handshake else {}
    leaf = engine.certificate_chain[0].to_dict() if engine.certificate_chain else {}
    findings_dtos = [
        serializers.finding_dto(f.to_dict(), engine.host, "")
        for f in engine.findings
    ]
    connection_error = h.get("connection_error")
    return analysis.AnalysisResult(
        host=engine.host,
        port=engine.port,
        profile=engine.profile,
        score=engine.score,
        status="failed" if connection_error else "completed",
        started_at=datetime.now(timezone.utc).isoformat(),
        connection_error=connection_error,
        ip_address=h.get("ip_address", ""),
        negotiated_protocol=h.get("negotiated_protocol", ""),
        negotiated_cipher=h.get("negotiated_cipher", ""),
        supported_protocols=h.get("supported_protocols", []),
        findings=findings_dtos,
        certificate=serializers.certificate_dto(leaf, engine.host) if leaf else serializers.empty_certificate_dto(),
        chain=[serializers.certificate_dto(c.to_dict(), engine.host) for c in engine.certificate_chain],
        handshake=h,
        raw_result=engine.to_dict(),
        _fingerprint=None,
    )


def persist_scan(
    db: Session,
    result,
    *,
    origin: str = "manual",
    recurring_scan_id: int | None = None,
    agent_id: str | None = None,
    client_scan_id: str | None = None,
    task_id: str | None = None,
    ai_text: str = "",
    profile_override: str | None = None,
    upload_level: str | None = None,
    rules_version: str | None = None,
) -> Scan:
    """Persiste un AnalysisResult (o un ScanResult del motor) y enlaza inventario.

    Idempotente respecto de ``(agent_id, client_scan_id)``: si ya existe un scan
    con ese par, se devuelve el existente sin recrear efectos.
    """
    ar = _as_analysis(result)

    if task_id is not None:
        existing = db.query(Scan).filter(Scan.task_id == task_id).first()
        if existing is not None:
            return existing
    if agent_id is not None and client_scan_id is not None:
        existing = (
            db.query(Scan)
            .filter(Scan.agent_id == agent_id, Scan.client_scan_id == client_scan_id)
            .first()
        )
        if existing is not None:
            return existing

    if ar.started_at:
        try:
            started_at = datetime.fromisoformat(ar.started_at)
        except ValueError:
            started_at = datetime.now(timezone.utc)
    else:
        started_at = datetime.now(timezone.utc)

    raw = ar.raw_result or {}
    org_id = _get_default_org_id(db)
    if agent_id:
        agent = db.get(Agent, agent_id)
        if agent is None:
            raise ValueError("Agent is not part of the current organization")
        org_id = agent.organization_id
    scan_row = Scan(
        host=ar.host,
        port=ar.port,
        port_is_alternate=ar.port_is_alternate,
        target=f"{ar.host}:{ar.port}",
        status=ar.status,
        score=ar.score,
        profile=profile_override or ar.profile,
        started_at=started_at,
        duration_ms=ar.duration_ms,
        ai_recommendation=ai_text,
        connection_error=ar.connection_error,
        raw_result=raw,
        origin=origin,
        recurring_scan_id=recurring_scan_id,
        agent_id=agent_id,
        client_scan_id=client_scan_id,
        task_id=task_id,
        upload_level=upload_level,
        rules_version=rules_version,
        organization_id=org_id,
    )
    db.add(scan_row)
    db.flush()

    # Enlazar el inventario SIEMPRE: todo Scan persistido queda ligado a su
    # Service (agent, host, port), incluso cuando el handshake fallo. Asi los
    # scans manuales, programados, de discovery y de agente no quedan con
    # service_id NULL.
    scan_row.organization_id = org_id
    service = upsert_inventory(
        db, ar, host=ar.host, port=ar.port, started_at=started_at, agent_id=agent_id
    )
    if service.organization_id != org_id:
        raise ValueError("Inventory service organization does not match scan")
    scan_row.service_id = service.id

    for f in ar.findings:
        db.add(Finding(
            scan_id=scan_row.id,
            rule_id=f["ruleId"],
            title=f["title"],
            description=f["description"],
            evidence=f["evidence"],
            recommendation=f["recommendation"],
            section_reference=f["sectionReference"],
            citation=f["citation"],
            severity=f["severity"],
            category=f["category"],
            affected_host=f["affectedHost"],
            source_document=f.get("sourceDocument") or "",
            evaluable=f.get("evaluable", True),
            status=f.get("status"),
        ))

    # Reconciliar Issues (Parte 2) solo para scans COMPLETADOS.
    if not ar.connection_error and scan_row.status == "completed":
        cert_fp = None
        if ar.chain:
            cert_fp = ar.chain[0].get("fingerprintSha256") or ar.chain[0].get("id") or None
        issue_service.reconcile_scan(db, scan_row, ar.findings, certificate_fingerprint=cert_fp)

    db.commit()
    db.refresh(scan_row)
    return scan_row


def upsert_inventory(
    db: Session,
    result,
    *,
    host: str,
    port: int,
    started_at: datetime,
    agent_id: str | None = None,
) -> Service:
    """Upsert de Asset/Service/Certificate para poblar el inventario.

    Devuelve el ``Service`` creado/actualizado (para poder linkear
    ``Scan.service_id`` al resultado de la corrida).
    """
    ar = _as_analysis(result)
    h = ar.handshake or {}
    ip = ar.ip_address or h.get("ip_address", "") or ""

    org_id = _get_default_org_id(db)
    asset = None
    if ip or host:
        asset_q = db.query(Asset).filter(Asset.port == port)
        if ip:
            asset_q = asset_q.filter(Asset.ip_address == ip)
        else:
            asset_q = asset_q.filter(Asset.hostname == host)
        if agent_id is not None:
            asset_q = asset_q.filter(Asset.agent_id == agent_id)
        asset = asset_q.first()
    if asset is None:
        asset = Asset(
            ip_address=ip,
            hostname=host,
            port=port,
            is_internal=is_internal_ip(ip) if ip else False,
            agent_id=agent_id,
            organization_id=org_id,
        )
        db.add(asset)
        db.flush()
    if not getattr(asset, "organization_id", None):
        asset.organization_id = org_id
    asset.last_seen = started_at

    service_q = db.query(Service).filter(Service.host == host, Service.port == port)
    if agent_id is not None:
        service_q = service_q.filter(Service.agent_id == agent_id)
    service = service_q.first()
    if service is None:
        service = Service(
            host=host,
            port=port,
            asset_id=asset.id,
            ip_address=ip,
            name=f"{host}:{port}",
            scope="internal" if is_internal_ip(ip) else "external",
            agent_id=agent_id,
            organization_id=org_id,
        )
        db.add(service)
        db.flush()
    if not getattr(service, "organization_id", None):
        service.organization_id = org_id
    db.flush()
    service.ip_address = ip
    service.asset_id = asset.id
    service.tls_enabled = bool(h) and not h.get("connection_error")
    service.tls_version = h.get("negotiated_protocol", "")
    service.cipher_suite = h.get("negotiated_cipher", "")
    service.security_status = serializers.score_to_status(ar.score)
    service.vulnerability_count = sum(
        1 for f in ar.findings if f.get("severity") in ("critical", "high")
    )
    service.last_seen = started_at
    if service.tls_version:
        asset.tls_version = service.tls_version

    cert_dto = ar.certificate or {}
    if ar.chain or cert_dto.get("fingerprintSha256"):
        cert_dto = ar.certificate or (ar.chain[0] if ar.chain else {})
        fp_sha256 = cert_dto.get("fingerprintSha256") or cert_dto.get("id") or ""
        if fp_sha256:
            cert = (
                db.query(Certificate)
                .filter(Certificate.fingerprint_sha256 == fp_sha256)
                .first()
            )
            if cert is None:
                cert = Certificate(
                    fingerprint_sha256=fp_sha256,
                    origin="discovered",
                    organization_id=getattr(service, "organization_id", None) or org_id,
                )
                db.add(cert)
            if not getattr(cert, "organization_id", None):
                cert.organization_id = getattr(service, "organization_id", None) or org_id
            cert.service_id = service.id
            cert.domain = cert_dto.get("domain", "")
            cert.subject_cn = (cert_dto.get("subject") or {}).get("CN", "")
            cert.issuer_cn = (cert_dto.get("issuer") or {}).get("CN", "")
            cert.serial_number = cert_dto.get("serialNumber", "")
            cert.not_before = cert_dto.get("notBefore", "")
            cert.not_after = cert_dto.get("notAfter", "")
            cert.days_until_expiry = cert_dto.get("daysUntilExpiry", 0)
            cert.is_expired = cert_dto.get("isExpired", False)
            cert.status = cert_dto.get("status", "valid")
            cert.key_type = cert_dto.get("keyType", "")
            cert.key_size = cert_dto.get("keySize", 0)
            cert.signature_algorithm = cert_dto.get("signatureAlgorithm", "")
            cert.fingerprint_sha1 = cert_dto.get("fingerprintSha1", "")
            cert.is_self_signed = cert_dto.get("isSelfSigned", False)
            cert.san = cert_dto.get("san") or []
            cert.subject = cert_dto.get("subject") or {}
            cert.issuer = cert_dto.get("issuer") or {}
            cert.basic_constraints = cert_dto.get("basicConstraints", "")
            cert.key_usage = cert_dto.get("keyUsage") or []
            cert.extended_key_usage = cert_dto.get("extendedKeyUsage") or []
            cert.ca_issuers = cert_dto.get("caIssuers") or []
            cert.crl_distribution_points = cert_dto.get("crlDistributionPoints") or []
            cert.ocsp_must_staple = cert_dto.get("ocspMustStaple", False)

    return service


def run_scan(
    db: Session,
    target: str,
    port: int | None = None,
    options: Optional[dict] = None,
    *,
    origin: str = "manual",
    recurring_scan_id: int | None = None,
    pinned_target: PinnedTarget | None = None,
):
    """Analiza un target (puro) y aplica los efectos de la plataforma."""
    opts = dict(options or {})
    if not opts.get("timeout"):
        opts["timeout"] = settings.default_timeout

    ar = analysis.analyze_target(
        target,
        opts,
        port=port,
        pinned_target=pinned_target,
    )
    target_label = f"{ar.host}:{ar.port}"

    if ar.connection_error:
        scan_row = persist_scan(db, ar, origin=origin, recurring_scan_id=recurring_scan_id)
        return serializers.scan_dto_from_analysis(
            ar, scan_id=scan_row.id, target=target_label,
            scan_started_at=ar.started_at, scan_duration_ms=ar.duration_ms,
            port_is_alternate=ar.port_is_alternate,
        )

    findings_dtos = ar.findings
    static_cves = cve_service.get_static_cves_for_findings(findings_dtos, db)
    nvd_keywords = cve_service.build_nvd_keywords(findings_dtos)

    ai_text, _source = generate_tenant_recommendation(
        db, ar.score, findings_dtos, ar.host
    )

    from ...fingerprint import ServiceFingerprint
    fp = ar._fingerprint or ServiceFingerprint(detected=False)
    keyword_matches, cpe_matches, cpe_name_used = cve_service.get_or_query_live_cves(db, fp, nvd_keywords)
    all_live_matches = keyword_matches + cpe_matches

    scan_row = persist_scan(
        db, ar, origin=origin, recurring_scan_id=recurring_scan_id, ai_text=ai_text,
    )
    generate_scan_alerts(db, scan_row, findings_dtos)
    cve_service.persist_scan_cve_matches(db, scan_row.id, static_cves, all_live_matches)
    db.commit()

    return serializers.scan_dto_from_analysis(
        ar, scan_id=scan_row.id, target=target_label,
        scan_started_at=ar.started_at, scan_duration_ms=ar.duration_ms,
        ai_recommendation=ai_text, port_is_alternate=ar.port_is_alternate,
        fingerprint_dto=ar.os_fingerprint, keyword_matches=keyword_matches,
        cpe_matches=cpe_matches, cpe_name_used=cpe_name_used,
    )


def ingest_scan_result(
    db: Session,
    ar: analysis.AnalysisResult,
    *,
    agent_id: str,
    client_scan_id: str,
    task_id: str | None = None,
    recurring_scan_id: int | None = None,
    upload_level: str = "standard",
    rules_version: str = "",
) -> tuple[Scan, bool]:
    """Aplica los efectos de plataforma a un scan YA calculado por un agente.

    Misma ruta que ``run_scan`` (persistencia, inventario con ``agent_id``,
    reconciliacion de issues, alertas, CVEs e IA) pero sin ejecutar el analisis.
    Idempotente por ``(agent_id, client_scan_id)``: un reintento devuelve el scan
    existente sin recrear efectos. Devuelve ``(scan, created)``.
    """
    existing = db.query(Scan).filter(Scan.task_id == task_id).first() if task_id else None
    if existing is None:
        existing = (
            db.query(Scan)
            .filter(Scan.agent_id == agent_id, Scan.client_scan_id == client_scan_id)
            .first()
        )
        if task_id and existing is not None and existing.task_id != task_id:
            raise ValueError("clientScanId already belongs to another task")
    if existing is not None:
        return existing, False

    # El score/findings del agente son datos de inventario: no se confia en ellos
    # para decisiones de seguridad, solo se persisten.
    findings_dtos = ar.findings
    ai_text = ""
    static_cves: list = []
    keyword_matches: list = []
    cpe_matches: list = []
    if not ar.connection_error and ar.status == "completed":
        static_cves = cve_service.get_static_cves_for_findings(findings_dtos, db)
        nvd_keywords = cve_service.build_nvd_keywords(findings_dtos)
        ai_text, _source = generate_tenant_recommendation(
            db, ar.score, findings_dtos, ar.host
        )
        from ...fingerprint import ServiceFingerprint

        fp = ar._fingerprint or ServiceFingerprint(detected=False)
        keyword_matches, cpe_matches, _cpe_name = cve_service.get_or_query_live_cves(
            db, fp, nvd_keywords
        )

    scan_row = persist_scan(
        db,
        ar,
        origin="agent",
        recurring_scan_id=recurring_scan_id,
        agent_id=agent_id,
        client_scan_id=client_scan_id,
        task_id=task_id,
        ai_text=ai_text,
        upload_level=upload_level,
        rules_version=rules_version,
    )
    try:
        if not ar.connection_error and scan_row.status == "completed":
            try:
                generate_scan_alerts(db, scan_row, findings_dtos)
            except Exception:
                db.rollback()
            try:
                cve_service.persist_scan_cve_matches(
                    db, scan_row.id, static_cves, keyword_matches + cpe_matches
                )
            except Exception:
                db.rollback()
    except Exception:
        pass
    try:
        db.commit()
    except Exception:
        db.rollback()
    return scan_row, True


def get_scan_result_dto(db: Session, scan_id: str) -> Optional[dict]:
    """Reconstruye el DTO desde un Scan persistido."""
    row = db.get(Scan, scan_id)
    if row is None:
        return None
    from ..models import Agent

    agent = db.get(Agent, row.agent_id) if row.agent_id else None
    raw = row.raw_result or {}

    # Reconstruir fingerprint desde raw_result si esta disponible
    fp_data = raw.get("fingerprint")
    if fp_data:
        from ...fingerprint import ServiceFingerprint
        fp = ServiceFingerprint(
            detected=fp_data.get("detected", False),
            method=fp_data.get("method"),
            software_name=fp_data.get("software_name"),
            software_version=fp_data.get("software_version"),
            os_family=fp_data.get("os_family"),
            confidence=fp_data.get("confidence", "low"),
            raw_banner=fp_data.get("raw_banner"),
            ja3_hash=fp_data.get("ja3_hash"),
            ja3s_hash=fp_data.get("ja3s_hash"),
        )
        fp_dto = fp.to_frontend_dto()
    else:
        fp_dto = {
            "detected": False, "os": None, "service": None, "banner": None,
            "confidence": None,
            "note": "OS/service fingerprinting is not available in this stage.",
        }

    # Reconstruir CVEs desde ScanCveMatch, separados por tipo
    all_cve_matches = cve_service.get_scan_cve_matches(db, scan_id)
    keyword_matches = [m for m in all_cve_matches if m["matchType"] != "cpe"]
    cpe_matches = [m for m in all_cve_matches if m["matchType"] == "cpe"]
    cpe_name_used = None
    if cpe_matches:
        # Intentar reconstruir CPE name desde fingerprint
        if fp_data:
            from ...cpe_mapping import software_name_to_cpe
            cpe_name_used = software_name_to_cpe(
                fp_data.get("software_name"), fp_data.get("software_version")
            )

    return {
        "id": row.id,
        "target": row.target,
        "host": row.host,
        "port": row.port,
        "portIsAlternate": row.port_is_alternate,
        "ipAddress": (raw.get("handshake") or {}).get("ip_address", ""),
        "scanStartedAt": row.started_at.isoformat(),
        "scanDurationMs": row.duration_ms or 0,
        "profile": row.profile,
        "score": row.score or 0,
        "status": "failed" if row.status == "failed" else serializers.score_to_status(row.score or 0),
        "negotiatedProtocol": (raw.get("handshake") or {}).get("negotiated_protocol", ""),
        "negotiatedCipher": (raw.get("handshake") or {}).get("negotiated_cipher", ""),
        "keyExchange": serializers.derive_key_exchange(raw.get("handshake") or {}),
        "signatureAlgorithm": (
            (raw.get("certificate") or {}).get("signatureAlgorithm")
            or ((raw.get("certificate_chain") or [{}])[0]).get("signatureAlgorithm", "")
        ),
        "supportedProtocols": (raw.get("handshake") or {}).get("supported_protocols", []),
        "cipherSuites": serializers.cipher_suites_dto(
            raw.get("handshake") or {}, (raw.get("handshake") or {}).get("negotiated_cipher", "")
        ),
        "certificate": serializers.certificate_dto(
            (raw.get("certificate_chain") or [{}])[0], row.host
        ) if raw.get("certificate_chain") else serializers.empty_certificate_dto(),
        "chain": [
            serializers.certificate_dto(c, row.host)
            for c in raw.get("certificate_chain", [])
        ],
        "findings": [
            {
                "id": f.id,
                "ruleId": f.rule_id,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "reference": f.section_reference or None,
                "severity": f.severity,
                "category": f.category,
                "affectedHost": f.affected_host,
                "affectedService": None,
                "detectionDate": f.detection_date.isoformat() if f.detection_date else "",
                "citation": f.citation,
                "observedValue": f.evidence,
                "sectionReference": f.section_reference,
                "sourceDocument": f.source_document or None,
                "standards": [],
                "ruleIds": [f.rule_id],
                "evaluable": f.evaluable,
                "status": f.status,
                "relatedCves": [
                    {"cveId": e.cve_id, "name": e.name, "matchType": "static_mapping",
                     "referenceUrl": f"https://nvd.nist.gov/vuln/detail/{e.cve_id}"}
                    for e in cve_mapping.get_static_cves_for_rule(f.rule_id)
                ],
            }
            for f in row.findings
        ],
        "osFingerprint": fp_dto,
        "handshakeSteps": [],
        "aiRecommendation": row.ai_recommendation or "",
        "connectionError": row.connection_error,
        "liveCveMatches": keyword_matches,
        "softwareKnownCves": {
            "queried": cpe_name_used is not None,
            "cpeName": cpe_name_used,
            "matches": cpe_matches,
        },
        "agentId": row.agent_id,
        "siteLabel": agent.site_label if agent else None,
    }


def list_scans(
    db: Session,
    page: int = 1,
    page_size: int = 20,
    search: str | None = None,
    agent_id: str | None = None,
    site_label: str | None = None,
):
    from ..models import Agent, Service

    q = db.query(Scan)
    if search:
        q = q.filter(or_(Scan.host.ilike(f"%{search}%"), Scan.target.ilike(f"%{search}%")))
    if agent_id:
        q = q.filter(Scan.agent_id == agent_id)
    if site_label:
        q = (
            q.join(Service, Service.id == Scan.service_id, isouter=True)
            .join(Agent, Agent.id == Scan.agent_id, isouter=True)
            .filter(
                or_(
                    Agent.site_label.ilike(f"%{site_label.strip()}%"),
                    (Agent.id.is_(None)) & False,
                )
            )
        )
        if site_label.strip():
            q = (
                db.query(Scan)
                .filter(
                    or_(
                        Scan.agent_id.is_(None),
                        Scan.agent_id.in_(
                            db.query(Agent.id).filter(
                                Agent.site_label.ilike(f"%{site_label.strip()}%")
                            )
                        ),
                    )
                )
            )
            if search:
                q = q.filter(or_(Scan.host.ilike(f"%{search}%"), Scan.target.ilike(f"%{search}%")))
    total = q.count()
    rows = q.order_by(Scan.started_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    from ..models import Agent

    items = []
    for scan in rows:
        svc = scan.service
        agent = db.get(Agent, scan.agent_id) if scan.agent_id else None
        items.append({
            "id": scan.id,
            "target": scan.target or (f"{scan.host}:{scan.port}" if scan.host else ""),
            "host": scan.host,
            "port": scan.port,
            "status": scan.status,
            "score": scan.score or 0,
            "date": scan.started_at.isoformat() if scan.started_at else "",
            "startedAt": scan.started_at.isoformat() if scan.started_at else None,
            "durationMs": scan.duration_ms,
            "origin": scan.origin or ("agent" if scan.agent_id else "platform"),
            "agentId": scan.agent_id,
            "siteLabel": (agent.site_label if agent else None) or (getattr(svc, "site_label", None) if svc else None),
        })
    return items, total
