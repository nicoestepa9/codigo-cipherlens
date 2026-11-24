"""El dashboard debe filtrar findings y alertas por agente/sitio sin AttributeError."""

from __future__ import annotations

from uuid import uuid4

from tls_analyzer.api import models
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.services.dashboard_service import dashboard_summary
from tls_analyzer.api.tenancy import set_system_session, set_tenant_session


def test_dashboard_filters_agent_data_through_scan_service():
    suffix = uuid4().hex[:8]
    db = SessionLocal()
    set_system_session(db)
    try:
        org = models.Organization(
            name=f"Dash {suffix}", slug=f"dash-{suffix}", status="active"
        )
        db.add(org)
        db.commit()
        db.refresh(org)

        agents = [
            models.Agent(
                name=f"agent-{index}-{suffix}",
                site_label="Sitio Norte" if index == 1 else "Sitio Sur",
                status="active",
                organization_id=org.id,
            )
            for index in (1, 2)
        ]
        db.add_all(agents)
        db.commit()

        services = [
            models.Service(
                host=f"host-{index}-{suffix}",
                port=443,
                agent_id=agent.id,
                organization_id=org.id,
            )
            for index, agent in enumerate(agents, start=1)
        ]
        scans = [
            models.Scan(
                service_id=service.id,
                host=service.host,
                port=443,
                agent_id=service.agent_id,
                organization_id=org.id,
            )
            for service in services
        ]
        db.add_all(services)
        db.commit()
        db.add_all(scans)
        db.commit()

        findings = [
            models.Finding(
                scan_id=scans[0].id,
                rule_id="CERT-01",
                title="Expirado",
                severity="critical",
                organization_id=org.id,
            ),
            models.Finding(
                scan_id=scans[1].id,
                rule_id="CERT-07",
                title="Sin SAN",
                severity="high",
                organization_id=org.id,
            ),
        ]
        certificate = models.Certificate(
            service_id=services[0].id,
            domain=services[0].host,
            status="expiring_soon",
            organization_id=org.id,
        )
        issue = models.Issue(
            service_id=services[0].id,
            rule_id="CERT-01",
            title="Expirado",
            severity="critical",
            organization_id=org.id,
        )
        db.add_all(findings)
        db.add(certificate)
        db.add(issue)
        db.commit()

        alerts = [
            models.Alert(
                type="vulnerability",
                severity="critical",
                title="Finding",
                related_scan_id=scans[0].id,
                related_target=services[0].host,
                organization_id=org.id,
            ),
            models.Alert(
                type="expiration",
                severity="high",
                title="Certificado",
                related_certificate_id=certificate.id,
                organization_id=org.id,
            ),
            models.Alert(
                type="agent_offline",
                severity="high",
                title="Agente",
                related_target=agents[0].id,
                organization_id=org.id,
            ),
            models.Alert(
                type="vulnerability",
                severity="high",
                title="Issue",
                related_issue_id=issue.id,
                organization_id=org.id,
            ),
        ]
        db.add_all(alerts)
        db.commit()
        agent_ids = [agent.id for agent in agents]
        org_id = org.id
    finally:
        db.close()

    db = SessionLocal()
    set_tenant_session(db, org_id)
    try:
        first = dashboard_summary(db, agent_id=agent_ids[0])
        second = dashboard_summary(db, agent_id=agent_ids[1])
        by_site = dashboard_summary(db, site_label="norte")
    finally:
        db.close()

    assert first["totalServices"] == 1
    assert first["criticalVulnerabilities"] == 1
    assert first["highVulnerabilities"] == 0
    assert first["unreadAlerts"] == 4
    assert first["certificatesExpiringSoon"] == 1

    assert second["totalServices"] == 1
    assert second["criticalVulnerabilities"] == 0
    assert second["highVulnerabilities"] == 1
    assert second["unreadAlerts"] == 0
    assert second["certificatesExpiringSoon"] == 0

    assert by_site["totalServices"] == 1
    assert by_site["unreadAlerts"] == 4
    assert by_site["criticalVulnerabilities"] == 1

    cleanup = SessionLocal()
    set_system_session(cleanup)
    try:
        cleanup.query(models.Alert).filter(
            models.Alert.organization_id == org_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Finding).filter(
            models.Finding.organization_id == org_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Certificate).filter(
            models.Certificate.organization_id == org_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Issue).filter(
            models.Issue.organization_id == org_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Scan).filter(
            models.Scan.organization_id == org_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Service).filter(
            models.Service.organization_id == org_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Agent).filter(
            models.Agent.organization_id == org_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Organization).filter(
            models.Organization.id == org_id
        ).delete(synchronize_session=False)
        cleanup.commit()
    finally:
        cleanup.close()
