from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from tls_analyzer import cli
from tls_analyzer.api import models
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.tenancy import set_system_session


def _run_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["tls-analyzer", *args])
    cli.main()


def test_operator_cli_create_disable_enable_and_purge_is_tenant_specific(
    monkeypatch, capsys, tmp_path
):
    suffix = uuid4().hex[:8]
    slug_a = f"operator-a-{suffix}"
    slug_b = f"operator-b-{suffix}"
    monkeypatch.setenv("OPERATOR_LOG_PATH", str(tmp_path / "operator.log"))

    _run_cli(
        monkeypatch,
        "create-org",
        "--name",
        f"Operator A {suffix}",
        "--admin-email",
        f"operator-a-{suffix}@example.com",
        "--slug",
        slug_a,
    )
    created_output = capsys.readouterr().out
    assert "Temporary password (shown once; change at first login):" in created_output
    _run_cli(monkeypatch, "list-orgs")
    assert slug_a in capsys.readouterr().out

    db = SessionLocal()
    set_system_session(db)
    try:
        org_a = db.query(models.Organization).filter_by(slug=slug_a).one()
        admin_a = db.query(models.User).filter_by(
            email=f"operator-a-{suffix}@example.com"
        ).one()
        org_b = models.Organization(
            name=f"Operator B {suffix}", slug=slug_b, status="active"
        )
        db.add(org_b)
        db.flush()
        service_a = models.Service(
            id=f"operator-service-a-{suffix}",
            host="same.example",
            port=443,
            organization_id=org_a.id,
        )
        service_b = models.Service(
            id=f"operator-service-b-{suffix}",
            host="same.example",
            port=443,
            organization_id=org_b.id,
        )
        db.add_all([service_a, service_b])
        db.flush()
        scan_b = models.Scan(
            id=f"operator-scan-b-{suffix}",
            service_id=service_b.id,
            host=service_b.host,
            port=443,
            organization_id=org_b.id,
        )
        db.add(scan_b)
        db.flush()
        finding_b = models.Finding(
            scan_id=scan_b.id, organization_id=org_b.id
        )
        db.add(finding_b)
        db.flush()
        scan_a = models.Scan(
            id=f"operator-scan-a-{suffix}",
            service_id=service_a.id,
            host=service_a.host,
            port=443,
            organization_id=org_a.id,
        )
        db.add(scan_a)
        db.flush()
        finding_a = models.Finding(
            scan_id=scan_a.id, organization_id=org_a.id
        )
        agent_key = models.ApiKey(
            name="operator purge agent key",
            key_hash=f"operator-agent-key-{suffix}",
            role="agent",
            organization_id=org_a.id,
        )
        user_key = models.ApiKey(
            name="operator purge user key",
            key_hash=f"operator-user-key-{suffix}",
            role="user",
            user_id=admin_a.id,
            organization_id=org_a.id,
        )
        team = models.Team(
            name=f"Operator purge team {suffix}",
            organization_id=org_a.id,
        )
        asset = models.Asset(
            ip_address="192.0.2.10",
            hostname=f"operator-{suffix}.example",
            organization_id=org_a.id,
        )
        certificate = models.Certificate(
            domain=f"operator-{suffix}.example",
            fingerprint_sha256=f"operator-fingerprint-{suffix}",
            organization_id=org_a.id,
        )
        issue = models.Issue(
            service_id=service_a.id,
            source_document="test",
            rule_id=f"operator-rule-{suffix}",
            organization_id=org_a.id,
        )
        alert = models.Alert(
            title="operator purge alert",
            organization_id=org_a.id,
        )
        recurring = models.RecurringScan(
            host=service_a.host,
            organization_id=org_a.id,
        )
        discovery = models.DiscoveryJob(
            cidr_or_targets=["192.0.2.0/24"],
            organization_id=org_a.id,
        )
        alert_threshold = models.AlertThreshold(organization_id=org_a.id)
        compliance_window = models.ComplianceWindow(
            name="operator purge window",
            organization_id=org_a.id,
        )
        integration = models.Integration(
            name="operator purge integration",
            organization_id=org_a.id,
        )
        audit_log = models.AuditLog(
            actor_user_id=admin_a.id,
            action="operator-purge-fixture",
            organization_id=org_a.id,
        )
        refresh_token = models.RefreshToken(
            user_id=admin_a.id,
            token_hash=f"operator-refresh-{suffix}",
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            organization_id=org_a.id,
        )
        db.add_all([
            finding_a,
            agent_key,
            user_key,
            team,
            asset,
            certificate,
            issue,
            alert,
            recurring,
            discovery,
            alert_threshold,
            compliance_window,
            integration,
            audit_log,
            refresh_token,
        ])
        db.flush()
        agent = models.Agent(
            name="operator purge agent",
            organization_id=org_a.id,
            api_key_id=agent_key.id,
        )
        db.add(agent)
        db.flush()
        team_member = models.TeamMember(
            team_id=team.id,
            user_id=admin_a.id,
            organization_id=org_a.id,
        )
        discovery_result = models.DiscoveryResult(
            discovery_job_id=discovery.id,
            ip_address="192.0.2.10",
            port=443,
            organization_id=org_a.id,
        )
        service_a.asset_id = asset.id
        service_a.certificate_id = certificate.id
        certificate.service_id = service_a.id
        scan_a.agent_id = agent.id
        asset.agent_id = agent.id
        service_a.agent_id = agent.id
        db.add_all([team_member, discovery_result])
        db.commit()
        org_a_id, org_b_id = org_a.id, org_b.id
        user_a_id, scan_a_id = admin_a.id, scan_a.id
        service_b_id, scan_b_id, finding_b_id = (
            service_b.id, scan_b.id, finding_b.id
        )
    finally:
        db.close()

    _run_cli(monkeypatch, "disable-org", "--slug", slug_a)
    db = SessionLocal()
    set_system_session(db)
    try:
        assert db.get(models.Organization, org_a_id).status == "disabled"
        assert db.get(models.Organization, org_b_id).status == "active"
    finally:
        db.close()

    _run_cli(monkeypatch, "enable-org", "--slug", slug_a)
    db = SessionLocal()
    set_system_session(db)
    try:
        assert db.get(models.Organization, org_a_id).status == "active"
    finally:
        db.close()

    monkeypatch.setattr("builtins.input", lambda _: "wrong-slug")
    with pytest.raises(SystemExit, match="Confirmation did not match"):
        _run_cli(monkeypatch, "delete-org", "--slug", slug_a, "--purge")
    db = SessionLocal()
    set_system_session(db)
    try:
        assert db.get(models.Organization, org_a_id) is not None
        assert db.get(models.Scan, scan_a_id) is not None
    finally:
        db.close()

    monkeypatch.setattr("builtins.input", lambda _: slug_a)
    _run_cli(monkeypatch, "delete-org", "--slug", slug_a, "--purge")
    db = SessionLocal()
    set_system_session(db)
    try:
        assert db.get(models.Organization, org_a_id) is None
        assert db.get(models.User, user_a_id) is None
        assert db.get(models.Scan, scan_a_id) is None
        for model in (
            models.Asset,
            models.Certificate,
            models.Finding,
            models.Team,
            models.TeamMember,
            models.Issue,
            models.IssueHistory,
            models.Agent,
            models.ApiKey,
            models.Alert,
            models.RecurringScan,
            models.DiscoveryJob,
            models.DiscoveryResult,
            models.Integration,
            models.AlertThreshold,
            models.ComplianceWindow,
            models.AuditLog,
            models.RefreshToken,
        ):
            assert db.query(model).filter(
                model.organization_id == org_a_id
            ).count() == 0, model.__tablename__
        assert db.get(models.Finding, finding_b_id) is not None
        assert db.get(models.Scan, scan_b_id) is not None
        assert db.get(models.Service, service_b_id) is not None
        assert db.get(models.Organization, org_b_id) is not None
    finally:
        db.close()

    operator_log = (tmp_path / "operator.log").read_text(encoding="utf-8")
    assert f'"organization_slug": "{slug_a}"' in operator_log
    assert "Temporary password" not in operator_log

    cleanup = SessionLocal()
    set_system_session(cleanup)
    try:
        cleanup.query(models.Finding).filter(
            models.Finding.id == finding_b_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Scan).filter(
            models.Scan.id == scan_b_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Service).filter(
            models.Service.id == service_b_id
        ).delete(synchronize_session=False)
        cleanup.query(models.Organization).filter(
            models.Organization.id == org_b_id
        ).delete(synchronize_session=False)
        cleanup.commit()
    finally:
        cleanup.close()
