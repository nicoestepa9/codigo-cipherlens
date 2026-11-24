"""Tests de agentes on-premise (Parte 5): gestion, ingesta, permisos y alcance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tls_analyzer import analysis
from tls_analyzer.alerts_engine import generate_agent_offline_alerts
from tls_analyzer.api.config import settings
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.deps import generate_api_key, hash_api_key
from tls_analyzer.api.main import app
from tls_analyzer.api.models import (
    Agent,
    Alert,
    AuditLog,
    ApiKey,
    Asset,
    Certificate,
    DiscoveryJob,
    DiscoveryResult,
    Finding,
    Issue,
    IssueHistory,
    Organization,
    Scan,
    ScanCveMatch,
    Service,
)
from tls_analyzer.api.services import agent_service
from tls_analyzer.api.tenancy import set_system_session


def _cleanup():
    db = SessionLocal()
    try:
        for model in (
            DiscoveryResult, DiscoveryJob, Finding, IssueHistory, Issue, Alert,
            AuditLog, ScanCveMatch, Scan, Certificate, Service, Asset, Agent,
            ApiKey,
        ):
            db.query(model).delete()
        db.commit()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _isolated_db():
    _cleanup()
    yield
    _cleanup()


def _make_agent(name: str = "site-a", site: str = "Site A"):
    db = SessionLocal()
    try:
        dto, plain = agent_service.create_agent(db, name, site, actor_user_id=None)
        return dto["id"], plain
    finally:
        db.close()


def _headers(key: str) -> dict[str, str]:
    return {"X-API-Key": key}


def _user_key(role: str = "user") -> str:
    db = SessionLocal()
    try:
        plain = generate_api_key()
        db.add(ApiKey(name="test-key", key_hash=hash_api_key(plain), prefix=plain[:8] + "...", role=role))
        db.commit()
        return plain
    finally:
        db.close()


def _scan_data(client_scan_id: str = "client-scan-0001", host: str = "intranet.corp.local") -> dict:
    return {
        "schemaVersion": analysis.SCHEMA_VERSION,
        "rulesVersion": analysis.RULES_VERSION,
        "clientScanId": client_scan_id,
        "uploadLevel": "standard",
        "target": {"host": host, "port": 443, "profile": "government-only"},
        "status": "completed",
        "score": 70,
        "durationMs": 123,
        "ipAddress": "10.0.0.5",
        "negotiatedProtocol": "TLSv1.2",
        "negotiatedCipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "findings": [
            {
                "ruleId": "PROTO-01",
                "title": "Weak protocol",
                "description": "d",
                "evidence": "e",
                "recommendation": "r",
                "sectionReference": "s",
                "citation": "c",
                "severity": "high",
                "category": "protocol",
                "affectedHost": "intranet.corp.local",
                "sourceDocument": "80052",
                "evaluable": True,
            }
        ],
        "certificate": {},
        "chain": [],
        "handshake": {},
        "osFingerprint": {},
        "rawResult": {},
    }


def test_create_and_list_agent():
    _cleanup()
    db = SessionLocal()
    try:
        dto, plain = agent_service.create_agent(db, "sede", "Sede Central", actor_user_id=None)
        assert plain.startswith("cg_")
        assert dto["status"] == "active"
        listed = agent_service.list_agents(db)
        assert len(listed) == 1
        assert listed[0]["siteLabel"] == "Sede Central"
    finally:
        db.close()


def test_lead_can_list_and_read_agents_but_cannot_manage_them():
    agent_id, _ = _make_agent()
    headers = _headers(_user_key("lead"))
    with TestClient(app) as client:
        listed = client.get("/api/agents", headers=headers)
        assert listed.status_code == 200, listed.text
        assert [row["id"] for row in listed.json()] == [agent_id]

        detail = client.get(f"/api/agents/{agent_id}", headers=headers)
        assert detail.status_code == 200, detail.text

        created = client.post(
            "/api/agents",
            headers=headers,
            json={"name": "lead-agent", "siteLabel": "Site B"},
        )
        assert created.status_code == 403

        revoked = client.delete(f"/api/agents/{agent_id}", headers=headers)
        assert revoked.status_code == 403


def test_agent_quota_returns_conflict_and_records_audit():
    from tls_analyzer.api.models import Organization

    db = SessionLocal()
    organization = db.query(Organization).first()
    original_limit = organization.max_agents
    organization.max_agents = 1
    db.commit()
    db.close()
    try:
        with TestClient(app) as client:
            first = client.post(
                "/api/agents", json={"name": "quota-agent-one", "siteLabel": "A"}
            )
            second = client.post(
                "/api/agents", json={"name": "quota-agent-two", "siteLabel": "A"}
            )
        assert first.status_code == 201, first.text
        assert second.status_code == 409
        db = SessionLocal()
        try:
            assert db.query(AuditLog).filter(
                AuditLog.action == "agent.quota_rejected",
                AuditLog.entity_id == "quota-agent-two",
            ).count() == 1
        finally:
            db.close()
    finally:
        db = SessionLocal()
        organization = db.query(Organization).first()
        organization.max_agents = original_limit
        db.commit()
        db.close()


def test_agent_key_blocked_on_read_endpoints():
    _cleanup()
    from tls_analyzer.api.config import settings

    db = SessionLocal()
    try:
        _, plain = agent_service.create_agent(db, "site-a", "A", actor_user_id=None)
    finally:
        db.close()
    prev = settings.disable_api_auth
    settings.disable_api_auth = False
    try:
        with TestClient(app) as client:
            resp = client.get("/api/scans", headers={"X-API-Key": plain})
            assert resp.status_code == 403
    finally:
        settings.disable_api_auth = prev


def test_viewer_key_blocked_on_ingest():
    _cleanup()
    with TestClient(app) as client:
        key = generate_api_key()
        db = SessionLocal()
        try:
            db.add(ApiKey(name="v", key_hash=hash_api_key(key), prefix="cg_x", role="user"))
            db.commit()
        finally:
            db.close()
        resp = client.post(
            "/api/agent/ingest/scan", json=_scan_data("client-viewer-1"),
            headers={"X-API-Key": key},
        )
        assert resp.status_code == 403


def test_disabled_organization_blocks_agent_ingest():
    suffix = uuid4().hex
    plain = generate_api_key()
    db = SessionLocal()
    set_system_session(db)
    try:
        org = Organization(
            name=f"Disabled agent org {suffix}",
            slug=f"disabled-agent-{suffix}",
            status="disabled",
        )
        db.add(org)
        db.flush()
        key = ApiKey(
            name="disabled ingest key",
            key_hash=hash_api_key(plain),
            prefix=plain[:8],
            role="agent",
            organization_id=org.id,
        )
        db.add(key)
        db.flush()
        agent = Agent(
            name="Disabled ingest agent",
            organization_id=org.id,
            api_key_id=key.id,
        )
        db.add(agent)
        db.commit()
        org_id, key_id, agent_id = org.id, key.id, agent.id
    finally:
        db.close()

    try:
        with TestClient(app) as client:
            response = client.post(
                "/api/agent/ingest/scan",
                json=_scan_data("disabled-org-ingest"),
                headers=_headers(plain),
            )
            assert response.status_code == 401
    finally:
        db = SessionLocal()
        set_system_session(db)
        try:
            db.query(Agent).filter(Agent.id == agent_id).delete()
            db.query(ApiKey).filter(ApiKey.id == key_id).delete()
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
        finally:
            db.close()


def test_revoked_agent_key_unauthorized():
    _cleanup()
    db = SessionLocal()
    try:
        dto, plain = agent_service.create_agent(db, "site-a", "A", actor_user_id=None)
        agent_service.revoke_agent(db, dto["id"], actor_user_id=None)
    finally:
        db.close()
    with TestClient(app) as client:
        resp = client.post(
            "/api/agent/heartbeat",
            json={"agentVersion": "0.1", "schemaVersion": analysis.SCHEMA_VERSION},
            headers={"X-API-Key": plain},
        )
        assert resp.status_code == 401


def test_ingest_scan_creates_scan_service_and_is_idempotent():
    _cleanup()
    db = SessionLocal()
    try:
        _, plain = agent_service.create_agent(db, "site-a", "A", actor_user_id=None)
    finally:
        db.close()
    with TestClient(app) as client:
        body = _scan_data("client-scan-1")
        first = client.post("/api/agent/ingest/scan", json=body, headers={"X-API-Key": plain})
        assert first.status_code == 201, first.text
        scan_id = first.json()["scanId"]

        second = client.post("/api/agent/ingest/scan", json=body, headers={"X-API-Key": plain})
        assert second.status_code == 200
        assert second.json()["scanId"] == scan_id

    db = SessionLocal()
    try:
        assert db.query(Scan).count() == 1
        scan = db.query(Scan).filter(Scan.id == scan_id).one()
        assert scan.origin == "agent"
        assert scan.agent_id is not None
        assert scan.service_id is not None
        assert scan.upload_level == "standard"
        svc = db.get(Service, scan.service_id)
        assert svc.host == "intranet.corp.local" and svc.agent_id == scan.agent_id
    finally:
        db.close()
        _cleanup()


def test_scope_same_host_two_agents_two_services():
    _cleanup()
    db = SessionLocal()
    try:
        _, key_a = agent_service.create_agent(db, "a", "A", actor_user_id=None)
        _, key_b = agent_service.create_agent(db, "b", "B", actor_user_id=None)
    finally:
        db.close()
    with TestClient(app) as client:
        client.post("/api/agent/ingest/scan", json=_scan_data("scan-a-1"), headers={"X-API-Key": key_a})
        client.post("/api/agent/ingest/scan", json=_scan_data("scan-b-1"), headers={"X-API-Key": key_b})
    db = SessionLocal()
    try:
        svcs = db.query(Service).filter(Service.host == "intranet.corp.local").all()
        assert len(svcs) == 2
        assert len({s.agent_id for s in svcs}) == 2
    finally:
        db.close()
        _cleanup()


def test_standard_ingest_preserves_certificate_for_scan_detail():
    _cleanup()
    db = SessionLocal()
    try:
        _, plain = agent_service.create_agent(db, "site-a", "A", actor_user_id=None)
    finally:
        db.close()
    certificate = {
        "fingerprintSha256": "e2e-fingerprint",
        "fingerprintSha1": "e2e-fingerprint-sha1",
        "serialNumber": "01",
        "notBefore": "2026-01-01T00:00:00+00:00",
        "notAfter": "2026-12-31T00:00:00+00:00",
        "daysUntilExpiry": 60,
        "isExpired": False,
        "keyType": "RSA",
        "keySize": 2048,
        "signatureAlgorithm": "sha256WithRSAEncryption",
        "isSelfSigned": True,
        "san": ["intranet.corp.local"],
        "subject": {"CN": "intranet.corp.local"},
        "issuer": {"CN": "intranet.corp.local"},
        "basicConstraints": "CA:FALSE",
        "keyUsage": [],
        "extendedKeyUsage": [],
    }
    with TestClient(app) as client:
        body = _scan_data("client-scan-cert-1")
        body["certificate"] = certificate
        body["chain"] = [certificate]
        body["handshake"] = {"negotiated_protocol": "TLSv1.2"}
        response = client.post(
            "/api/agent/ingest/scan", json=body, headers={"X-API-Key": plain}
        )
        assert response.status_code == 201, response.text
        scan_id = response.json()["scanId"]
        detail = client.get(f"/api/scans/{scan_id}")
        assert detail.status_code == 200, detail.text
        scan = detail.json()
        assert scan["negotiatedCipher"] == body["negotiatedCipher"]
        assert scan["signatureAlgorithm"] == certificate["signatureAlgorithm"]
        cert = scan["certificate"]
        assert cert["commonName"] == "intranet.corp.local"
        assert cert["isSelfSigned"] is True
        assert cert["fingerprintSha256"] == "e2e-fingerprint"
    _cleanup()


def test_ingest_validation_rejects_extra_and_bad_schema():
    _cleanup()
    db = SessionLocal()
    try:
        _, plain = agent_service.create_agent(db, "site-a", "A", actor_user_id=None)
    finally:
        db.close()
    with TestClient(app) as client:
        bad_extra = _scan_data("client-extra-1")
        bad_extra["agentId"] = "otro-agente"
        r = client.post("/api/agent/ingest/scan", json=bad_extra, headers={"X-API-Key": plain})
        assert r.status_code == 422

        bad_schema = _scan_data("client-schema-1")
        bad_schema["schemaVersion"] = 999
        r2 = client.post("/api/agent/ingest/scan", json=bad_schema, headers={"X-API-Key": plain})
        assert r2.status_code == 422


def test_ingest_discovery_classification_scoped_per_agent():
    _cleanup()
    db = SessionLocal()
    try:
        dto_a, key_a = agent_service.create_agent(db, "a", "A", actor_user_id=None)
        dto_b, _key_b = agent_service.create_agent(db, "b", "B", actor_user_id=None)
        from tls_analyzer.api.models import Organization

        org = db.query(Organization).first()
        org_id = org.id if org else 1
        db.add(Asset(ip_address="10.0.0.5", hostname="known.corp", agent_id=dto_a["id"], organization_id=org_id))
        db.add(Asset(ip_address="10.0.0.5", hostname="other.corp", agent_id=dto_b["id"], organization_id=org_id))
        db.commit()
    finally:
        db.close()
    with TestClient(app) as client:
        body = {
            "schemaVersion": analysis.SCHEMA_VERSION,
            "rulesVersion": analysis.RULES_VERSION,
            "clientJobId": "job-a-0001",
            "cidrOrTargets": ["10.0.0.0/24"],
            "ports": [443],
            "scanInternal": True,
            "results": [
                {"ipAddress": "10.0.0.5", "port": 443, "service": "https", "serviceName": "HTTPS", "hasTls": True, "tlsVersion": "TLSv1.3"},
                {"ipAddress": "10.0.0.9", "port": 443, "service": "https", "serviceName": "HTTPS", "hasTls": True},
            ],
        }
        resp = client.post("/api/agent/ingest/discovery", json=body, headers={"X-API-Key": key_a})
        assert resp.status_code == 201, resp.text
    db = SessionLocal()
    try:
        results = db.query(DiscoveryResult).all()
        by_ip = {r.ip_address: r for r in results}
        assert by_ip["10.0.0.5"].inventory_status == "inventoried"
        assert by_ip["10.0.0.9"].inventory_status == "shadow_it"
        assert by_ip["10.0.0.5"].scope == "internal"
        known_asset = (
            db.query(Asset)
            .filter(Asset.ip_address == "10.0.0.5", Asset.agent_id == dto_a["id"])
            .one()
        )
        assert known_asset.tls_version == "TLSv1.3"
    finally:
        db.close()
        _cleanup()


def test_heartbeat_and_offline_alert():
    _cleanup()
    db = SessionLocal()
    try:
        dto, plain = agent_service.create_agent(db, "site-a", "A", actor_user_id=None)
        agent_id = dto["id"]
    finally:
        db.close()
    with TestClient(app) as client:
        resp = client.post(
            "/api/agent/heartbeat",
            json={"agentVersion": "0.1.0", "schemaVersion": analysis.SCHEMA_VERSION},
            headers={"X-API-Key": plain},
        )
        assert resp.status_code == 204

    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        assert agent.version == "0.1.0"
        assert agent.last_seen_at is not None

        # Forzar que se vea offline.
        agent.last_seen_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db.commit()
        assert generate_agent_offline_alerts(db) == 1
        assert generate_agent_offline_alerts(db) == 0  # no duplica

        # Volver a verse online resuelve la alerta.
        agent.last_seen_at = datetime.now(timezone.utc)
        db.commit()
        generate_agent_offline_alerts(db)
        alert = (
            db.query(Alert).filter(Alert.type == "agent_offline").one()
        )
        assert alert.status == "resolved"
    finally:
        db.close()
        _cleanup()

def test_ingest_rejects_invalid_upload_level_and_discovery_limits(monkeypatch):
    _cleanup()
    db = SessionLocal()
    try:
        _, plain = agent_service.create_agent(db, "site-a", "A", actor_user_id=None)
    finally:
        db.close()
    monkeypatch.setattr(settings, "agent_max_discovery_targets", 1)
    monkeypatch.setattr(settings, "agent_max_discovery_ports", 1)
    with TestClient(app) as client:
        bad_level = _scan_data("client-level-1")
        bad_level["uploadLevel"] = "burner"
        assert client.post(
            "/api/agent/ingest/scan", json=bad_level, headers={"X-API-Key": plain}
        ).status_code == 422

        base = {
            "schemaVersion": analysis.SCHEMA_VERSION,
            "rulesVersion": analysis.RULES_VERSION,
            "clientJobId": "job-limits-1",
            "scanInternal": True,
            "results": [],
        }
        too_many_targets = {**base, "cidrOrTargets": ["10.0.0.0/24", "10.0.1.0/24"]}
        assert client.post(
            "/api/agent/ingest/discovery",
            json=too_many_targets,
            headers={"X-API-Key": plain},
        ).status_code == 422

        too_many_ports = {**base, "cidrOrTargets": ["10.0.0.0/24"], "ports": [443, 8443]}
        assert client.post(
            "/api/agent/ingest/discovery",
            json=too_many_ports,
            headers={"X-API-Key": plain},
        ).status_code == 422

        invalid_result_port = {
            **base,
            "cidrOrTargets": ["10.0.0.0/24"],
            "results": [{"ipAddress": "10.0.0.1", "port": 0}],
        }
        assert client.post(
            "/api/agent/ingest/discovery",
            json=invalid_result_port,
            headers={"X-API-Key": plain},
        ).status_code == 422
    _cleanup()
