"""M3 remote task queue, local allowlists, leases and result delivery."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import URL, create_engine, event
from sqlalchemy.orm import sessionmaker

from tls_analyzer import analysis
from tls_analyzer.agent.config import AgentConfig
from tls_analyzer.agent.remote_tasks import TargetNotAllowed, validate_remote_task
from tls_analyzer.agent.runner import AgentRunner
from tls_analyzer.api.db import Base, SessionLocal, TenantSession
from tls_analyzer.api.deps import generate_api_key, hash_api_key
from tls_analyzer.api.main import app
from tls_analyzer.api.models import (
    AgentTask,
    Agent,
    ApiKey,
    Asset,
    AuditLog,
    DiscoveryJob,
    DiscoveryResult,
    Organization,
    RecurringScan,
    Scan,
    Service,
    User,
)
from tls_analyzer.api.services import agent_service, agent_task_service
from tls_analyzer.api.tenancy import install_tenancy, set_system_session, set_tenant_session
from tls_analyzer.discovery import DiscoveredService


def _cleanup() -> None:
    db = SessionLocal()
    set_system_session(db)
    try:
        db.query(AgentTask).delete(synchronize_session=False)
        db.query(DiscoveryResult).delete(synchronize_session=False)
        db.query(DiscoveryJob).delete(synchronize_session=False)
        db.query(Scan).delete(synchronize_session=False)
        db.query(Service).delete(synchronize_session=False)
        db.query(Asset).delete(synchronize_session=False)
        db.query(RecurringScan).delete(synchronize_session=False)
        db.query(AuditLog).filter(AuditLog.action.like("agent_task.%")).delete(
            synchronize_session=False
        )
        db.commit()
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _isolated_task_data():
    _cleanup()
    yield
    _cleanup()


def _make_agent(name: str = "remote-agent") -> tuple[str, str]:
    db = SessionLocal()
    try:
        dto, key = agent_service.create_agent(db, name, "Test Site", actor_user_id=None)
        return dto["id"], key
    finally:
        db.close()


def _heartbeat(client: TestClient, key: str, *, allow: bool = True) -> None:
    response = client.post(
        "/api/agent/heartbeat",
        headers={"X-API-Key": key},
        json={
            "agentVersion": "test",
            "schemaVersion": analysis.SCHEMA_VERSION,
            "capabilities": {
                "allowRemoteTasks": allow,
                "networkCount": 1 if allow else 0,
                "portCount": 1 if allow else 0,
                "allowedNetworks": ["10.0.0.0/24"] if allow else [],
                "allowedPorts": [443] if allow else [],
            },
        },
    )
    assert response.status_code == 204, response.text


def _scan_ingest(client_scan_id: str, task_id: str) -> dict:
    return {
        "schemaVersion": analysis.SCHEMA_VERSION,
        "rulesVersion": analysis.RULES_VERSION,
        "clientScanId": client_scan_id,
        "taskId": task_id,
        "uploadLevel": "minimal",
        "target": {"host": "10.0.0.5", "port": 443, "profile": "citizen-facing"},
        "status": "completed",
        "score": 80,
        "durationMs": 10,
        "ipAddress": "10.0.0.5",
        "findings": [],
        "certificate": {},
        "chain": [],
        "handshake": {},
        "osFingerprint": {},
        "rawResult": {},
    }


def test_remote_scan_is_queued_then_claimed_only_by_assigned_agent():
    agent_a, key_a = _make_agent("agent-a")
    _agent_b, key_b = _make_agent("agent-b")
    with TestClient(app) as client:
        response = client.post(
            "/api/scans",
            json={
                "target": "10.0.0.5",
                "port": 443,
                "executor": {"type": "agent", "agentId": agent_a},
            },
        )
        assert response.status_code == 202, response.text
        task_id = response.json()["taskId"]
        _heartbeat(client, key_b)
        assert client.post(
            "/api/agent/tasks/claim",
            headers={"X-API-Key": key_b},
            json={"maxTasks": 1, "agentVersion": "test"},
        ).json() == []
        _heartbeat(client, key_a)
        claimed = client.post(
            "/api/agent/tasks/claim",
            headers={"X-API-Key": key_a},
            json={"maxTasks": 1, "agentVersion": "test"},
        )
        assert claimed.status_code == 200, claimed.text
        assert [item["taskId"] for item in claimed.json()] == [task_id]
        assert claimed.json()[0]["type"] == "scan"
        assert client.post(
            "/api/agent/tasks/claim",
            headers={"X-API-Key": key_a},
            json={"maxTasks": 1, "agentVersion": "test"},
        ).json() == []

    db = SessionLocal()
    try:
        task = db.get(AgentTask, task_id)
        assert task is not None
        assert task.status == "claimed"
        assert task.attempts == 1
        assert task.lease_expires_at is not None
        assert db.query(AuditLog).filter(
            AuditLog.action == "agent_task.created",
            AuditLog.entity_id == task_id,
        ).count() == 1
    finally:
        db.close()


def test_agent_must_opt_in_before_claim_and_task_status_renews_lease():
    agent_id, key = _make_agent()
    db = SessionLocal()
    try:
        task = agent_task_service.create_task(
            db,
            agent_id=agent_id,
            task_type="scan",
            payload={"target": {"host": "10.0.0.5", "port": 443}, "options": {}},
            requested_by_user_id=None,
        )
        task_id = task.id
    finally:
        db.close()

    with TestClient(app) as client:
        _heartbeat(client, key, allow=False)
        assert client.post(
            "/api/agent/tasks/claim",
            headers={"X-API-Key": key},
            json={"maxTasks": 1},
        ).json() == []
        _heartbeat(client, key, allow=True)
        claimed = client.post(
            "/api/agent/tasks/claim",
            headers={"X-API-Key": key},
            json={"maxTasks": 1},
        ).json()
        assert claimed[0]["taskId"] == task_id
        running = client.post(
            f"/api/agent/tasks/{task_id}/status",
            headers={"X-API-Key": key},
            json={"status": "running"},
        )
        assert running.status_code == 200, running.text
        assert running.json()["status"] == "running"
        lease_until = datetime.fromisoformat(running.json()["leaseExpiresAt"])
        assert lease_until.replace(tzinfo=timezone.utc) > (
            datetime.now(timezone.utc)
        )


@pytest.fixture
def claim_database(tmp_path):
    # A file-backed database lets each worker use a separate connection.
    url = URL.create("sqlite", database=str(tmp_path / "agent-claims.db"))
    engine = create_engine(url, connect_args={"timeout": 10})
    sessions = sessionmaker(bind=engine, class_=TenantSession, expire_on_commit=False)
    install_tenancy(sessions)
    try:
        Base.metadata.create_all(engine)
        yield engine, sessions
    finally:
        engine.dispose()


def test_concurrent_claimers_receive_one_copy_of_a_task(claim_database):
    engine, sessions = claim_database
    with sessions() as db:
        set_system_session(db)
        organization = Organization(name="Claim Tests", slug="claim-tests", status="active")
        db.add(organization)
        db.commit()
        organization_id = organization.id
        set_tenant_session(db, organization_id)
        agent, _ = agent_service.create_agent(
            db, "concurrent-agent", "Test Site", actor_user_id=None
        )
        agent_id = agent["id"]
        task = agent_task_service.create_task(
            db,
            agent_id=agent_id,
            task_type="scan",
            payload={"target": {"host": "10.0.0.5", "port": 443}, "options": {}},
            requested_by_user_id=None,
        )
        task_id = task.id

    before_claim_update = Barrier(2, timeout=10)

    @event.listens_for(engine, "before_cursor_execute")
    def synchronize_claim_updates(conn, _cursor, _sql, _params, context, _many):
        # Both workers must have selected the queued task before either updates it.
        if not context.isupdate or context.compiled.statement.table.name != AgentTask.__tablename__:
            return
        if not conn.info.get("claim_update_synchronized"):
            conn.info["claim_update_synchronized"] = True
            before_claim_update.wait()

    def claim_once():
        with sessions() as session:
            set_tenant_session(session, organization_id)
            agent_row = session.get(Agent, agent_id)
            return agent_task_service.claim_tasks(
                session, agent=agent_row, max_tasks=1
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: claim_once(), range(2)))
    assert [claimed["taskId"] for tasks in results for claimed in tasks] == [task_id]
    with sessions() as db:
        set_tenant_session(db, organization_id)
        persisted = db.get(AgentTask, task_id)
        assert (persisted.status, persisted.attempts) == ("claimed", 1)


def test_runner_does_not_poll_when_remote_tasks_are_disabled():
    calls: list[str] = []

    class RecordingClient:
        def heartbeat(self):
            calls.append("heartbeat")

        def claim_tasks(self, max_tasks):  # pragma: no cover - must not run
            calls.append("claim")
            return []

    runner = AgentRunner(
        AgentConfig(server_url="https://platform.example.test"),
        client=RecordingClient(),
    )
    runner._run_remote_tasks()
    runner.tick()
    assert calls == ["heartbeat"]


def test_result_task_id_makes_agent_scan_ingest_idempotent():
    agent_id, key = _make_agent()
    with TestClient(app) as client:
        queued = client.post(
            "/api/scans",
            json={
                "target": "10.0.0.5:443",
                "executor": {"type": "agent", "agentId": agent_id},
            },
        )
        assert queued.status_code == 202, queued.text
        task_id = queued.json()["taskId"]
        _heartbeat(client, key)
        claimed = client.post(
            "/api/agent/tasks/claim",
            headers={"X-API-Key": key},
            json={"maxTasks": 1},
        ).json()
        assert claimed[0]["taskId"] == task_id
        first = client.post(
            "/api/agent/ingest/scan",
            headers={"X-API-Key": key},
            json=_scan_ingest("scan-client-first", task_id),
        )
        assert first.status_code == 201, first.text
        second = client.post(
            "/api/agent/ingest/scan",
            headers={"X-API-Key": key},
            json=_scan_ingest("scan-client-retry", task_id),
        )
        assert second.status_code == 200, second.text
        assert second.json()["scanId"] == first.json()["scanId"]

    db = SessionLocal()
    try:
        task = db.get(AgentTask, task_id)
        assert task.status == "done"
        assert task.result_scan_id == first.json()["scanId"]
        assert db.query(Scan).filter(Scan.task_id == task_id).count() == 1
    finally:
        db.close()


def test_task_listing_and_cancellation_are_tenant_scoped_and_audited():
    agent_id, _key = _make_agent("cancel-agent")
    with TestClient(app) as client:
        queued = client.post(
            "/api/scans",
            json={
                "target": "10.0.0.5",
                "executor": {"type": "agent", "agentId": agent_id},
            },
        )
        assert queued.status_code == 202, queued.text
        task_id = queued.json()["taskId"]
        listed = client.get("/api/agent-tasks", params={"status": "queued"})
        assert listed.status_code == 200, listed.text
        assert any(task["id"] == task_id for task in listed.json())
        details = client.get(f"/api/agent-tasks/{task_id}")
        assert details.status_code == 200
        cancelled = client.delete(f"/api/agent-tasks/{task_id}")
        assert cancelled.status_code == 200, cancelled.text
        assert cancelled.json()["status"] == "cancelled"
        again = client.delete(f"/api/agent-tasks/{task_id}")
        assert again.status_code == 409
    db = SessionLocal()
    try:
        assert db.query(AuditLog).filter(
            AuditLog.action == "agent_task.cancelled",
            AuditLog.entity_id == task_id,
        ).count() == 1
    finally:
        db.close()


def test_recurring_agent_scan_enqueues_once_and_failure_updates_schedule():
    from tls_analyzer.api.services import recurring_scan_service

    agent_id, _key = _make_agent("recurring-agent")
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        schedule = RecurringScan(
            host="10.0.0.5",
            port=443,
            agent_id=agent_id,
            interval_hours=24,
            enabled=True,
            organization_id=agent.organization_id,
            next_run_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        db.add(schedule)
        db.commit()
        schedule_id = schedule.id
    finally:
        db.close()

    recurring_scan_service._execute_scheduled_scan(schedule_id)
    recurring_scan_service._execute_scheduled_scan(schedule_id)
    db = SessionLocal()
    try:
        tasks = db.query(AgentTask).filter(
            AgentTask.recurring_scan_id == schedule_id
        ).all()
        assert len(tasks) == 1
        task = tasks[0]
        assert task.type == "scan"
        schedule = db.get(RecurringScan, schedule_id)
        assert schedule.is_running is True
        assert schedule.next_run_at > datetime.now(timezone.utc).replace(tzinfo=None)
        agent = db.get(Agent, agent_id)
        claimed = agent_task_service.claim_tasks(
            db, agent=agent, max_tasks=1
        )
        assert claimed[0]["taskId"] == task.id
        agent_task_service.update_task_status(
            db,
            agent=agent,
            task_id=task.id,
            status="failed",
            reason="test_failure",
        )
        db.refresh(schedule)
        assert schedule.consecutive_failures == 1
        assert schedule.is_running is False
    finally:
        db.close()


def test_agent_task_role_and_cross_organization_agent_are_rejected():
    db = SessionLocal()
    try:
        organization = db.query(Organization).first()
        user_a = User(
            email=f"remote-user-{datetime.now().timestamp()}@example.test",
            name="Tenant A admin",
            role="admin",
            organization_id=organization.id,
        )
        db.add(user_a)
        db.commit()
        db.refresh(user_a)
        user_a_id = user_a.id
        key = generate_api_key()
        db.add(ApiKey(
            name="viewer-task-test",
            key_hash=hash_api_key(key),
            prefix=key[:8] + "...",
            role="viewer",
            organization_id=organization.id,
        ))

        set_system_session(db)
        suffix = str(datetime.now().timestamp()).replace(".", "")
        other_org = Organization(
            name=f"Remote Other {suffix}",
            slug=f"remote-other-{suffix}",
            status="active",
        )
        db.add(other_org)
        db.flush()
        user = User(
            email=f"remote-{suffix}@example.test",
            name="Remote tenant admin",
            role="admin",
            organization_id=other_org.id,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        other_agent_dto, _ = agent_service.create_agent(
            db, "foreign-agent", "Other", actor_user_id=user.id
        )
        other_agent = other_agent_dto["id"]
    finally:
        db.close()

    from tls_analyzer.api.config import settings

    previous = settings.disable_api_auth
    settings.disable_api_auth = False
    try:
        from tls_analyzer.api.services.auth_service import create_access_token

        token = create_access_token(user_a_id, "admin")
        with TestClient(app) as client:
            denied = client.get(
                "/api/agent-tasks", headers={"X-API-Key": key}
            )
            assert denied.status_code == 403
            foreign = client.post(
                "/api/scans",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "target": "10.0.0.5",
                    "executor": {"type": "agent", "agentId": other_agent},
                },
            )
            assert foreign.status_code == 404, foreign.text
    finally:
        settings.disable_api_auth = previous


def test_viewer_cannot_enqueue_scan_or_discovery_on_an_agent():
    agent_id, _key = _make_agent("viewer-enqueue-agent")
    db = SessionLocal()
    try:
        organization = db.query(Organization).first()
        viewer_key = generate_api_key()
        db.add(ApiKey(
            name="viewer-enqueue-test",
            key_hash=hash_api_key(viewer_key),
            prefix=viewer_key[:8] + "...",
            role="viewer",
            organization_id=organization.id,
        ))
        db.commit()
    finally:
        db.close()

    from tls_analyzer.api.config import settings

    previous = settings.disable_api_auth
    settings.disable_api_auth = False
    try:
        with TestClient(app) as client:
            scan = client.post(
                "/api/scans",
                headers={"X-API-Key": viewer_key},
                json={
                    "target": "10.0.0.5",
                    "executor": {"type": "agent", "agentId": agent_id},
                },
            )
            assert scan.status_code == 403, scan.text
            discovery = client.post(
                "/api/discovery",
                headers={"X-API-Key": viewer_key},
                json={
                    "ipRange": "10.0.0.0/24",
                    "ports": [443],
                    "executor": {"type": "agent", "agentId": agent_id},
                },
            )
            assert discovery.status_code == 403, discovery.text
    finally:
        settings.disable_api_auth = previous

    db = SessionLocal()
    try:
        assert db.query(AgentTask).count() == 0
    finally:
        db.close()


def test_task_lease_requeues_then_fails_at_max_attempts_and_queued_task_expires():
    agent_id, _ = _make_agent()
    db = SessionLocal()
    try:
        agent = db.get(Agent, agent_id)
        task = agent_task_service.create_task(
            db,
            agent_id=agent_id,
            task_type="scan",
            payload={"target": {"host": "10.0.0.5", "port": 443}, "options": {}},
            requested_by_user_id=None,
        )
        task_id = task.id
        for attempt in range(3):
            claimed = agent_task_service.claim_tasks(
                db, agent=agent, max_tasks=1
            )
            assert claimed and claimed[0]["taskId"] == task_id
            task = db.get(AgentTask, task_id)
            assert task.attempts == attempt + 1
            task.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
        assert agent_task_service.claim_tasks(db, agent=agent, max_tasks=1) == []
        task = db.get(AgentTask, task_id)
        assert task.status == "failed"
        assert task.error == "Lease expired after maximum attempts"

        expired = agent_task_service.create_task(
            db,
            agent_id=agent_id,
            task_type="discovery",
            payload={"ipRange": "10.0.0.0/24", "ports": [443]},
            requested_by_user_id=None,
        )
        expired.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
        assert agent_task_service.claim_tasks(db, agent=agent, max_tasks=1) == []
        assert db.get(AgentTask, expired.id).status == "expired"
    finally:
        db.close()


def test_local_allowlist_is_fail_closed_and_pins_valid_scan_targets():
    config = AgentConfig(
        server_url="https://platform.example.test",
        allow_remote_tasks=True,
        allowed_networks=["10.0.0.0/24"],
        allowed_ports=[443],
    )
    task = {
        "taskId": "12345678-1234-1234-1234-123456789abc",
        "type": "scan",
        "payload": {
            "target": {"host": "10.0.0.5", "port": 443},
            "options": {},
        },
    }
    validated = validate_remote_task(task, config)
    assert validated["pinned_address"] == "10.0.0.5"
    assert validated["ports"] == [443]

    config.allowed_networks = []
    with pytest.raises(TargetNotAllowed, match="target_not_allowed"):
        validate_remote_task(task, config)
    config.allowed_networks = ["10.0.0.0/24"]
    task["payload"]["target"]["host"] = "10.0.1.5"
    with pytest.raises(TargetNotAllowed, match="target_not_allowed"):
        validate_remote_task(task, config)


def test_runner_rejects_out_of_scope_task_without_connecting(monkeypatch):
    import tls_analyzer.agent.remote_tasks as remote_tasks

    agent_id, key = _make_agent("reject-agent")
    with TestClient(app) as client:
        queued = client.post(
            "/api/scans",
            json={
                "target": "10.0.1.5",
                "executor": {"type": "agent", "agentId": agent_id},
            },
        )
        assert queued.status_code == 202, queued.text
        task_id = queued.json()["taskId"]
        _heartbeat(client, key)
        claimed = client.post(
            "/api/agent/tasks/claim",
            headers={"X-API-Key": key},
            json={"maxTasks": 1},
        ).json()[0]

        monkeypatch.setattr(
            remote_tasks.analysis,
            "analyze_target",
            lambda *args, **kwargs: pytest.fail("out-of-scope target was scanned"),
        )

        class RejectBridge:
            def update_task_status(self, task_id, status, reason=None):
                payload = {"status": status}
                if reason:
                    payload["reason"] = reason
                return client.post(
                    f"/api/agent/tasks/{task_id}/status",
                    headers={"X-API-Key": key},
                    json=payload,
                ).json()

        runner = AgentRunner(
            AgentConfig(
                server_url="https://platform.example.test",
                allow_remote_tasks=True,
                allowed_networks=["10.0.0.0/24"],
                allowed_ports=[443],
            ),
            client=RejectBridge(),
        )
        runner._process_remote_task(claimed)
        details = client.get(f"/api/agent-tasks/{task_id}")
        assert details.status_code == 200
        assert details.json()["status"] == "rejected"
        assert details.json()["error"] == "target_not_allowed"

    db = SessionLocal()
    try:
        audit = db.query(AuditLog).filter(
            AuditLog.action == "agent_task.rejected",
            AuditLog.entity_id == task_id,
        ).one()
        assert audit.actor_type == "agent"
        assert audit.meta["reason"] == "target_not_allowed"
    finally:
        db.close()


def test_runner_executes_allowlisted_discovery_and_ingest_classifies_results(
    monkeypatch,
):
    import tls_analyzer.agent.remote_tasks as remote_tasks

    agent_id, key = _make_agent("discovery-agent")
    with TestClient(app) as client:
        # A user requests an internal /24; the platform queues it without opening
        # any connection to the client network.
        queued = client.post(
            "/api/discovery",
            json={
                "ipRange": "10.0.0.0/24",
                "ports": [443],
                "executor": {"type": "agent", "agentId": agent_id},
            },
        )
        assert queued.status_code == 202, queued.text
        task_id = queued.json()["taskId"]
        _heartbeat(client, key)
        claimed = client.post(
            "/api/agent/tasks/claim",
            headers={"X-API-Key": key},
            json={"maxTasks": 1},
        ).json()
        assert claimed[0]["taskId"] == task_id

        db = SessionLocal()
        try:
            agent = db.get(Agent, agent_id)
            db.add(Asset(
                ip_address="10.0.0.2",
                hostname="known.internal",
                agent_id=agent_id,
                organization_id=agent.organization_id,
            ))
            db.commit()
        finally:
            db.close()

        monkeypatch.setattr(
            remote_tasks,
            "run_discovery_sync",
            lambda **kwargs: [
                DiscoveredService(
                    ip_address="10.0.0.2",
                    port=443,
                    hostname="known.internal",
                    service="https",
                    service_name="HTTPS",
                    has_tls=True,
                    tls_version="TLSv1.3",
                    scope="internal",
                ),
                DiscoveredService(
                    ip_address="10.0.0.3",
                    port=443,
                    hostname=None,
                    service="https",
                    service_name="HTTPS",
                    has_tls=True,
                    tls_version="TLSv1.2",
                    scope="internal",
                ),
            ],
        )

        class ClientBridge:
            def update_task_status(self, task_id, status, reason=None):
                payload = {"status": status}
                if reason:
                    payload["reason"] = reason
                return client.post(
                    f"/api/agent/tasks/{task_id}/status",
                    headers={"X-API-Key": key},
                    json=payload,
                ).json()

            def ingest_discovery(self, payload):
                response = client.post(
                    "/api/agent/ingest/discovery",
                    headers={"X-API-Key": key},
                    json=payload,
                )
                assert response.status_code in (200, 201), response.text
                return response.json()

        runner = AgentRunner(
            AgentConfig(
                server_url="https://platform.example.test",
                allow_remote_tasks=True,
                allowed_networks=["10.0.0.0/24"],
                allowed_ports=[443],
                max_task_hosts=1024,
                max_task_ports=8,
            ),
            client=ClientBridge(),
        )
        runner._process_remote_task(claimed[0])

        task_details = client.get(f"/api/agent-tasks/{task_id}")
        assert task_details.status_code == 200, task_details.text
        result = client.get(
            f"/api/discovery/{task_details.json()['resultJobId']}/results"
        )
        assert result.status_code == 200, result.text
        assert [item["inventoried"] for item in result.json()] == [True, False]
        retry = client.post(
            "/api/agent/ingest/discovery",
            headers={"X-API-Key": key},
            json={
                "schemaVersion": analysis.SCHEMA_VERSION,
                "rulesVersion": analysis.RULES_VERSION,
                "clientJobId": "retry-client-job-1",
                "taskId": task_id,
                "cidrOrTargets": ["10.0.0.0/24"],
                "ports": [443],
                "scanInternal": True,
                "results": [
                    {
                        "ipAddress": "10.0.0.2",
                        "hostname": "known.internal",
                        "port": 443,
                        "service": "https",
                        "serviceName": "HTTPS",
                        "hasTls": True,
                        "tlsVersion": "TLSv1.3",
                    }
                ],
            },
        )
        assert retry.status_code == 200, retry.text
        assert retry.json()["jobId"] == task_details.json()["resultJobId"]

    db = SessionLocal()
    try:
        task = db.get(AgentTask, task_id)
        assert task.status == "done"
        assert task.result_job_id is not None
        job = db.get(DiscoveryJob, task.result_job_id)
        assert job.organization_id == task.organization_id
        assert job.agent_id == agent_id
        assert db.query(DiscoveryResult).filter(
            DiscoveryResult.discovery_job_id == job.id
        ).count() == 2
    finally:
        db.close()
