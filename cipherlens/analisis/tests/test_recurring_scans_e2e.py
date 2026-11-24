"""End-to-end tests of recurring scans against a real loopback TLS server."""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tests.local_tls import TlsServer, write_certificate
from tls_analyzer.api.config import settings
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.main import app
from tls_analyzer.api.models import Certificate, RecurringScan, Scan, Service
from tls_analyzer.api.services import cve_service, recurring_scan_service


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    cert_path, key_path = write_certificate(tmp_path_factory.mktemp("recurring-tls"))
    server = TlsServer(cert_path, key_path)
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(autouse=True)
def _use_local_tls_only(monkeypatch):
    monkeypatch.setattr(settings, "cloud_scan_block_private", False)
    monkeypatch.setattr(cve_service, "query_nvd_by_cpe", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(cve_service, "query_nvd_by_keyword", lambda *_args, **_kwargs: [])


@pytest.fixture(autouse=True)
def _clean_state():
    """Aisla la DB en memoria (conexion compartida) entre tests."""
    db = SessionLocal()
    try:
        db.query(Scan).filter(Scan.recurring_scan_id.isnot(None)).delete()
        db.query(RecurringScan).delete()
        db.commit()
    finally:
        db.close()
    yield


def _client() -> TestClient:
    return TestClient(app)


def _create_schedule(client: TestClient, server: TlsServer) -> dict:
    resp = client.post("/api/recurring-scans", json={
        "host": "127.0.0.1", "port": server.port, "intervalHours": 24.0,
        "profile": "citizen-facing", "enabled": True,
        "authorizationAccepted": True,
        "authorizationVersion": "2026-10-v1",
    })
    assert resp.status_code == 201, resp.text
    return resp.json()


def _latest_scan(db, schedule_id: int) -> Scan | None:
    return (
        db.query(Scan)
        .filter(Scan.recurring_scan_id == schedule_id)
        .order_by(Scan.started_at.desc())
        .first()
    )


# --------------------------------------------------------------------------
# run-now: pipeline real completo
# --------------------------------------------------------------------------

@pytest.mark.e2e
def test_run_now_executes_real_pipeline(tls_server):
    with _client() as client:
        schedule = _create_schedule(client, tls_server)

        resp = client.post(f"/api/recurring-scans/{schedule['id']}/run-now")
        assert resp.status_code == 200, resp.text
        updated = resp.json()
        assert updated["host"] == "127.0.0.1"
        assert updated["lastRunAt"] is not None
        assert updated["isRunning"] is False
        assert updated["consecutiveFailures"] == 0

        # Se persistio un Scan con origen "scheduled" y recurrente vinculado.
        db = SessionLocal()
        try:
            scan_row = _latest_scan(db, schedule["id"])
            assert scan_row is not None, "no scan was persisted by run-now"
            assert scan_row.origin == "scheduled"
            assert scan_row.recurring_scan_id == schedule["id"]
            assert scan_row.status == "completed"
            assert scan_row.score is not None and 0 <= scan_row.score <= 100
            assert scan_row.raw_result is not None
            cert_chain = scan_row.raw_result.get("certificate_chain") or []
            assert cert_chain and (cert_chain[0].get("not_after"))

            # Inventario resuelto: service_id linkeado al scan
            assert scan_row.service_id is not None

            # El run recurrente debe reconciliar el inventory (Service + Certificate),
            # igual que un scan manual.
            service = db.query(Service).filter(
                Service.host == "127.0.0.1", Service.port == tls_server.port
            ).first()
            assert service is not None, "recurring run did not create/update the Service inventory"
            assert service.id == scan_row.service_id
            assert service.last_seen is not None
            assert service.tls_enabled is True

            cert = db.query(Certificate).filter(
                Certificate.service_id == service.id
            ).first()
            assert cert is not None, "recurring run did not create the Certificate inventory"
            assert cert.not_after
            assert cert.days_until_expiry != 0 or cert.status

            # nextRunAt avanza interval_hours desde lastRunAt
            assert schedule["intervalHours"] == 24.0
            last = datetime.fromisoformat(updated["lastRunAt"])
            nxt = datetime.fromisoformat(updated["nextRunAt"])
            assert abs((nxt - last - timedelta(hours=24.0)).total_seconds()) < 5
        finally:
            db.close()


# --------------------------------------------------------------------------
# Scheduler tick: misma funcion que el job periodico de APScheduler
# --------------------------------------------------------------------------

@pytest.mark.e2e
def test_scheduler_tick_executes_due_scan(tls_server):
    with _client() as client:
        schedule = _create_schedule(client, tls_server)

        # El schedule recien creado tiene next_run_at=now, por lo que esta "due"
        recurring_scan_service.run_scheduled_scans_tick()

        db = SessionLocal()
        try:
            scan_row = _latest_scan(db, schedule["id"])
            assert scan_row is not None, "tick did not execute the due scan"
            assert scan_row.origin == "scheduled"
            assert scan_row.recurring_scan_id == schedule["id"]
            assert scan_row.status == "completed"

            row = db.get(RecurringScan, schedule["id"])
            assert row.last_run_at is not None
            assert row.consecutive_failures == 0
        finally:
            db.close()


# --------------------------------------------------------------------------
# Segunda corrida: la comparacion detecta que hay corrida previa
# --------------------------------------------------------------------------

@pytest.mark.e2e
def test_second_run_comparison_has_previous(tls_server):
    with _client() as client:
        schedule = _create_schedule(client, tls_server)

        for _ in range(2):
            response = client.post(f"/api/recurring-scans/{schedule['id']}/run-now")
            assert response.status_code == 200, response.text
            assert response.json()["consecutiveFailures"] == 0

        db = SessionLocal()
        try:
            latest = _latest_scan(db, schedule["id"])
            assert latest is not None
            cmp = recurring_scan_service.compute_scan_comparison(db, latest)
            assert cmp.has_previous is True
            assert cmp.score_delta == 0

            # Host estatico: dos corridas dan resultados idénticos.
            # Con score_delta == 0 y sin reglas nuevas/resueltas no debe
            # generarse alerta de regresion/mejora (sanity, no forzado).
            assert not cmp.new_critical_or_high_rule_ids
            assert not cmp.resolved_rule_ids
        finally:
            db.close()
