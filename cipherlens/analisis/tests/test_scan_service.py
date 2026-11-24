"""Tests del bug 0.2: todo Scan persistido queda enlazado a su Service."""

from datetime import datetime, timezone

from tls_analyzer import analysis
from tls_analyzer.api.db import SessionLocal
from tls_analyzer.api.models import Asset, Scan, Service
from tls_analyzer.api.services import scan_service

_HOST = "scan-service-link.test"
_PORT = 443


def _fake_analysis(*, connection_error=None):
    """AnalysisResult minimo, sin red, para ejercitar la persistencia."""
    return analysis.AnalysisResult(
        host=_HOST,
        port=_PORT,
        started_at=datetime.now(timezone.utc).isoformat(),
        duration_ms=5,
        status="failed" if connection_error else "completed",
        connection_error=connection_error,
        handshake={
            "ip_address": "" if connection_error else "203.0.113.10",
            "negotiated_protocol": "" if connection_error else "TLSv1.3",
            "negotiated_cipher": "" if connection_error else "TLS_AES_128_GCM_SHA256",
            "connection_error": connection_error,
        },
    )


def _patch_pipeline(monkeypatch, *, connection_error=None):
    """Corre run_scan sin red: analyze_target y NVD mockeados."""
    monkeypatch.setattr(
        scan_service.analysis,
        "analyze_target",
        lambda *a, **kw: _fake_analysis(connection_error=connection_error),
    )
    monkeypatch.setattr(
        scan_service.cve_service,
        "get_or_query_live_cves",
        lambda *a, **kw: ([], [], None),
    )


def _cleanup(host: str):
    db = SessionLocal()
    try:
        db.query(Scan).filter(Scan.host == host).delete(synchronize_session=False)
        db.query(Service).filter(Service.host == host).delete(synchronize_session=False)
        db.query(Asset).filter(Asset.hostname == host).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


def test_run_scan_links_service_id(monkeypatch):
    _cleanup(_HOST)
    _patch_pipeline(monkeypatch)
    db = SessionLocal()
    try:
        scan_service.run_scan(db, f"{_HOST}:{_PORT}")
        row = db.query(Scan).filter(Scan.host == _HOST).one()
        assert row.service_id is not None, "run_scan dejo Scan.service_id en NULL"
        service = db.get(Service, row.service_id)
        assert service is not None
        assert service.host == _HOST
        assert service.port == _PORT
    finally:
        db.close()


def test_run_scan_connection_error_also_links_service_id(monkeypatch):
    _cleanup(_HOST)
    _patch_pipeline(monkeypatch, connection_error="boom")
    db = SessionLocal()
    try:
        scan_service.run_scan(db, f"{_HOST}:{_PORT}")
        row = db.query(Scan).filter(Scan.host == _HOST).one()
        assert row.status == "failed"
        assert row.service_id is not None, "run_scan dejo Scan.service_id en NULL"
        service = db.get(Service, row.service_id)
        assert service is not None
        assert service.host == _HOST
    finally:
        db.close()


def test_run_scan_scheduled_origin_links_service_id(monkeypatch):
    """El origen scheduled (recurring) usa el mismo run_scan: mismo enlace."""
    _cleanup(_HOST)
    _patch_pipeline(monkeypatch)
    db = SessionLocal()
    try:
        scan_service.run_scan(db, f"{_HOST}:{_PORT}", origin="scheduled")
        row = db.query(Scan).filter(Scan.host == _HOST).one()
        assert row.origin == "scheduled"
        assert row.service_id is not None
    finally:
        db.close()


def test_persist_scan_links_service_without_network():
    """persist_scan tambien enlaza: cualquier llamante directo queda cubierto."""
    _cleanup(_HOST)
    db = SessionLocal()
    try:
        result = _fake_analysis(connection_error="boom")
        row = scan_service.persist_scan(db, result)
        assert row.service_id is not None
        assert db.get(Service, row.service_id).host == _HOST
    finally:
        db.close()


def test_run_scan_persists_tls_version_on_asset(monkeypatch):
    """El asset del inventario refleja el TLS negociado por el scan."""
    _cleanup(_HOST)
    _patch_pipeline(monkeypatch)
    db = SessionLocal()
    try:
        scan_service.run_scan(db, f"{_HOST}:{_PORT}")
        asset = (
            db.query(Asset)
            .filter(Asset.hostname == _HOST, Asset.port == _PORT)
            .one()
        )
        assert asset.tls_version == "TLSv1.3"

        _patch_pipeline(monkeypatch, connection_error="boom")
        scan_service.run_scan(db, f"{_HOST}:{_PORT}")
        db.refresh(asset)
        assert asset.tls_version == "TLSv1.3"
    finally:
        db.close()
        _cleanup(_HOST)
