"""Minimizacion de datos en el agente segun ``upload_level`` (Parte 5.6)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .. import analysis as analysis_mod

if TYPE_CHECKING:  # pragma: no cover
    from ..analysis import AnalysisResult

_MINIMAL_CERT_KEYS = (
    "keyType",
    "keySize",
    "signatureAlgorithm",
    "notBefore",
    "notAfter",
    "isExpired",
    "daysUntilExpiry",
    "fingerprintSha256",
    "isSelfSigned",
)

_STANDARD_HANDSHAKE_KEYS = (
    "cipher_suites",
    "supported_protocols",
    "ip_address",
    "negotiated_protocol",
)


def _cert_summary(cert: dict, level: str) -> dict:
    if not cert:
        return {}
    if level == "minimal":
        return {k: cert.get(k) for k in _MINIMAL_CERT_KEYS if k in cert}
    return dict(cert)


def _fingerprint_dto(fp: dict, level: str) -> dict:
    out = dict(fp or {})
    if level in ("minimal", "standard"):
        out.pop("raw_banner", None)
        out.pop("banner", None)
    return out


def build_scan_payload(
    ar: "AnalysisResult",
    client_scan_id: str,
    upload_level: str = "standard",
) -> dict:
    """Arma el payload de scan que sale de la red segun el nivel de carga."""
    level = (
        upload_level if upload_level in ("minimal", "standard", "full") else "standard"
    )
    payload: dict = {
        "schemaVersion": analysis_mod.SCHEMA_VERSION,
        "rulesVersion": ar.rules_version or analysis_mod.RULES_VERSION,
        "clientScanId": client_scan_id,
        "uploadLevel": level,
        "target": {
            "host": ar.host,
            "port": ar.port,
            "profile": ar.profile,
        },
        "portIsAlternate": ar.port_is_alternate,
        "startedAt": ar.started_at or datetime.now(timezone.utc).isoformat(),
        "durationMs": ar.duration_ms,
        "status": ar.status,
        "score": ar.score,
        "connectionError": ar.connection_error,
        "ipAddress": ar.ip_address,
        "negotiatedProtocol": ar.negotiated_protocol,
        "negotiatedCipher": ar.negotiated_cipher,
        "supportedProtocols": list(ar.supported_protocols),
        "findings": list(ar.findings),
        "certificate": _cert_summary(ar.certificate, level),
        "osFingerprint": _fingerprint_dto(ar.os_fingerprint, level),
    }
    if level in ("standard", "full"):
        payload["chain"] = [_cert_summary(c, level) for c in ar.chain]
        payload["handshake"] = {
            k: v
            for k, v in (ar.handshake or {}).items()
            if k in ("cipher_suites", "supported_protocols", "ip_address", "negotiated_protocol")
        }
    if level == "full":
        payload["handshake"] = dict(ar.handshake or {})
        payload["rawResult"] = dict(ar.raw_result or {})
    return payload


def build_discovery_payload(
    discovered,
    client_job_id: str,
    *,
    cidr: str,
    ports: list[int],
    scan_internal: bool = True,
) -> dict:
    """Arma el payload de discovery con los resultados crudos."""
    return {
        "schemaVersion": analysis_mod.SCHEMA_VERSION,
        "rulesVersion": analysis_mod.RULES_VERSION,
        "clientJobId": client_job_id,
        "cidrOrTargets": [cidr],
        "ports": list(ports or [443]),
        "scanInternal": bool(scan_internal),
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "results": [
            {
                "ipAddress": s.ip_address,
                "hostname": s.hostname,
                "port": s.port,
                "service": s.service,
                "serviceName": s.service_name,
                "hasTls": s.has_tls,
                "tlsVersion": s.tls_version,
                "osFingerprint": s.os_fingerprint,
            }
            for s in discovered
        ],
    }
