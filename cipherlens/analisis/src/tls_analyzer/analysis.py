"""Nucleo de analisis puro (sin FastAPI ni SQLAlchemy).

Ejecuta el pipeline de red y analisis para un target TLS y devuelve un
``AnalysisResult`` serializable (dicts JSON). Es la base que comparten:

- el backend (``tls_analyzer.api.services.scan_service``), que le agrega
  persistencia, reconciliacion de issues, alertas, enriquecimiento NVD y
  recomendacion con IA; y
- el agente on-premise (``tls_analyzer.agent``), que lo ejecuta dentro de la
  red del cliente y sube solo el resumen.

Este modulo **no** importa ``fastapi`` ni ``sqlalchemy`` a proposito: el agente
debe poder correr sin esas dependencias (ver test de aislamiento).
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from . import nist
from . import serializers
from .certificate import analyze_certificate_from_der, fetch_certificate_chain
from .fingerprint import (
    ServiceFingerprint,
    fingerprint_from_banner,
    fingerprint_from_handshake,
    grab_banner,
    grab_https_banner,
)
from .handshake import analyze_handshake
from .cloud_network import PinnedTarget, open_target_connection
from .scanner import ScanResult as EngineScanResult
from .scanner import scan as engine_scan

# Version del esquema de ingesta (entero) y del motor de reglas (cadena).
# El agente los declara en cada payload; la plataforma rechaza versiones que no
# soporta (ver routers/agents.py) y guarda rulesVersion para poder mostrarlo.
SCHEMA_VERSION = 1
RULES_VERSION = "2024.10"

DEFAULT_TIMEOUT = 10.0


@dataclass
class AnalysisResult:
    """Resultado serializable de ``analyze_target``.

    Todos los campos son JSON-friendly. Los campos con prefijo ``_`` no se
    serializan y se usan solo en el proceso que ejecuta el analisis (p. ej. el
    objeto ``ServiceFingerprint`` para resolver CPE en la plataforma).
    """

    host: str
    port: int
    port_is_alternate: bool = False
    profile: str = nist.DEFAULT_PROFILE
    score: int = 100
    status: str = "completed"
    started_at: str = ""
    duration_ms: int = 0
    connection_error: Optional[str] = None
    ip_address: str = ""
    negotiated_protocol: str = ""
    negotiated_cipher: str = ""
    supported_protocols: list = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    certificate: dict = field(default_factory=dict)
    chain: list[dict] = field(default_factory=list)
    handshake: dict = field(default_factory=dict)
    os_fingerprint: dict = field(default_factory=dict)
    fingerprint: dict = field(default_factory=dict)
    raw_result: dict = field(default_factory=dict)
    rules_version: str = RULES_VERSION
    schema_version: int = SCHEMA_VERSION
    _fingerprint: Any = field(default=None, repr=False, compare=False)
    _engine: Any = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        """Version serializable (excluye campos privados)."""
        return {
            "host": self.host,
            "port": self.port,
            "portIsAlternate": self.port_is_alternate,
            "profile": self.profile,
            "score": self.score,
            "status": self.status,
            "startedAt": self.started_at,
            "durationMs": self.duration_ms,
            "connectionError": self.connection_error,
            "ipAddress": self.ip_address,
            "negotiatedProtocol": self.negotiated_protocol,
            "negotiatedCipher": self.negotiated_cipher,
            "supportedProtocols": self.supported_protocols,
            "findings": self.findings,
            "certificate": self.certificate,
            "chain": self.chain,
            "handshake": self.handshake,
            "osFingerprint": self.os_fingerprint,
            "fingerprint": self.fingerprint,
            "rawResult": self.raw_result,
            "schemaVersion": SCHEMA_VERSION,
            "rulesVersion": RULES_VERSION,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisResult":
        """Reconstruye un AnalysisResult desde un payload (plataforma/agente)."""
        return cls(
            host=data.get("host", ""),
            port=int(data.get("port") or 0),
            port_is_alternate=bool(data.get("portIsAlternate")),
            profile=data.get("profile") or nist.DEFAULT_PROFILE,
            score=int(data.get("score") or 0),
            status=data.get("status") or "completed",
            started_at=data.get("startedAt") or "",
            duration_ms=int(data.get("scanDurationMs") or data.get("durationMs") or 0),
            connection_error=data.get("connectionError"),
            ip_address=data.get("ipAddress") or "",
            negotiated_protocol=data.get("negotiatedProtocol") or "",
            negotiated_cipher=data.get("negotiatedCipher") or "",
            supported_protocols=list(data.get("supportedProtocols") or []),
            findings=list(data.get("findings") or []),
            certificate=dict(data.get("certificate") or {}),
            chain=list(data.get("chain") or []),
            handshake=dict(data.get("handshake") or {}),
            os_fingerprint=dict(data.get("osFingerprint") or {}),
            fingerprint=dict(data.get("fingerprint") or {}),
            raw_result=dict(data.get("rawResult") or {}),
        )


def parse_target(target: str, default_port: Optional[int]) -> tuple[str, int]:
    t = (target or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.rstrip("/")
    port = default_port or 443
    if ":" in t:
        parts = t.rsplit(":", 1)
        try:
            port = int(parts[1])
            t = parts[0]
        except ValueError:
            pass
    return t, port


def _port_available(
    host: str,
    port: int,
    timeout: float,
    *,
    pinned_target: PinnedTarget | None = None,
) -> bool:
    try:
        with open_target_connection(
            host,
            port,
            min(timeout, 3.0),
            pinned_target=pinned_target,
        ):
            return True
    except OSError:
        return False


def select_port(
    host: str,
    port: int,
    alternate_ports: list[int],
    timeout: float,
    *,
    pinned_target: PinnedTarget | None = None,
) -> tuple[int, bool]:
    """Fase 2: si el puerto principal (443) falla, prueba los alternativos."""
    if not alternate_ports or port != 443:
        return port, False
    if port_available(host, port, timeout, pinned_target=pinned_target):
        return port, False
    for alt in alternate_ports:
        if port_available(host, alt, timeout, pinned_target=pinned_target):
            return alt, True
    return port, False


def port_available(
    host: str,
    port: int,
    timeout: float,
    *,
    pinned_target: PinnedTarget | None = None,
) -> bool:
    return _port_available(host, port, timeout, pinned_target=pinned_target)


def fetch_chain(
    host: str,
    port: int,
    timeout: float,
    handshake=None,
    *,
    pinned_target: PinnedTarget | None = None,
):
    # Reuse cert data already captured during handshake (avoids extra TLS connection)
    if handshake and handshake.peer_cert_chain_der:
        chain = []
        for der in handshake.peer_cert_chain_der:
            try:
                chain.append(analyze_certificate_from_der(der))
            except Exception:
                continue
        if chain:
            return chain
    if handshake and handshake.peer_cert_der:
        try:
            return [analyze_certificate_from_der(handshake.peer_cert_der)]
        except Exception:
            pass
    # Fallback: open a new connection only if handshake didn't capture certs
    return fetch_certificate_chain(
        host, port, timeout, pinned_target=pinned_target
    )


def guess_service(port: int) -> str:
    """Inferir nombre de servicio desde el puerto para banner parsing."""
    port_map = {
        443: "https", 8443: "https", 4443: "https",
        80: "http", 8080: "http", 8000: "http",
        22: "ssh", 25: "smtp",
    }
    return port_map.get(port, "https")


def build_fingerprint(
    host: str,
    port: int,
    handshake,
    timeout: float,
    *,
    pinned_target: PinnedTarget | None = None,
) -> ServiceFingerprint:
    """Construye el fingerprint completo: banner grabbing + JA3/JA3S."""
    # Nivel 1: JA3/JA3S desde datos crudos del handshake
    tls_fp = fingerprint_from_handshake(
        client_hello_raw=handshake.raw_client_hello if handshake else None,
        server_hello_raw=handshake.raw_server_hello if handshake else None,
    )

    # Nivel 2: Banner grabbing
    banner_fp = ServiceFingerprint(detected=False)
    service = guess_service(port)
    https_ports = {443, 8443, 4443}
    try:
        if port in https_ports:
            # HTTPS: hacer peticion TLS + HTTP para leer header Server:
            banner = grab_https_banner(
                host,
                port,
                timeout=min(timeout, 5.0),
                pinned_target=pinned_target,
            )
            if banner:
                banner_fp = fingerprint_from_banner(service, banner)
        else:
            # HTTP/SSH/SMTP: banner TCP crudo
            banner = grab_banner(
                host,
                port,
                timeout=min(timeout, 3.0),
                pinned_target=pinned_target,
            )
            if banner:
                banner_fp = fingerprint_from_banner(service, banner)
    except Exception:
        pass

    if banner_fp.detected:
        return ServiceFingerprint(
            detected=True,
            method=banner_fp.method,
            software_name=banner_fp.software_name,
            software_version=banner_fp.software_version,
            os_family=None,
            confidence=banner_fp.confidence,
            raw_banner=banner_fp.raw_banner,
            ja3_hash=tls_fp.ja3_hash,
            ja3s_hash=tls_fp.ja3s_hash,
        )
    if tls_fp.detected:
        return tls_fp

    return ServiceFingerprint(detected=False)


def _default_fingerprint_dto() -> dict:
    return {
        "detected": False, "os": None, "service": None, "banner": None,
        "confidence": None,
        "note": (
            "OS/service fingerprinting is not available in this stage; "
            "it is a planned capability tied to Network Discovery."
        ),
    }


def analyze_target(
    target: str,
    options: Optional[dict] = None,
    *,
    port: Optional[int] = None,
    pinned_target: PinnedTarget | None = None,
) -> AnalysisResult:
    """Pipeline puro: puerto -> handshake -> cert -> reglas -> fingerprint -> score.

    No toca la base de datos. Devuelve un ``AnalysisResult`` serializable.
    """
    opts = options or {}
    profile = opts.get("profile") or nist.DEFAULT_PROFILE
    if profile not in (nist.PROFILE_CITIZEN_FACING, nist.PROFILE_GOVERNMENT_ONLY):
        profile = nist.DEFAULT_PROFILE
    timeout = float(opts.get("timeout") or DEFAULT_TIMEOUT)
    alternate_ports = list(opts.get("alternatePorts") or [])

    host, parsed_port = parse_target(target, port)
    effective_port, port_is_alternate = select_port(
        host,
        parsed_port,
        alternate_ports,
        timeout,
        pinned_target=pinned_target,
    )

    started_at = datetime.now(timezone.utc)
    start = time.perf_counter()

    handshake = analyze_handshake(
        host, effective_port, timeout, pinned_target=pinned_target
    )
    h = handshake.to_dict() if handshake else {}

    if handshake is not None and handshake.connection_error:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return AnalysisResult(
            host=host,
            port=effective_port,
            port_is_alternate=port_is_alternate,
            profile=profile,
            score=EngineScanResult(host=host, port=effective_port).score,
            status="failed",
            started_at=started_at.isoformat(),
            duration_ms=duration_ms,
            connection_error=handshake.connection_error,
            ip_address=h.get("ip_address", ""),
            negotiated_protocol=h.get("negotiated_protocol", ""),
            negotiated_cipher=h.get("negotiated_cipher", ""),
            supported_protocols=h.get("supported_protocols", []),
            findings=[],
            certificate=serializers.empty_certificate_dto(),
            chain=[],
            handshake=h,
            os_fingerprint=_default_fingerprint_dto(),
            fingerprint={},
            raw_result=EngineScanResult(host=host, port=effective_port, handshake=handshake).to_dict(),
        )

    chain_objs = fetch_chain(
        host,
        effective_port,
        timeout,
        handshake,
        pinned_target=pinned_target,
    )
    engine_result = engine_scan(handshake, chain_objs, host, profile)
    duration_ms = int((time.perf_counter() - start) * 1000)

    detection_date = started_at.isoformat()
    findings_dtos = [
        serializers.finding_dto(f.to_dict(), host, detection_date)
        for f in engine_result.findings
    ]
    leaf = engine_result.certificate_chain[0].to_dict() if engine_result.certificate_chain else {}
    certificate = serializers.certificate_dto(leaf, host) if leaf else serializers.empty_certificate_dto()
    chain = [serializers.certificate_dto(c.to_dict(), host) for c in engine_result.certificate_chain]

    fp = build_fingerprint(
        host,
        effective_port,
        handshake,
        timeout,
        pinned_target=pinned_target,
    )

    raw_result = engine_result.to_dict()
    raw_result["fingerprint"] = fp.to_dict()

    return AnalysisResult(
        host=host,
        port=effective_port,
        port_is_alternate=port_is_alternate,
        profile=profile,
        score=engine_result.score,
        status="completed",
        started_at=detection_date,
        duration_ms=duration_ms,
        connection_error=None,
        ip_address=h.get("ip_address", ""),
        negotiated_protocol=h.get("negotiated_protocol", ""),
        negotiated_cipher=h.get("negotiated_cipher", ""),
        supported_protocols=h.get("supported_protocols", []),
        findings=findings_dtos,
        certificate=certificate,
        chain=chain,
        handshake=h,
        os_fingerprint=fp.to_frontend_dto(),
        fingerprint=fp.to_dict(),
        raw_result=raw_result,
        _fingerprint=fp,
    )
