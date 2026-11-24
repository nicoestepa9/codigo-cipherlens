"""Serializadores del motor de analisis hacia el contrato de la API (camelCase).

Convierte los objetos del motor (snake_case, severidad NIST en mayuscula) en
DTOs que replican exactamente las interfaces TypeScript del frontend
CryptoGuard (ScanResult, CertificateInfo, Finding, CipherSuite, etc.).

Reglas centrales:
- Severidad interna ``CRITICAL/HIGH/MEDIUM/LOW/INFO/NOT_EVALUABLE`` se expone
  en minuscula. ``NOT_EVALUABLE`` no se pierde: se expone como ``severity: info``
  junto con el booleano ``evaluable: false``.
- ``id`` es un UUID asignado en la capa de persistencia.
- Los datos que el motor no produce (osFingerprint, handshakeSteps) se exponen
  como ``detected: false`` / ``[]`` con una nota honesta de la limitacion.
"""

from __future__ import annotations

import time
from typing import Any

from .cve_mapping import get_static_cves_for_rule
from .scanner import ScanResult as EngineScanResult

# Severidad NIST -> severidad del frontend
SEV_API = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "NOT_EVALUABLE": "info",
}

SCORE_SECURE = 80
SCORE_WARNING = 50
CERT_EXPIRING_DAYS = 30

_OS_FINGERPRINT_NOTE = (
    "OS/service fingerprinting is not available in this stage; "
    "it is a planned capability tied to Network Discovery."
)


def score_to_status(score: int) -> str:
    """Traduce el score (0-100) al estado del frontend."""
    if score >= SCORE_SECURE:
        return "secure"
    if score >= SCORE_WARNING:
        return "warning"
    return "critical"


def cert_status(cert: dict) -> str:
    """Estado de un certificado: expired | expiring_soon | valid."""
    if cert.get("is_expired", cert.get("isExpired")):
        return "expired"
    days = cert.get("days_until_expiry", cert.get("daysUntilExpiry", 999))
    if days <= CERT_EXPIRING_DAYS:
        return "expiring_soon"
    return "valid"


def _group_name(group: str) -> str:
    """Extrae el nombre de grupo de '0x001d (x25519)'."""
    if not group:
        return ""
    if "(" in group:
        return group.split("(")[-1].rstrip(")").strip()
    return group.split(" ")[0].strip()


def derive_key_exchange(handshake: dict) -> str:
    """Deriva el key exchange del handshake (grupo key_share, kea o nombre)."""
    she = handshake.get("server_hello_extensions") or {}
    for ext in she.get("extensions", []):
        if ext.get("type_name") == "key_share":
            name = _group_name(ext.get("group", ""))
            if name and "unknown" not in name:
                return name
    negotiated = handshake.get("negotiated_cipher", "")
    for suite in handshake.get("accepted_cipher_suites", []):
        if suite.get("name") == negotiated and suite.get("kea"):
            return str(suite["kea"]).upper()
    name = negotiated.upper()
    if not name:
        return ""
    for prefix in ("ECDHE", "DHE", "ECDH", "RSA"):
        if name.startswith(prefix) or f"_{prefix}_" in name or prefix in name:
            return prefix
    return ""


def derive_encryption(suite_name: str) -> str:
    """Deriva el algoritmo de cifrado desde el nombre de la suite."""
    n = suite_name.upper()
    if "CHACHA20" in n:
        return "ChaCha20-Poly1305"
    if "3DES" in n:
        return "3DES-EDE-CBC"
    alg = "AES-256" if "AES256" in n else "AES-128" if "AES128" in n else ""
    if "GCM" in n:
        return f"{alg}-GCM"
    if "CCM" in n:
        return f"{alg}-CCM"
    if "CBC" in n:
        return f"{alg}-CBC"
    return alg


def cipher_status(suite: dict) -> str:
    """Clasifica una suite como secure | warning | critical."""
    name = (suite.get("name") or "").upper()
    proto = suite.get("protocol") or ""
    kea = (suite.get("kea") or "").upper()
    mac = (suite.get("mac") or "").upper()
    if any(weak in name for weak in ("3DES", "RC4", "DES-CBC3", "NULL", "EXPORT")):
        return "critical"
    if kea == "RSA" or name.startswith("TLS_RSA_WITH"):
        return "critical"
    if "TLS 1.0" in proto or "TLS 1.1" in proto:
        return "warning"
    if "CBC" in name and "GCM" not in name and "CCM" not in name:
        return "warning"
    if "SHA1" in name or mac == "SHA1":
        return "warning"
    return "secure"


def finding_dto(f: dict, host: str, detection_date: str) -> dict:
    """Convierte un finding del motor al contrato del frontend."""
    details = f.get("details") or {}
    raw_sev = f.get("severity", "INFO")
    rule_ids = list(details.get("rule_ids") or [])
    standards = list(details.get("standards") or [])
    section = f.get("section_reference") or ""
    evidence = f.get("observed_value") or ""
    rule_id = f.get("id") or ""
    return {
        "id": rule_id,
        "ruleId": rule_id,
        "title": f.get("title") or "",
        "description": f.get("description") or "",
        "evidence": evidence,
        "recommendation": f.get("recommendation") or "",
        "reference": section,
        "severity": SEV_API.get(raw_sev, "info"),
        "category": f.get("category") or "",
        "affectedHost": host,
        "affectedService": None,
        "detectionDate": detection_date,
        # Extras que el motor ya calcula y no hay que perder
        "citation": f.get("citation") or "",
        "observedValue": evidence,
        "sectionReference": section,
        "sourceDocument": details.get("standard"),
        "standards": standards,
        "ruleIds": rule_ids,
        "evaluable": raw_sev != "NOT_EVALUABLE",
        "status": details.get("status"),
        # CVEs estáticos del mapping
        "relatedCves": [
            {"cveId": e.cve_id, "name": e.name, "matchType": "static_mapping",
             "referenceUrl": f"https://nvd.nist.gov/vuln/detail/{e.cve_id}"}
            for e in get_static_cves_for_rule(rule_id)
        ],
    }


def certificate_dto(cert: dict, host: str = "") -> dict:
    """Convierte CertificateInfo del motor al contrato del frontend."""
    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}
    san = cert.get("san") or []
    domain = san[0] if san else subject.get("CN") or host
    return {
        "id": cert.get("fingerprint_sha256", cert.get("fingerprintSha256", "")),
        "domain": domain,
        "commonName": subject.get("CN", ""),
        "subject": subject,
        "issuerName": issuer.get("CN", ""),
        "issuer": issuer,
        "serialNumber": cert.get("serial_number", cert.get("serialNumber", "")),
        "notBefore": cert.get("not_before", cert.get("notBefore", "")),
        "notAfter": cert.get("not_after", cert.get("notAfter", "")),
        "daysUntilExpiry": cert.get("days_until_expiry", cert.get("daysUntilExpiry", 0)),
        "isExpired": bool(cert.get("is_expired", cert.get("isExpired", False))),
        "san": san,
        "keyType": cert.get("key_type", cert.get("keyType", "")),
        "keySize": cert.get("key_size", cert.get("keySize", 0)),
        "signatureAlgorithm": cert.get(
            "signature_algorithm", cert.get("signatureAlgorithm", "")
        ),
        "fingerprintSha256": cert.get(
            "fingerprint_sha256", cert.get("fingerprintSha256", "")
        ),
        "fingerprintSha1": cert.get(
            "fingerprint_sha1", cert.get("fingerprintSha1", "")
        ),
        "isSelfSigned": bool(
            cert.get("is_self_signed", cert.get("isSelfSigned", False))
        ),
        "basicConstraints": cert.get(
            "basic_constraints", cert.get("basicConstraints", "")
        ),
        "keyUsage": cert.get("key_usage", cert.get("keyUsage", [])),
        "extendedKeyUsage": cert.get(
            "extended_key_usage", cert.get("extendedKeyUsage", [])
        ),
        "caIssuers": cert.get("ca_issuers", cert.get("caIssuers", [])),
        "crlDistributionPoints": cert.get(
            "crl_distribution_points", cert.get("crlDistributionPoints", [])
        ),
        "ocspMustStaple": bool(
            cert.get("ocsp_must_staple", cert.get("ocspMustStaple", False))
        ),
        "status": cert_status(cert),
        "origin": "discovered",
        "serviceId": None,
        "serviceName": None,
    }


def empty_certificate_dto() -> dict:
    """Certificado vacio para scans sin cadena (p. ej. connection failed)."""
    return {
        "id": "", "domain": "", "commonName": "", "subject": {}, "issuerName": "",
        "issuer": {}, "serialNumber": "", "notBefore": "", "notAfter": "",
        "daysUntilExpiry": 0, "isExpired": False, "san": [], "keyType": "",
        "keySize": 0, "signatureAlgorithm": "", "fingerprintSha256": "",
        "fingerprintSha1": "", "isSelfSigned": False, "basicConstraints": "",
        "keyUsage": [], "extendedKeyUsage": [], "caIssuers": [],
        "crlDistributionPoints": [], "ocspMustStaple": False,
        "status": "unknown", "origin": "discovered", "serviceId": None,
        "serviceName": None,
    }


def cipher_suites_dto(handshake: dict, negotiated_cipher: str) -> list[dict]:
    """Lista de cipher suites aceptadas en el contrato del frontend."""
    suites = []
    for suite in handshake.get("accepted_cipher_suites", []):
        name = suite.get("name", "")
        suites.append({
            "name": name,
            "protocol": suite.get("protocol", ""),
            "keyExchange": (suite.get("kea") or "").upper(),
            "encryption": derive_encryption(name),
            "mac": suite.get("mac", ""),
            "bits": suite.get("bits", 0),
            "status": cipher_status(suite),
            "selected": name == negotiated_cipher,
        })
    return suites


def scan_result_dto(
    scan_result: EngineScanResult,
    *,
    scan_id: str,
    target: str,
    scan_started_at: str,
    scan_duration_ms: int,
    ai_recommendation: str = "",
    port_is_alternate: bool = False,
    fingerprint: Any = None,
    keyword_matches: list[dict] | None = None,
    cpe_matches: list[dict] | None = None,
    cpe_name_used: str | None = None,
) -> dict:
    """Convierte un ScanResult del motor en el ScanResult del frontend."""
    handshake = scan_result.handshake
    h = handshake.to_dict() if handshake else {}
    connection_error = h.get("connection_error") if h else None

    leaf = scan_result.certificate_chain[0].to_dict() if scan_result.certificate_chain else {}
    certificate = certificate_dto(leaf, scan_result.host) if leaf else empty_certificate_dto()
    chain = [certificate_dto(c.to_dict(), scan_result.host) for c in scan_result.certificate_chain]

    negotiated_protocol = h.get("negotiated_protocol", "")
    negotiated_cipher = h.get("negotiated_cipher", "")

    # Fingerprint: usar el proporcionado o el default hardcodeado
    if fingerprint is not None:
        fp_dto = fingerprint.to_frontend_dto() if hasattr(fingerprint, "to_frontend_dto") else fingerprint
    else:
        fp_dto = {
            "detected": False, "os": None, "service": None, "banner": None,
            "confidence": None, "note": _OS_FINGERPRINT_NOTE,
        }

    return {
        "id": scan_id,
        "target": target,
        "host": scan_result.host,
        "port": scan_result.port,
        "portIsAlternate": port_is_alternate,
        "ipAddress": h.get("ip_address", ""),
        "scanStartedAt": scan_started_at,
        "scanDurationMs": scan_duration_ms,
        "profile": scan_result.profile,
        "score": scan_result.score,
        "status": score_to_status(scan_result.score),
        "negotiatedProtocol": negotiated_protocol,
        "negotiatedCipher": negotiated_cipher,
        "keyExchange": derive_key_exchange(h),
        "signatureAlgorithm": certificate.get("signatureAlgorithm", ""),
        "supportedProtocols": h.get("supported_protocols", []),
        "cipherSuites": cipher_suites_dto(h, negotiated_cipher),
        "certificate": certificate,
        "chain": chain,
        "findings": [
            finding_dto(f.to_dict(), scan_result.host, scan_started_at)
            for f in scan_result.findings
        ],
        "osFingerprint": fp_dto,
        "handshakeSteps": [],
        "aiRecommendation": ai_recommendation,
        "connectionError": connection_error,
        "liveCveMatches": keyword_matches or [],
        "softwareKnownCves": {
            "queried": cpe_name_used is not None,
            "cpeName": cpe_name_used,
            "matches": cpe_matches or [],
        },
    }


def scan_dto_from_analysis(
    analysis: Any,
    *,
    scan_id: str,
    target: str,
    scan_started_at: str = "",
    scan_duration_ms: int = 0,
    ai_recommendation: str = "",
    port_is_alternate: bool = False,
    fingerprint_dto: Any = None,
    keyword_matches: list[dict] | None = None,
    cpe_matches: list[dict] | None = None,
    cpe_name_used: str | None = None,
) -> dict:
    """Construye el ScanResult del frontend desde un AnalysisResult (dicts).

    Equivalente a ``scan_result_dto`` pero sin objetos del motor: se usa tanto
    en el camino local como en la ingesta del agente.
    """
    h = getattr(analysis, "handshake", None) or {}
    negotiated_cipher = h.get("negotiated_cipher", "")

    if fingerprint_dto is not None:
        fp_dto = fingerprint_dto
    else:
        fp_dto = getattr(analysis, "os_fingerprint", None) or {
            "detected": False, "os": None, "service": None, "banner": None,
            "confidence": None, "note": _OS_FINGERPRINT_NOTE,
        }

    return {
        "id": scan_id,
        "target": target,
        "host": analysis.host,
        "port": analysis.port,
        "portIsAlternate": port_is_alternate,
        "ipAddress": h.get("ip_address", ""),
        "scanStartedAt": scan_started_at or getattr(analysis, "started_at", ""),
        "scanDurationMs": scan_duration_ms or getattr(analysis, "duration_ms", 0),
        "profile": analysis.profile,
        "score": analysis.score,
        "status": score_to_status(analysis.score),
        "negotiatedProtocol": h.get("negotiated_protocol", ""),
        "negotiatedCipher": negotiated_cipher,
        "keyExchange": derive_key_exchange(h),
        "signatureAlgorithm": (getattr(analysis, "certificate", None) or {}).get("signatureAlgorithm", ""),
        "supportedProtocols": h.get("supported_protocols", []),
        "cipherSuites": cipher_suites_dto(h, negotiated_cipher),
        "certificate": getattr(analysis, "certificate", None) or empty_certificate_dto(),
        "chain": getattr(analysis, "chain", None) or [],
        "findings": getattr(analysis, "findings", None) or [],
        "osFingerprint": fp_dto,
        "handshakeSteps": [],
        "aiRecommendation": ai_recommendation,
        "connectionError": getattr(analysis, "connection_error", None),
        "liveCveMatches": keyword_matches or [],
        "softwareKnownCves": {
            "queried": cpe_name_used is not None,
            "cpeName": cpe_name_used,
            "matches": cpe_matches or [],
        },
    }


def history_entry_dto(scan_row: Any) -> dict:
    """Convierte un Scan persistido en HistoryEntry del frontend."""
    return {
        "id": scan_row.id,
        "target": scan_row.target,
        "host": scan_row.host,
        "port": scan_row.port,
        "kind": "tls_scan",
        "date": _iso(scan_row.started_at),
        "score": None if scan_row.status == "failed" else scan_row.score,
        "durationMs": scan_row.duration_ms or 0,
        "status": "failed" if scan_row.status == "failed" else "running" if scan_row.status == "running" else "completed",
        "profile": scan_row.profile,
        "origin": getattr(scan_row, "origin", None),
        "agentId": getattr(scan_row, "agent_id", None),
        "uploadLevel": getattr(scan_row, "upload_level", None),
    }


def _iso(dt: Any) -> str:
    if dt is None:
        return ""
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)


def measure_duration(func: Any) -> tuple[Any, int]:
    """Ejecuta func() y devuelve (resultado, duracion_ms)."""
    start = time.perf_counter()
    result = func()
    duration_ms = int((time.perf_counter() - start) * 1000)
    return result, duration_ms


def paged(items: list, total: int, page: int, page_size: int) -> dict:
    """Contenedor de paginacion del frontend: {items, total, page, pageSize}."""
    return {"items": items, "total": total, "page": page, "pageSize": page_size}
