"""NIST SP 800-52 Rev.2 compliance detector.

Evalua un JSON de resultados de handshake TLS (formato de escaneo de
tls-analyzer) contra las reglas de NIST SP 800-52 Rev.2 ("Guidelines for the
Selection, Configuration, and Use of Transport Layer Security (TLS)
Implementations", agosto 2019).

Cada regla esta implementada como una funcion pura que recibe el JSON parseado
y un perfil de aplicacion, y devuelve cero o mas findings. Cada finding cita la
seccion exacta del documento para mantener trazabilidad.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from .crypto_strength import normalize_cipher_name, resolve_evaluation_date

PROFILE_CITIZEN_FACING = "citizen-facing"
PROFILE_GOVERNMENT_ONLY = "government-only"
DEFAULT_PROFILE = PROFILE_CITIZEN_FACING

EVALUATED_AGAINST = "NIST SP 800-52 Rev.2 (Aug 2019)"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_INFO = "INFO"
SEVERITY_NOT_EVALUABLE = "NOT_EVALUABLE"

SEVERITY_ORDER = (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_INFO,
    SEVERITY_NOT_EVALUABLE,
)

# Severidad segun la palabra clave normativa del documento (Seccion 2 del spec).
_SEVERITY_FOR = {
    SEVERITY_CRITICAL: SEVERITY_CRITICAL,
    SEVERITY_HIGH: SEVERITY_HIGH,
    SEVERITY_MEDIUM: SEVERITY_MEDIUM,
    SEVERITY_INFO: SEVERITY_INFO,
}

# ---------------------------------------------------------------------------
# Helpers de datos
# ---------------------------------------------------------------------------

_PROTO_NORMALIZE = {
    "sslv2": "SSL 2.0",
    "sslv3": "SSL 3.0",
    "tlsv1": "TLS 1.0",
    "tlsv1.0": "TLS 1.0",
    "tls1.0": "TLS 1.0",
    "tls 1.0": "TLS 1.0",
    "tlsv1.1": "TLS 1.1",
    "tls1.1": "TLS 1.1",
    "tls 1.1": "TLS 1.1",
    "tlsv1.2": "TLS 1.2",
    "tls1.2": "TLS 1.2",
    "tls 1.2": "TLS 1.2",
    "tlsv1.3": "TLS 1.3",
    "tls1.3": "TLS 1.3",
    "tls 1.3": "TLS 1.3",
}

_PROTO_ORDER = {
    "SSL 2.0": (2, 0),
    "SSL 3.0": (3, 0),
    "TLS 1.0": (3, 1),
    "TLS 1.1": (3, 2),
    "TLS 1.2": (3, 3),
    "TLS 1.3": (3, 4),
}


def _norm_proto(proto: Any) -> str:
    return _PROTO_NORMALIZE.get(str(proto).strip().lower(), str(proto).strip())


def _proto_tuple(proto: Any):
    return _PROTO_ORDER.get(_norm_proto(proto))


def _proto_at_least(proto: Any, ref: str) -> bool:
    t = _proto_tuple(proto)
    r = _proto_tuple(ref)
    return t is not None and r is not None and t >= r


def _proto_at_most(proto: Any, ref: str) -> bool:
    t = _proto_tuple(proto)
    r = _proto_tuple(ref)
    return t is not None and r is not None and t <= r


def _proto_below(proto: Any, ref: str) -> bool:
    t = _proto_tuple(proto)
    r = _proto_tuple(ref)
    return t is not None and r is not None and t < r


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _leaf_cert(data: dict) -> dict:
    chain = data.get("certificate_chain") or []
    if not chain:
        return {}
    return chain[0] if isinstance(chain[0], dict) else {}


def _curve_name(key_type: Any) -> str:
    key_type = str(key_type or "")
    if "(" in key_type and ")" in key_type:
        return key_type[key_type.index("(") + 1 : key_type.index(")")].strip()
    return key_type.strip()


def _negotiated_cipher(data: dict) -> str:
    return normalize_cipher_name(str((data.get("handshake") or {}).get("negotiated_cipher") or ""))


def _cipher_pool(data: dict) -> set[str]:
    handshake = data.get("handshake") or {}
    names = {
        normalize_cipher_name(str(suite.get("name") or ""))
        for suite in (handshake.get("accepted_cipher_suites") or [])
        if isinstance(suite, dict)
    }
    names.add(_negotiated_cipher(data))
    return names - {""}


def _negotiated_proto(data: dict) -> str:
    return _norm_proto((data.get("handshake") or {}).get("negotiated_protocol"))


def _extension_types(data: dict) -> list[int]:
    she = (data.get("handshake") or {}).get("server_hello_extensions") or {}
    exts = she.get("extensions") if isinstance(she, dict) else None
    if not exts:
        return []
    types = []
    for e in exts:
        if isinstance(e, dict):
            t = e.get("type")
            if isinstance(t, int):
                types.append(t)
    return types


def _compression_method(data: dict) -> Any:
    she = (data.get("handshake") or {}).get("server_hello_extensions") or {}
    if isinstance(she, dict):
        return she.get("compression_method")
    return None


# ---------------------------------------------------------------------------
# Tipos de extension TLS
# ---------------------------------------------------------------------------

EXT_RENEGOTIATION_INFO = 0xFF01
EXT_EXTENDED_MASTER_SECRET = 0x0023
EXT_STATUS_REQUEST = 0x0005
EXT_SUPPORTED_GROUPS = 0x000A
EXT_KEY_SHARE = 0x0033
EXT_ENCRYPT_THEN_MAC = 0x0016
EXT_CLIENT_CERTIFICATE_URL = 0x0002
EXT_CLIENT_CERTIFICATE_TYPE = 0x0013
EXT_SERVER_CERTIFICATE_TYPE = 0x0014
EXT_EARLY_DATA = 0x002A

# ---------------------------------------------------------------------------
# Cipher suites permitidas por NIST SP 800-52 Rev.2
# ---------------------------------------------------------------------------

# Seccion 3.3.1.2: unicos 4 cipher suites TLS 1.3 aceptables.
TLS13_ALLOWED = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
}

# Seccion 3.3.1.1 + Apendice C: suites TLS 1.2 aprobadas (nombres OpenSSL e IANA).
TLS12_ALLOWED = {
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES256-SHA256",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "DHE-RSA-CHACHA20-POLY1305",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

# Apendice D: suites con RSA key transport, aceptables solo en periodo de transicion.
TLS12_RSA_KEY_TRANSPORT = {
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA256",
    "AES256-SHA256",
    "AES128-SHA",
    "AES256-SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
}

ALLOWED_CIPHERS = TLS13_ALLOWED | TLS12_ALLOWED | TLS12_RSA_KEY_TRANSPORT

# Orden de preferencia NIST para TLS 1.3 (mas fuerte primero).
_TLS13_RANK = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_128_CCM_SHA256",
]


def _is_tls13_cipher(name: str) -> bool:
    return name in TLS13_ALLOWED or name.startswith("TLS_") and "AES_128_CCM" in name


def _cipher_tls13_rank(name: str) -> int:
    return _TLS13_RANK.index(name) if name in _TLS13_RANK else len(_TLS13_RANK)


# ---------------------------------------------------------------------------
# Reglas de deteccion
# ---------------------------------------------------------------------------

Finding = dict


def _mkfinding(
    rule_id: str,
    title: str,
    severity: str,
    section: str,
    citation: str,
    observed_value: str,
    recommendation: str,
    status: str | None = None,
) -> Finding:
    finding = {
        "id": rule_id,
        "title": title,
        "severity": severity,
        "section_reference": section,
        "citation": citation,
        "observed_value": observed_value,
        "recommendation": recommendation,
    }
    if status is not None:
        finding["status"] = status
    return finding


def _not_evaluable(rule_id: str, title: str, section: str, citation: str, reason: str) -> Finding:
    finding = _mkfinding(
        rule_id,
        title,
        SEVERITY_NOT_EVALUABLE,
        section,
        citation,
        f"Informacion insuficiente: {reason}",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    )
    finding["status"] = SEVERITY_NOT_EVALUABLE
    return finding


def _check_proto(data: dict, profile: str) -> list[Finding]:
    """Seccion 3.1 - versiones de protocolo."""
    findings = []
    supported = [_norm_proto(p) for p in ((data.get("handshake") or {}).get("supported_protocols") or [])]
    observed = f"supported_protocols = {supported}"

    if "SSL 2.0" in supported or "SSL 3.0" in supported:
        findings.append(_mkfinding(
            "PROTO-01",
            "SSL 2.0/3.0 habilitado",
            SEVERITY_CRITICAL,
            "SP 800-52 Rev.2, Section 3.1",
            "shall not use TLS 1.0, SSL 3.0, or SSL 2.0",
            observed,
            "Deshabilitar SSL 2.0 y SSL 3.0 por completo.",
        ))

    if "TLS 1.0" in supported:
        if profile == PROFILE_GOVERNMENT_ONLY:
            findings.append(_mkfinding(
                "PROTO-03",
                "TLS 1.0 habilitado (perfil government-only)",
                SEVERITY_HIGH,
                "SP 800-52 Rev.2, Section 3.1",
                "shall not use TLS 1.0",
                observed,
                "Deshabilitar TLS 1.0.",
            ))
        else:
            findings.append(_mkfinding(
                "PROTO-02",
                "TLS 1.0 habilitado",
                SEVERITY_MEDIUM,
                "SP 800-52 Rev.2, Section 3.1",
                "use of TLS versions 1.1 and 1.0 is generally discouraged",
                observed,
                "Deshabilitar TLS 1.0 salvo justificacion de interoperabilidad (Apendice F).",
            ))

    if profile == PROFILE_GOVERNMENT_ONLY and "TLS 1.1" in supported:
        findings.append(_mkfinding(
            "PROTO-03",
            "TLS 1.1 habilitado (perfil government-only)",
            SEVERITY_HIGH,
            "SP 800-52 Rev.2, Section 3.1",
            "should not be configured to use TLS 1.1",
            observed,
            "Deshabilitar TLS 1.1.",
        ))

    if "TLS 1.2" not in supported:
        findings.append(_mkfinding(
            "PROTO-04",
            "TLS 1.2 ausente",
            SEVERITY_CRITICAL,
            "SP 800-52 Rev.2, Section 3.1",
            "shall be configured to negotiate TLS 1.2",
            observed,
            "Habilitar TLS 1.2 como minimo obligatorio.",
        ))

    if "TLS 1.3" not in supported:
        findings.append(_mkfinding(
            "PROTO-05",
            "TLS 1.3 ausente",
            SEVERITY_MEDIUM,
            "SP 800-52 Rev.2, Section 3.1",
            "shall support TLS 1.3 by January 1, 2024",
            observed,
            "Habilitar TLS 1.3 (obligatorio desde el 1 de enero de 2024).",
        ))

    if supported:
        findings.append(_not_evaluable(
            "PROTO-06",
            "Negociacion de version no verificable",
            "SP 800-52 Rev.2, Section 3.1",
            "Servers that incorrectly implement TLS version negotiation shall not be used",
            "requiere prueba activa de version negotiation, no deducible de un JSON unico.",
        ))

    return findings


def _check_cert(data: dict, profile: str) -> list[Finding]:
    """Seccion 3.2 / 3.2.1 (Tabla 3-1) - certificado del servidor."""
    cert = _leaf_cert(data)
    if not cert:
        return []

    findings = []

    if cert.get("is_expired"):
        findings.append(_mkfinding(
            "CERT-01",
            "Certificado expirado",
            SEVERITY_CRITICAL,
            "SP 800-52 Rev.2, Table 3-1",
            "Validity period must be current",
            f"not_after = {cert.get('not_after')}",
            "Renovar el certificado inmediatamente.",
        ))

    nb = _parse_date(cert.get("not_before"))
    na = _parse_date(cert.get("not_after"))
    if nb and na and (na - nb).days > 3 * 365:
        findings.append(_mkfinding(
            "CERT-02",
            "Vigencia mayor a 3 anios",
            SEVERITY_MEDIUM,
            "SP 800-52 Rev.2, Table 3-1",
            "Validity Period: 3 years or less",
            f"not_before={cert.get('not_before')} not_after={cert.get('not_after')}",
            "Emitir certificados con vigencia de 3 anios o menos.",
        ))

    key_type = str(cert.get("key_type") or "")
    key_size = cert.get("key_size") or 0

    if "RSA" in key_type and isinstance(key_size, int) and 0 < key_size < 2048:
        findings.append(_mkfinding(
            "CERT-03",
            "Clave RSA menor a 2048 bits",
            SEVERITY_CRITICAL,
            "SP 800-52 Rev.2, Table 3-1",
            "2048-bit RSA key modulus or other approved lengths",
            f"key_type={key_type} key_size={key_size}",
            "Usar claves RSA de al menos 2048 bits.",
        ))

    if "EC" in key_type:
        curve = _curve_name(key_type).lower().replace(" ", "")
        if curve and curve not in {"secp256r1", "secp384r1", "p-256", "p-384"}:
            findings.append(_mkfinding(
                "CERT-04",
                "Curva EC no aprobada",
                SEVERITY_HIGH,
                "SP 800-52 Rev.2, Section 3.2",
                "either curve P-256 or curve P-384 should be used",
                f"key_type={key_type}",
                "Usar P-256 o P-384.",
            ))

    strength_bits = 0
    if "RSA" in key_type or "DSA" in key_type:
        # RSA/DSA: ~112 bits de seguridad equivale a un modulo de 2048 bits.
        strength_bits = key_size if isinstance(key_size, int) else 0
        below_112 = 0 < strength_bits < 2048
    elif "EC" in key_type or "Ed" in key_type or "DH" in key_type:
        # Curvas prime: la seguridad en bits es ~mitad del tamano (P-224 = 112).
        strength_bits = key_size if isinstance(key_size, int) else 0
        below_112 = 0 < strength_bits < 224
    else:
        below_112 = False
    sig = str(cert.get("signature_algorithm") or "").lower()
    if below_112:
        findings.append(_mkfinding(
            "CERT-05",
            "Fuerza de clave menor a 112 bits",
            SEVERITY_CRITICAL,
            "SP 800-52 Rev.2, Section 3.2.1",
            "public key and signature shall provide at least 112 bits of security",
            f"key_type={key_type} key_size={key_size}",
            "Usar claves con al menos 112 bits de seguridad equivalente.",
        ))

    if "md5" in sig or "sha1" in sig or "sha-1" in sig:
        findings.append(_mkfinding(
            "CERT-06",
            "Firma con MD5 o SHA-1",
            SEVERITY_CRITICAL,
            "SP 800-52 Rev.2, Table 3-1",
            "only sha256WithRSAEncryption or stronger signatures allowed",
            f"signature_algorithm = {cert.get('signature_algorithm')}",
            "Reemplazar la firma por sha256WithRSAEncryption, ecdsa-with-SHA256 o superior.",
        ))

    if not cert.get("san"):
        findings.append(_mkfinding(
            "CERT-07",
            "Sin Subject Alternative Names",
            SEVERITY_HIGH,
            "SP 800-52 Rev.2, Table 3-1",
            "SAN: Required",
            f"san = {cert.get('san')}",
            "Agregar el/los hostname/s al campo SAN del certificado.",
        ))

    eku = cert.get("extended_key_usage") or []
    if eku and not any("serverAuth" in str(e) for e in eku):
        findings.append(_mkfinding(
            "CERT-08",
            "Extended Key Usage sin serverAuth",
            SEVERITY_MEDIUM,
            "SP 800-52 Rev.2, Table 3-1",
            "id-kp-serverAuth ... Required",
            f"extended_key_usage = {eku}",
            "Incluir id-kp-serverAuth (1.3.6.1.5.5.7.3.1) en el EKU.",
        ))

    if "ocsp_responders" in cert:
        if not cert.get("ocsp_responders"):
            findings.append(_mkfinding(
                "CERT-09",
                "Sin fuente de revocacion (OCSP)",
                SEVERITY_HIGH,
                "SP 800-52 Rev.2, Section 3.2",
                "CA shall publish revocation information in OCSP responses",
                f"ocsp_responders = {cert.get('ocsp_responders')}",
                "Configurar un responder OCSP en el AIA del certificado.",
            ))
    else:
        findings.append(_not_evaluable(
            "CERT-09",
            "Fuente de revocacion (OCSP) no verificable",
            "SP 800-52 Rev.2, Section 3.2",
            "certificates issued by a CA that publishes revocation information in OCSP responses",
            "el JSON no incluye el campo ocsp_responders.",
        ))

    if "ca_issuers" in cert:
        if not cert.get("ca_issuers"):
            findings.append(_mkfinding(
                "CERT-10",
                "Sin CA Issuers en AIA",
                SEVERITY_MEDIUM,
                "SP 800-52 Rev.2, Table 3-1",
                "Authority Information Access... Required",
                f"ca_issuers = {cert.get('ca_issuers')}",
                "Agregar el enlace al certificado del emisor en el AIA.",
            ))
    else:
        findings.append(_not_evaluable(
            "CERT-10",
            "CA Issuers en AIA no verificable",
            "SP 800-52 Rev.2, Table 3-1",
            "Authority Information Access... Required",
            "el JSON no incluye el campo ca_issuers.",
        ))

    if cert.get("is_self_signed"):
        findings.append(_mkfinding(
            "CERT-11",
            "Certificado autofirmado",
            SEVERITY_HIGH,
            "SP 800-52 Rev.2, Section 3.2.3",
            "certificates shall be issued by a trusted CA",
            f"is_self_signed = {cert.get('is_self_signed')}",
            "Usar un certificado emitido por una CA de confianza publica o propia gestionada.",
        ))

    bc = str(cert.get("basic_constraints") or "")
    if "CA=True" in bc:
        findings.append(_mkfinding(
            "CERT-12",
            "Basic Constraints CA=True en certificado hoja",
            SEVERITY_HIGH,
            "SP 800-52 Rev.2, Table 3-1",
            "end-entity certificate shall not assert CA capability",
            f"basic_constraints = {bc}",
            "Emitir el certificado hoja sin la capacidad de CA.",
        ))

    return findings


def _check_cipher(data: dict, profile: str) -> list[Finding]:
    """Seccion 3.3.1 - cipher suites."""
    findings = []
    handshake = data.get("handshake") or {}
    negotiated = _negotiated_cipher(data)
    proto = _negotiated_proto(data)
    rejected = [normalize_cipher_name(str(name)) for name in handshake.get("rejected_cipher_suites") or []]
    observed_negotiated = f"negotiated_cipher = {negotiated or '<none>'}"

    cipher_pool = _cipher_pool(data)

    if any("des" in c.lower() for c in cipher_pool):
        findings.append(_mkfinding(
            "CIPH-01",
            "3DES/DES en uso",
            SEVERITY_CRITICAL,
            "SP 800-52 Rev.2, Section 3.3.1.1",
            "3DES cipher suites are no longer allowed",
            f"cipher suites = {sorted(cipher_pool)}",
            "Remover todos los cipher suites 3DES/DES.",
        ))

    if negotiated and negotiated not in ALLOWED_CIPHERS:
        findings.append(_mkfinding(
            "CIPH-02",
            "Cipher suite negociada fuera de las listas permitidas",
            SEVERITY_HIGH,
            "SP 800-52 Rev.2, Section 3.3.1",
            "cipher suites not in this section, Appendix C, or Appendix D shall not be used",
            observed_negotiated,
            "Configurar solo cipher suites de la Seccion 3.3.1, Apendice C o D.",
        ))

    if negotiated and proto != "TLS 1.3":
        is_fs = "DHE" in negotiated.upper() or "ECDHE" in negotiated.upper()
        if not is_fs:
            findings.append(_mkfinding(
                "CIPH-03",
                "Sin Forward Secrecy",
                SEVERITY_HIGH,
                "SP 800-52 Rev.2, Section 3.3.1",
                "DHE/ECDHE preferred for perfect forward secrecy",
                observed_negotiated,
                "Priorizar cipher suites DHE/ECDHE.",
            ))

    key_share_group = _extract_key_share_group(data)
    weak_groups = {"secp192r1", "secp224r1", "secp160r1", "secp160k1", "secp160r2"}
    if key_share_group and any(g in key_share_group.lower() for g in weak_groups):
        findings.append(_mkfinding(
            "CIPH-04",
            "Clave efimera menor a 112 bits",
            SEVERITY_CRITICAL,
            "SP 800-52 Rev.2, Section 3.3.1",
            "each ephemeral key-pair shall have at least 112 bits of security",
            f"key_share group = {key_share_group}",
            "Usar grupos DHE/ECDHE con al menos 112 bits de seguridad.",
        ))

    if negotiated and _preference_violation(negotiated, rejected):
        findings.append(_mkfinding(
            "CIPH-05",
            "Preferencia de servidor no sigue el orden recomendado",
            SEVERITY_MEDIUM,
            "SP 800-52 Rev.2, Section 3.3.1.1",
            "prefer ECDHE/DHE, then GCM/CCM over CBC",
            f"negotiated={negotiated}, rejected={rejected}",
            "Configurar la preferencia: DHE/ECDHE, luego GCM/CCM antes que CBC.",
        ))

    if negotiated and proto != "TLS 1.3":
        if negotiated.upper().startswith("TLS_RSA_") or (
            not negotiated.upper().startswith("TLS_")
            and "DHE" not in negotiated.upper()
            and "ECDHE" not in negotiated.upper()
            and not negotiated.upper().startswith("PSK")
        ):
            findings.append(_mkfinding(
                "CIPH-06",
                "RSA key transport en uso",
                SEVERITY_HIGH,
                "SP 800-52 Rev.2, Appendix D",
                "this guideline does not recommend cipher suites that use RSA key transport",
                observed_negotiated,
                "Migrar a suites con DHE/ECDHE.",
            ))

    if negotiated and "CBC" in negotiated.upper():
        if EXT_ENCRYPT_THEN_MAC not in _extension_types(data):
            findings.append(_mkfinding(
                "CIPH-07",
                "CBC sin Encrypt-then-MAC",
                SEVERITY_MEDIUM,
                "SP 800-52 Rev.2, Section 3.4.2.7",
                "servers negotiating CBC shall support encrypt_then_mac",
                observed_negotiated,
                "Soportar la extension encrypt_then_mac (0x0016) o eliminar CBC.",
            ))

    if proto == "TLS 1.3" and negotiated and negotiated not in TLS13_ALLOWED:
        findings.append(_mkfinding(
            "CIPH-08",
            "Cipher TLS 1.3 fuera de la lista permitida",
            SEVERITY_HIGH,
            "SP 800-52 Rev.2, Section 3.3.1.2",
            "only four TLS 1.3 cipher suites are acceptable",
            observed_negotiated,
            "Usar una de las 4 suites TLS 1.3 permitidas.",
        ))

    return findings


def _extract_key_share_group(data: dict) -> str:
    she = (data.get("handshake") or {}).get("server_hello_extensions") or {}
    exts = she.get("extensions") if isinstance(she, dict) else None
    if not exts:
        return ""
    for e in exts:
        if isinstance(e, dict) and e.get("type") == EXT_KEY_SHARE:
            return str(e.get("group") or "")
    return ""


def _preference_violation(negotiated: str, rejected: list) -> bool:
    rejected = [str(r) for r in rejected]
    if not rejected:
        return False

    if negotiated in TLS13_ALLOWED:
        rank_negotiated = _cipher_tls13_rank(negotiated)
        for r in rejected:
            if r in TLS13_ALLOWED and _cipher_tls13_rank(r) < rank_negotiated:
                return True
        return False

    def strength(name: str) -> int:
        upper = name.upper()
        score = 0
        if "ECDHE" in upper:
            score += 200
        elif "DHE" in upper:
            score += 150
        else:
            score += 50
        if "GCM" in upper:
            score += 100
        elif "CHACHA20" in upper:
            score += 90
        elif "CBC" in upper:
            score += 30
        if "AES256" in upper or "AES-256" in upper or "AES_256" in upper:
            score += 20
        if "SHA256" in upper or "SHA384" in upper:
            score += 10
        return score

    base = strength(negotiated)
    return any(strength(r) > base for r in rejected)


def _check_extensions(data: dict, profile: str) -> list[Finding]:
    """Seccion 3.4.1, 3.4.2, 3.4.3 - extensiones."""
    findings = []
    proto = _negotiated_proto(data)
    ext_types = _extension_types(data)
    handshake = data.get("handshake") or {}
    has_ext_data = bool((handshake.get("server_hello_extensions") or {}).get("extensions"))

    if proto and proto != "TLS 1.3" and has_ext_data:
        if EXT_RENEGOTIATION_INFO not in ext_types:
            findings.append(_mkfinding(
                "EXT-01",
                "Renegotiation Indication ausente",
                SEVERITY_HIGH,
                "SP 800-52 Rev.2, Section 3.4.1.1",
                "renegotiation_info extension is mandatory",
                f"extensiones en ServerHello = {ext_types}",
                "Habilitar la extension renegotiation_info (RFC 5746).",
            ))

        if EXT_EXTENDED_MASTER_SECRET not in ext_types:
            findings.append(_mkfinding(
                "EXT-02",
                "Extended Master Secret ausente (TLS <= 1.2)",
                SEVERITY_HIGH,
                "SP 800-52 Rev.2, Section 3.4.1.3",
                "extended_master_secret extension is mandatory",
                f"extensiones en ServerHello = {ext_types}",
                "Habilitar extended_master_secret (RFC 7627).",
            ))

        if EXT_STATUS_REQUEST not in ext_types:
            findings.append(_mkfinding(
                "EXT-03",
                "OCSP stapling (status_request) ausente",
                SEVERITY_MEDIUM,
                "SP 800-52 Rev.2, Section 3.4.1.5",
                "status_request extension is mandatory",
                f"extensiones en ServerHello = {ext_types}",
                "Habilitar el OCSP stapling (status_request).",
            ))

    if proto == "TLS 1.3" and has_ext_data and EXT_KEY_SHARE not in ext_types:
        findings.append(_mkfinding(
            "EXT-05",
            "Key Share ausente en TLS 1.3",
            SEVERITY_HIGH,
            "SP 800-52 Rev.2, Section 3.4.2.3",
            "key_share extension is mandatory for TLS 1.3",
            f"extensiones en ServerHello = {ext_types}",
            "El ServerHello TLS 1.3 debe incluir key_share.",
        ))

    if proto and proto != "TLS 1.3" and has_ext_data:
        if EXT_SUPPORTED_GROUPS not in ext_types:
            negotiated = _negotiated_cipher(data)
            if "ECDHE" in negotiated.upper() or "DHE" in negotiated.upper():
                findings.append(_mkfinding(
                    "EXT-04",
                    "Supported Groups ausente",
                    SEVERITY_MEDIUM,
                    "SP 800-52 Rev.2, Section 3.4.2.2",
                    "supported_groups extension is conditionally mandatory",
                    f"extensiones en ServerHello = {ext_types}",
                    "Indicar los grupos soportados mediante supported_groups.",
                ))

    if proto and _proto_below(proto, "TLS 1.2") and not _proto_at_least(proto, "TLS 1.3"):
        if "TLS_FALLBACK_SCSV" not in [str(r) for r in (handshake.get("rejected_cipher_suites") or [])]:
            findings.append(_mkfinding(
                "EXT-09",
                "Fallback SCSV no verificable",
                SEVERITY_MEDIUM,
                "SP 800-52 Rev.2, Section 3.4.2.1",
                "TLS_FALLBACK_SCSV shall be supported to prevent downgrade",
                "servidor soporta versiones anteriores a TLS 1.2 sin TLS 1.3",
                "Garantizar soporte de TLS_FALLBACK_SCSV (0x5600).",
            ))

    if EXT_CLIENT_CERTIFICATE_URL in ext_types:
        findings.append(_mkfinding(
            "EXT-07",
            "Client Certificate URL presente",
            SEVERITY_MEDIUM,
            "SP 800-52 Rev.2, Section 3.4.3.1",
            "client_certificate_url is discouraged",
            f"extension client_certificate_url presente (tipo {EXT_CLIENT_CERTIFICATE_URL})",
            "Eliminar el soporte de client_certificate_url.",
        ))

    if EXT_EARLY_DATA in ext_types:
        findings.append(_mkfinding(
            "EXT-08",
            "Early Data / 0-RTT presente",
            SEVERITY_MEDIUM,
            "SP 800-52 Rev.2, Section 3.4.3.2",
            "early_data is discouraged",
            f"extension early_data presente (tipo {EXT_EARLY_DATA})",
            "Deshabilitar 0-RTT.",
        ))

    if EXT_CLIENT_CERTIFICATE_TYPE in ext_types or EXT_SERVER_CERTIFICATE_TYPE in ext_types:
        raw = []
        she = (handshake.get("server_hello_extensions") or {})
        for e in (she.get("extensions") or []):
            if isinstance(e, dict) and e.get("type") in (EXT_CLIENT_CERTIFICATE_TYPE, EXT_SERVER_CERTIFICATE_TYPE):
                raw.append(e.get("type_name", str(e.get("type"))))
        if raw:
            findings.append(_mkfinding(
                "EXT-06",
                "Raw Public Keys presente",
                SEVERITY_CRITICAL,
                "SP 800-52 Rev.2, Section 3.4.3.3",
                "raw public keys shall not be supported",
                f"extensiones certificate_type presentes: {raw}",
                "Deshabilitar el uso de raw public keys.",
            ))

    return findings


def _check_compression(data: dict, profile: str) -> list[Finding]:
    """Seccion 3.7 - compresion."""
    comp = _compression_method(data)
    if comp is None:
        return []
    if comp != 0:
        return [_mkfinding(
            "COMP-01",
            "Metodo de compresion distinto de null",
            SEVERITY_HIGH,
            "SP 800-52 Rev.2, Section 3.7",
            "null compression shall be enabled, all others disabled",
            f"compression_method = {comp}",
            "Habilitar solo el metodo de compresion null.",
        )]
    return []


def _check_not_evaluable(data: dict, profile: str) -> list[Finding]:
    """Seccion 3.6 - reglas que requieren informacion fuera del alcance del JSON."""
    return [
        _not_evaluable(
            "NE-01",
            "Validacion de modulo criptografico FIPS 140",
            "SP 800-52 Rev.2, Section 3.3.3",
            "cryptographic modules shall be validated to FIPS 140",
            "requiere acceso a la infraestructura del servidor.",
        ),
        _not_evaluable(
            "NE-02",
            "Comportamiento de renegociacion ante splicing",
            "SP 800-52 Rev.2, Section 3.4.1.1",
            "renegotiation shall be resistant to splicing attacks",
            "requiere prueba activa de renegociacion.",
        ),
        _not_evaluable(
            "NE-03",
            "Gestion del trust anchor store",
            "SP 800-52 Rev.2, Section 3.5.2",
            "trust anchors shall be managed and protected",
            "requiere acceso a la configuracion del servidor.",
        ),
        _not_evaluable(
            "NE-04",
            "Comportamiento ante 0-RTT real",
            "SP 800-52 Rev.2, Section 3.6",
            "0-RTT data shall be treated as replayable",
            "requiere prueba activa de comportamiento 0-RTT.",
        ),
        _not_evaluable(
            "NE-05",
            "Parcheo y actualizacion del sistema operativo",
            "SP 800-52 Rev.2, Section 3.8",
            "servers shall be patched and updated",
            "requiere acceso a la infraestructura del servidor.",
        ),
    ]


RULES: list[tuple[str, Callable[[dict, str], list[Finding]]]] = [
    ("protocol", _check_proto),
    ("certificate", _check_cert),
    ("cipher", _check_cipher),
    ("extensions", _check_extensions),
    ("compression", _check_compression),
    ("not_evaluable", _check_not_evaluable),
]


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------

class NISTEvaluationError(ValueError):
    """Error de evaluacion con mensaje claro para el usuario."""


def load_scan_file(path: str) -> dict:
    """Carga un archivo JSON de escaneo con manejo de errores claro."""
    import os

    if not os.path.exists(path):
        raise NISTEvaluationError(f"Archivo no encontrado: {path}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise NISTEvaluationError(f"El archivo {path} no es JSON valido: {exc}") from exc
    if not isinstance(data, dict):
        raise NISTEvaluationError("El JSON debe ser un objeto (dict) de resultados de escaneo.")
    if "handshake" not in data:
        raise NISTEvaluationError("Falta el campo clave 'handshake' en el JSON de entrada.")
    if "certificate_chain" not in data:
        raise NISTEvaluationError("Falta el campo clave 'certificate_chain' en el JSON de entrada.")
    return data


def evaluate(data: dict, profile: str = DEFAULT_PROFILE, evaluation_date: Any = None) -> dict:
    """Evalua el JSON de escaneo contra NIST SP 800-52 Rev.2.

    Devuelve el reporte en el formato definido en la seccion 4 del spec.
    """
    if not isinstance(data, dict):
        raise NISTEvaluationError("El JSON de entrada debe ser un objeto.")
    if profile not in (PROFILE_CITIZEN_FACING, PROFILE_GOVERNMENT_ONLY):
        raise NISTEvaluationError(f"Perfil invalido: {profile}. Use 'citizen-facing' o 'government-only'.")
    if "handshake" not in data:
        raise NISTEvaluationError("Falta el campo clave 'handshake' en el JSON de entrada.")

    findings: list[Finding] = []
    for _name, rule in RULES:
        try:
            found = rule(data, profile)
            if found:
                findings.extend(found)
        except Exception:
            # Tolerante: una regla que falla no debe romper la evaluacion.
            continue

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.get("severity", SEVERITY_INFO)))

    summary = {"critical": 0, "high": 0, "medium": 0, "info": 0, "not_evaluable": 0}
    for f in findings:
        sev = f.get("severity")
        if sev == SEVERITY_NOT_EVALUABLE:
            summary["not_evaluable"] += 1
        elif sev:
            key = sev.lower()
            if key in summary:
                summary[key] += 1

    host = data.get("host") or (data.get("handshake") or {}).get("host") or ""
    port = data.get("port") or (data.get("handshake") or {}).get("port") or 443

    return {
        "host": host,
        "port": port,
        "profile": profile,
        "evaluated_against": EVALUATED_AGAINST,
        "evaluation_date": resolve_evaluation_date(data, evaluation_date).isoformat(),
        "summary": summary,
        "findings": findings,
    }
