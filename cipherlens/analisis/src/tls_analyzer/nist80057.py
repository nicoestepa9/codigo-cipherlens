"""NIST SP 800-57 Part 1 Rev.5 compliance detector.

Modulo de reglas para el detector de vulnerabilidades TLS basado en NIST
SP 800-57 Part 1 Rev.5 ("Recommendation for Key Management: Part 1 - General",
mayo 2020). Provee el marco de "security strength" (bits de seguridad
equivalentes) y el cronograma de cuando cada nivel de fuerza deja de ser
aceptable (Tabla 4: 112 bits deja de aceptarse en 2031).

Aplica al JSON de escaneo en dos puntos:
1. certificate_chain[].key_type + key_size + not_before/not_after
2. handshake.accepted_cipher_suites[].bits / key exchange usado

Cada regla cita la seccion exacta de la Rev.5 (no de Rev.4).
"""

from __future__ import annotations

from datetime import date
from typing import Any, Callable

from .nist import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_MEDIUM,
    SEVERITY_NOT_EVALUABLE,
    SEVERITY_ORDER,
    DEFAULT_PROFILE,
    _cipher_pool,
    _leaf_cert,
    _mkfinding,
    _negotiated_cipher,
    _not_evaluable,
    _parse_date,
)
from .crypto_strength import (
    SCHEDULE_112_CUTOFF,
    cipher_strength_bits,
    ec_group_security_bits,
    ffdhe_group_security_bits,
    hash_strength_bits,
    key_share_group_name,
    resolve_evaluation_date,
    security_strength_bits,
)

EVALUATED_AGAINST = "NIST SP 800-57 Part 1 Rev.5 (May 2020)"

Finding = dict

SCT_EXT = 0x0012


class NISTEvaluationError(ValueError):
    """Error de evaluacion con mensaje claro para el usuario."""


def _extension_types(data: dict) -> list[int]:
    she = (data.get("handshake") or {}).get("server_hello_extensions") or {}
    exts = she.get("extensions") if isinstance(she, dict) else None
    if not exts:
        return []
    types = []
    for e in exts:
        if isinstance(e, dict) and isinstance(e.get("type"), int):
            types.append(e["type"])
    return types


def _has_sct(data: dict) -> bool:
    return SCT_EXT in _extension_types(data)


# ---------------------------------------------------------------------------
# Reglas de deteccion
# ---------------------------------------------------------------------------


def _check_key(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 5.6.1.1 (Tabla 2) - fuerza de la clave del certificado y ciphers."""
    findings = []
    cert = _leaf_cert(data)
    if not cert:
        return findings

    key_type = str(cert.get("key_type") or "")
    key_size = cert.get("key_size") or 0
    strength = security_strength_bits(key_type, key_size)
    observed = f"key_type={key_type} key_size={key_size}"

    if "RSA" in key_type and isinstance(key_size, int) and 0 < key_size < 2048:
        findings.append(_mkfinding(
            "KEY-01",
            "Clave RSA por debajo de 112 bits de seguridad",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Table 2, Section 5.6.1.1",
            "RSA with k<2048 provides less than 112 bits; not approved for applying protection",
            observed,
            "Usar claves RSA de al menos 2048 bits.",
        ))

    if ("EC" in key_type or "Ed" in key_type) and strength is not None and strength < 112:
        findings.append(_mkfinding(
            "KEY-02",
            "Clave EC/EdDSA por debajo de 112 bits",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Table 2, Section 5.6.1.1",
            "ECC with f<224 provides less than 112 bits of security",
            observed,
            "Usar curvas de 224 bits o superiores (P-256, P-384).",
        ))

    if ("DSA" in key_type or "DH" in key_type) and isinstance(key_size, int) and 0 < key_size < 2048:
        findings.append(_mkfinding(
            "KEY-03",
            "Clave DSA/DH (FFC) por debajo de 112 bits",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Table 2, Section 5.6.1.1",
            "FFC with L<2048 provides less than 112 bits of security",
            observed,
            "Usar grupos DSA/DH con L>=2048 y N>=224.",
        ))

    pool = _cipher_pool(data)

    if any("2tdea" in c.lower() or "des-ede2" in c.lower() for c in pool):
        findings.append(_mkfinding(
            "KEY-04",
            "Uso de 2TDEA",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Table 2, Section 5.6.1.1",
            "2TDEA provides at most 80 bits of security; not approved",
            f"cipher suites = {sorted(pool)}",
            "Eliminar cualquier cipher suite basado en 2TDEA.",
        ))

    if any(("3des" in c.lower() or "tdea" in c.lower() or "des-cbc3" in c.lower()) for c in pool):
        findings.append(_mkfinding(
            "KEY-05",
            "Uso de 3TDEA (3DES), disallowed desde 2023",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Table 2 footnote 68, Section 5.6.1.1",
            "3TDEA is deprecated through 2023, after which it will be disallowed",
            f"cipher suites = {sorted(pool)}",
            "Eliminar cipher suites 3DES; migrar a AES-GCM.",
        ))

    if strength is not None and strength < 112:
        findings.append(_mkfinding(
            "KEY-06",
            "Algoritmo/clave por debajo de 112 bits",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Section 5.6.1.1",
            "less than 112 bits of security is not approved for applying protection",
            observed,
            "Migrar a claves con al menos 112 bits de seguridad.",
        ))

    if strength == 112:
        findings.append(_mkfinding(
            "KEY-07",
            "Clave con exactamente 112 bits de seguridad",
            SEVERITY_INFO,
            "SP 800-57 Part 1 Rev.5, Table 4, Section 5.6.3",
            "112 bits is acceptable until 2030; disallowed after 2031",
            observed,
            "Planificar la migracion a 128 bits (AES-128 / P-256) antes de 2031.",
        ))

    return findings


def _check_hash(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 5.6.1.2 (Tabla 3) y 5.6.2 (combinacion) - funciones hash."""
    findings = []
    cert = _leaf_cert(data)
    if not cert:
        return findings

    sig = str(cert.get("signature_algorithm") or "")
    sig_lower = sig.lower()
    hash_strength = hash_strength_bits(sig)

    if "sha1" in sig_lower or "sha-1" in sig_lower:
        findings.append(_mkfinding(
            "HASH-01",
            "SHA-1 usado para firma digital",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Table 3, Section 5.6.1.2",
            "SHA-1 provides less than 80 bits of security for digital signatures",
            f"signature_algorithm = {sig}",
            "Usar SHA-256 o superior en el certificado.",
        ))

    if hash_strength is not None and hash_strength < 112:
        findings.append(_mkfinding(
            "HASH-02",
            "Hash con menos de 112 bits usado para proteger informacion nueva",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Section 5.6.1.2",
            "no longer approved for applying cryptographic protection, e.g. generating a signature",
            f"signature_algorithm = {sig}",
            "Reemplazar la firma por SHA-256 o superior.",
        ))

    key_strength = security_strength_bits(cert.get("key_type") or "", cert.get("key_size") or 0)
    if hash_strength is not None and key_strength is not None:
        effective = min(hash_strength, key_strength)
        if effective < 128:
            findings.append(_mkfinding(
                "HASH-03",
                "Combinacion firma+hash con fuerza mixta",
                SEVERITY_MEDIUM,
                "SP 800-57 Part 1 Rev.5, Section 5.6.2",
                "the combination provides no more than the weaker of the two algorithms",
                f"hash={hash_strength} bits, key={key_strength} bits -> {effective} bits",
                "Alinear la fuerza del hash y de la clave de firma.",
            ))

    return findings


def _check_schedule(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 5.6.3 (Tabla 4) - cronograma de fuerza de seguridad."""
    findings = []
    cert = _leaf_cert(data)
    if not cert:
        return findings

    key_type = str(cert.get("key_type") or "")
    key_size = cert.get("key_size") or 0
    strength = security_strength_bits(key_type, key_size)
    if strength is None:
        return findings
    observed = f"key_type={key_type} key_size={key_size}"

    if strength < 112:
        findings.append(_mkfinding(
            "SCHED-02",
            "Fuerza menor a 112 bits",
            SEVERITY_CRITICAL,
            "SP 800-57 Part 1 Rev.5, Table 4, Section 5.6.3",
            "Applying protection: Disallowed for <112 bits",
            observed,
            "Migrar a claves con al menos 128 bits.",
        ))

    if strength == 112 and eval_date > SCHEDULE_112_CUTOFF:
        findings.append(_mkfinding(
            "SCHED-01",
            "Fuerza de 112 bits usada para aplicar proteccion despues de 2030",
            SEVERITY_HIGH,
            "SP 800-57 Part 1 Rev.5, Table 4, Section 5.6.3",
            "Applying protection: Disallowed for 112 bits in 2031+",
            observed,
            "Migrar a 128 bits antes de 2031.",
        ))

    if strength == 112:
        na = _parse_date(cert.get("not_after"))
        if na and na.date() > SCHEDULE_112_CUTOFF:
            findings.append(_mkfinding(
                "SCHED-03",
                "Certificado con clave de 112 bits vigente despues de 2030",
                SEVERITY_HIGH,
                "SP 800-57 Part 1 Rev.5, Table 4 + Section 5.6.4",
                "protection should not extend beyond the algorithm security lifetime",
                f"not_after = {cert.get('not_after')}",
                "Emitir la clave siguiente con al menos 128 bits.",
            ))

    if strength >= 128:
        findings.append(_mkfinding(
            "SCHED-04",
            "Fuerza de clave aceptable",
            SEVERITY_INFO,
            "SP 800-57 Part 1 Rev.5, Table 4, Section 5.6.3",
            "strength >= 128 bits is acceptable in both periods",
            observed,
            "Ninguna accion requerida.",
        ))

    return findings


def _check_combo(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 5.6.2 - fuerza efectiva y reglas de combinacion."""
    findings = []
    handshake = data.get("handshake") or {}
    negotiated = _negotiated_cipher(data)
    cipher_strength = cipher_strength_bits(negotiated) if negotiated else None
    group = key_share_group_name(data)
    group_strength = ec_group_security_bits(group) or ffdhe_group_security_bits(group)

    if group_strength is not None and cipher_strength is not None and group_strength < cipher_strength:
        findings.append(_mkfinding(
            "COMBO-02",
            "Key agreement de fuerza menor que el algoritmo simetrico derivado",
            SEVERITY_MEDIUM,
            "SP 800-57 Part 1 Rev.5, Section 5.6.2",
            "the combination can provide no more than the weaker key agreement",
            f"key_share={group or '<none>'} ({group_strength} bits), cipher={negotiated or '<none>'} ({cipher_strength} bits)",
            "Usar un grupo de key exchange con al menos la fuerza del cipher.",
        ))

    findings.append(_not_evaluable(
        "COMBO-03",
        "Reutilizacion de clave de key-agreement como clave de firma no verificable",
        "SP 800-57 Part 1 Rev.5, Section 5.6.2.d",
        "the key used for key agreement shall be different from the ECDSA key used for digital signatures",
        "no se puede observar desde un JSON de handshake si el mismo par de claves se usa para dos propositos.",
    ))

    findings.append(_not_evaluable(
        "COMBO-04",
        "Clave fuerte procesada por algoritmo mas debil no verificable",
        "SP 800-57 Part 1 Rev.5, Section 5.6.2",
        "a strong key wrapped by a weaker process loses security strength",
        "el key-wrapping no es observable en un handshake TLS.",
    ))

    return findings


def _check_pqc(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 5.6.1.1 - nota de vigilancia post-cuantica (informativa)."""
    cert = _leaf_cert(data)
    if not cert:
        return []
    key_type = str(cert.get("key_type") or "")
    if any(k in key_type for k in ("RSA", "EC", "DSA", "DH", "Ed")):
        return [_mkfinding(
            "PQC-01",
            "Vigilancia post-cuantica",
            SEVERITY_INFO,
            "SP 800-57 Part 1 Rev.5, Section 5.6.1.1",
            "may need replacement with post-quantum counterparts when practical quantum computers exist",
            f"key_type={key_type}",
            "Monitorear el cronograma de migracion a algoritmos post-cuanticos (sin accion inmediata).",
        )]
    return []


def _check_crypto(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 5.3.6 (Tabla 1) - cryptoperiods."""
    findings = []
    cert = _leaf_cert(data)
    if not cert:
        return findings

    nb = _parse_date(cert.get("not_before"))
    na = _parse_date(cert.get("not_after"))
    if nb and na and (na - nb).days > 3 * 365:
        findings.append(_mkfinding(
            "CRYPTO-01",
            "Vigencia del certificado mayor a 3 anios",
            SEVERITY_MEDIUM,
            "SP 800-57 Part 1 Rev.5, Section 5.3.6, item 1.b",
            "a maximum cryptoperiod of about one to three years is recommended",
            f"not_before={cert.get('not_before')} not_after={cert.get('not_after')}",
            "Emitir certificados con vigencia de 3 anios o menos.",
        ))

    findings.append(_not_evaluable(
        "CRYPTO-02",
        "Uso real de la clave privada mas alla de su cryptoperiod no verificable",
        "SP 800-57 Part 1 Rev.5, Section 5.3.4",
        "cryptoperiod of a public key is not the same as certificate validity",
        "requiere el historial de reemision de la clave, externo al JSON.",
    ))

    return findings


def _check_reduce(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 5.6.5 - reduccion de fuerza de seguridad en el tiempo."""
    findings = []
    cert = _leaf_cert(data)
    if not cert:
        return findings

    sig = str(cert.get("signature_algorithm") or "").lower()
    key_type = str(cert.get("key_type") or "")
    strength = security_strength_bits(key_type, cert.get("key_size") or 0)
    weak = ("sha1" in sig or "sha-1" in sig or "md5" in sig) or (strength is not None and strength < 112)
    if not weak:
        return findings

    if not _has_sct(data):
        findings.append(_not_evaluable(
            "REDUCE-01",
            "Firma debilitada - proteccion por SCT no verificable",
            "SP 800-57 Part 1 Rev.5, Section 5.6.5",
            "the signature may still be valid if adequately protected by a stronger algorithm",
            "no se puede confirmar la presencia de Signed Certificate Timestamps desde este JSON.",
        ))

    findings.append(_mkfinding(
        "REDUCE-02",
        "Informacion previamente protegida puede haber perdido seguridad",
        SEVERITY_INFO,
        "SP 800-57 Part 1 Rev.5, Section 5.6.5",
        "information protected with now-inadequate algorithms may no longer be secure",
        f"signature_algorithm={cert.get('signature_algorithm')}",
        "Evaluar re-firmar o migrar la informacion protegida con el algoritmo debilitado.",
    ))

    return findings


RULES: list[tuple[str, Callable[[dict, str, date], list[Finding]]]] = [
    ("key", _check_key),
    ("hash", _check_hash),
    ("schedule", _check_schedule),
    ("combo", _check_combo),
    ("pqc", _check_pqc),
    ("crypto", _check_crypto),
    ("reduce", _check_reduce),
]


# ---------------------------------------------------------------------------
# Fuerza efectiva de la conexion
# ---------------------------------------------------------------------------


def compute_strengths(data: dict) -> dict:
    """Fuerza de seguridad de certificado, firma, cipher y fuerza efectiva (COMBO-01)."""
    cert = _leaf_cert(data)
    cert_strength = security_strength_bits(cert.get("key_type") or "", cert.get("key_size") or 0) if cert else None
    hash_strength = hash_strength_bits(cert.get("signature_algorithm") or "") if cert else None
    negotiated = _negotiated_cipher(data)
    cipher_strength = cipher_strength_bits(negotiated) if negotiated else None

    known = [s for s in (cert_strength, hash_strength, cipher_strength) if s is not None]
    return {
        "certificate_key_strength_bits": cert_strength,
        "signature_hash_strength_bits": hash_strength,
        "cipher_strength_bits": cipher_strength,
        "effective_strength_bits": min(known) if known else None,
    }


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------


def evaluate(data: dict, profile: str = DEFAULT_PROFILE, evaluation_date: Any = None) -> dict:
    """Evalua el JSON de escaneo contra NIST SP 800-57 Part 1 Rev.5."""
    if not isinstance(data, dict):
        raise NISTEvaluationError("El JSON de entrada debe ser un objeto.")
    if "handshake" not in data:
        raise NISTEvaluationError("Falta el campo clave 'handshake' en el JSON de entrada.")

    eval_date = resolve_evaluation_date(data, evaluation_date)

    findings: list[Finding] = []
    for _name, rule in RULES:
        try:
            found = rule(data, profile, eval_date)
            if found:
                findings.extend(found)
        except Exception:
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
        "evaluation_date": eval_date.isoformat(),
        "summary": summary,
        "findings": findings,
        "security_strength": compute_strengths(data),
    }
