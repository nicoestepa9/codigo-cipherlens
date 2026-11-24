"""NIST SP 800-131A Rev.2 compliance detector.

Modulo de reglas para el detector de vulnerabilidades TLS basado en NIST
SP 800-131A Rev.2 ("Transitioning the Use of Cryptographic Algorithms and Key
Lengths", marzo 2019). Este documento da el detalle fino de fechas exactas en
que cada algoritmo/tamano de clave pasa de `acceptable` a `deprecated` /
`disallowed` / `legacy use`.

Los 4 estados de aprobacion (Seccion 1.2.3) se reportan en el campo `status`
de cada finding, con una severidad mapeada para consistencia con los otros
modulos. `classify()` centraliza la logica de las tablas observables.

Los campos no observables en un handshake TLS (RBG, key wrapping, KDF) se
documentan como NOT_EVALUABLE para trazabilidad completa del estandar.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

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
)
from .crypto_strength import (
    DH_MQV_NONCOMPLIANT_CUTOFF,
    RSA_NONCOMPLIANT_OTHER_CUTOFF,
    RSA_PKCS1V15_CUTOFF,
    TDEA_3KEY_CUTOFF,
    ec_group_order_bits,
    ffdhe_group_security_bits,
    hash_strength_bits,
    key_share_group_name,
    normalize_cipher_name,
    resolve_evaluation_date,
    security_strength_bits,
)

EVALUATED_AGAINST = "NIST SP 800-131A Rev.2 (March 2019)"

STATUS_ACCEPTABLE = "Acceptable"
STATUS_DEPRECATED = "Deprecated"
STATUS_LEGACY_USE = "Legacy use"
STATUS_DISALLOWED = "Disallowed"
STATUS_NOT_EVALUABLE = "NOT_EVALUABLE"

_STATE_SEVERITY = {
    STATUS_DISALLOWED: SEVERITY_CRITICAL,
    STATUS_DEPRECATED: SEVERITY_MEDIUM,
    STATUS_LEGACY_USE: SEVERITY_INFO,
    STATUS_ACCEPTABLE: SEVERITY_INFO,
    STATUS_NOT_EVALUABLE: SEVERITY_NOT_EVALUABLE,
}

Finding = dict


class NISTEvaluationError(ValueError):
    """Error de evaluacion con mensaje claro para el usuario."""


def _state_finding(
    rule_id: str,
    title: str,
    status: str,
    section: str,
    citation: str,
    observed: str,
    recommendation: str,
) -> Finding:
    return _mkfinding(
        rule_id,
        title,
        _STATE_SEVERITY.get(status, SEVERITY_INFO),
        section,
        citation,
        observed,
        recommendation,
        status=status,
    )


# ---------------------------------------------------------------------------
# classify() - logica central de las tablas observables
# ---------------------------------------------------------------------------


def classify(algorithm: str, key_or_group_size: int | None, purpose: str, eval_date: date) -> dict:
    """Clasifica un algoritmo/parametro en uno de los 4 estados de aprobacion.

    Centraliza la logica de las tablas 1, 2, 4, 5, 8 y 9 del documento.

    ``purpose`` toma uno de: "encrypt", "decrypt", "sign", "verify",
    "key_agreement", "key_transport", "mac". Retorna ``{status, severity}``.
    """
    algo = (algorithm or "").lower()
    if eval_date is None:
        eval_date = date.today()

    if "skipjack" in algo:
        status = STATUS_DISALLOWED if purpose in ("encrypt", "sign", "key_transport", "mac") else STATUS_LEGACY_USE
        return {"status": status, "severity": _STATE_SEVERITY[status]}

    if "2tdea" in algo or "des-ede2" in algo:
        status = STATUS_DISALLOWED if purpose in ("encrypt", "sign", "key_transport", "mac") else STATUS_LEGACY_USE
        return {"status": status, "severity": _STATE_SEVERITY[status]}

    if any(t in algo for t in ("3tdea", "3des", "des-cbc3", "des-ede3")):
        if purpose in ("decrypt", "verify"):
            status = STATUS_LEGACY_USE
        elif eval_date > TDEA_3KEY_CUTOFF:
            status = STATUS_DISALLOWED
        else:
            status = STATUS_DEPRECATED
        return {"status": status, "severity": _STATE_SEVERITY[status]}

    if "aes" in algo and "gcm" in algo or "aes" in algo and "ccm" in algo:
        return {"status": STATUS_ACCEPTABLE, "severity": _STATE_SEVERITY[STATUS_ACCEPTABLE]}

    if algo.startswith(("rsa", "ecdsa", "eddsa", "dsa", "ed")) or "ec" in algo:
        return _classify_signature(algo, key_or_group_size, purpose)

    if algo in ("x25519", "x448"):
        return _classify_ec_group(algo, key_or_group_size, purpose)

    if "sha" in algo:
        return _classify_hash(algo, purpose)

    return {"status": STATUS_NOT_EVALUABLE, "severity": SEVERITY_NOT_EVALUABLE}


def _classify_signature(algo: str, size: int | None, purpose: str) -> dict:
    size = size or 0
    if "ecdsa" in algo or "ec" in algo:
        if size and size >= 224:
            status = STATUS_ACCEPTABLE
        elif size and 160 <= size < 224:
            status = STATUS_LEGACY_USE if purpose == "verify" else STATUS_DISALLOWED
        else:
            status = STATUS_DISALLOWED
        return {"status": status, "severity": _STATE_SEVERITY[status]}

    if "eddsa" in algo or "ed25519" in algo or "ed448" in algo or algo.startswith("ed"):
        status = STATUS_ACCEPTABLE if size and size >= 224 else STATUS_DISALLOWED
        return {"status": status, "severity": _STATE_SEVERITY[status]}

    if "rsa" in algo:
        if size >= 2048:
            status = STATUS_ACCEPTABLE
        elif 1024 <= size < 2048:
            status = STATUS_LEGACY_USE if purpose == "verify" else STATUS_DISALLOWED
        else:
            status = STATUS_DISALLOWED
        return {"status": status, "severity": _STATE_SEVERITY[status]}

    if "dsa" in algo:
        if size in (2048, 3072):
            status = STATUS_ACCEPTABLE if purpose == "verify" else STATUS_ACCEPTABLE
        elif 512 <= size < 2048:
            status = STATUS_LEGACY_USE if purpose == "verify" else STATUS_DISALLOWED
        else:
            status = STATUS_DISALLOWED
        return {"status": status, "severity": _STATE_SEVERITY[status]}

    return {"status": STATUS_NOT_EVALUABLE, "severity": SEVERITY_NOT_EVALUABLE}


def _classify_ec_group(algo: str, size: int | None, purpose: str) -> dict:
    size = size or 0
    if size >= 224:
        return {"status": STATUS_ACCEPTABLE, "severity": _STATE_SEVERITY[STATUS_ACCEPTABLE]}
    if 160 <= size < 224:
        status = STATUS_LEGACY_USE if purpose == "verify" else STATUS_DISALLOWED
        return {"status": status, "severity": _STATE_SEVERITY[status]}
    return {"status": STATUS_DISALLOWED, "severity": SEVERITY_CRITICAL}


def _classify_hash(algo: str, purpose: str) -> dict:
    a = algo.lower()
    if "sha1" in a or "sha-1" in a:
        if purpose == "mac" or purpose == "verify_hash":
            return {"status": STATUS_ACCEPTABLE, "severity": _STATE_SEVERITY[STATUS_ACCEPTABLE]}
        if purpose == "verify":
            return {"status": STATUS_LEGACY_USE, "severity": _STATE_SEVERITY[STATUS_LEGACY_USE]}
        return {"status": STATUS_DISALLOWED, "severity": SEVERITY_CRITICAL}
    if "sha3" in a or "sha-3" in a or "sha224" in a or "sha-224" in a or "sha256" in a or "sha-256" in a or "sha384" in a or "sha-384" in a or "sha512" in a or "sha-512" in a:
        return {"status": STATUS_ACCEPTABLE, "severity": _STATE_SEVERITY[STATUS_ACCEPTABLE]}
    return {"status": STATUS_NOT_EVALUABLE, "severity": SEVERITY_NOT_EVALUABLE}


# ---------------------------------------------------------------------------
# Reglas de deteccion
# ---------------------------------------------------------------------------


def _check_blk(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 2, Tabla 1 - cifrado por bloque."""
    findings = []
    handshake = data.get("handshake") or {}
    pool = _cipher_pool(data)

    skipjack = [c for c in pool if "skipjack" in c.lower()]
    if skipjack:
        findings.append(_state_finding(
            "BLK-04",
            "SKIPJACK detectado en cifrado",
            STATUS_DISALLOWED,
            "SP 800-131A Rev.2, Table 1, Section 2",
            "The use of SKIPJACK for encryption is disallowed",
            f"cipher suites = {sorted(skipjack)}",
            "Eliminar cualquier cipher suite basado en SKIPJACK.",
        ))

    tdea2 = [c for c in pool if "2tdea" in c.lower() or "des-ede2" in c.lower() or "des-ede-cbc" in c.lower()]
    if tdea2:
        findings.append(_state_finding(
            "BLK-01",
            "Two-key TDEA usado para cifrar",
            STATUS_DISALLOWED,
            "SP 800-131A Rev.2, Table 1, Section 2",
            "Encryption using two-key TDEA is disallowed",
            f"cipher suites = {sorted(tdea2)}",
            "Eliminar cipher suites con 2TDEA.",
        ))

    tdea3 = [c for c in pool if "3des" in c.lower() or "des-cbc3" in c.lower() or "des-ede3" in c.lower() or ("tdea" in c.lower() and c not in tdea2)]
    if tdea3:
        if eval_date > TDEA_3KEY_CUTOFF:
            findings.append(_state_finding(
                "BLK-02",
                "Three-key TDEA (3DES) usado para cifrar despues de 2023",
                STATUS_DISALLOWED,
                "SP 800-131A Rev.2, Table 1, Section 2",
                "After December 31, 2023, three-key TDEA is disallowed for encryption",
                f"cipher suites = {sorted(tdea3)}",
                "Eliminar cipher suites 3DES; migrar a AES-GCM.",
            ))
        else:
            findings.append(_state_finding(
                "BLK-03",
                "Three-key TDEA (3DES) usado para cifrar (deprecated)",
                STATUS_DEPRECATED,
                "SP 800-131A Rev.2, Table 1, Section 2",
                "three-key TDEA is deprecated through December 31, 2023",
                f"cipher suites = {sorted(tdea3)}",
                "Planificar la migracion a AES antes del corte de 2023.",
            ))

    cipher_info = handshake.get("cipher_info")
    measured_suites = list(handshake.get("accepted_cipher_suites") or [])
    if isinstance(cipher_info, dict):
        measured_suites.append(
            {"name": _negotiated_cipher(data), **cipher_info}
        )
    measured_bits: dict[str, set[int]] = {}
    for suite in measured_suites:
        if not isinstance(suite, dict):
            continue
        name = normalize_cipher_name(str(suite.get("name") or ""))
        bits = suite.get("bits")
        if type(bits) is int and bits > 0:
            measured_bits.setdefault(name, set()).add(bits)

    aes = {
        cipher for cipher in pool
        if re.search(r"(?:^|[^A-Z0-9])AES(?=[0-9]|[^A-Z0-9]|$)", cipher)
    }
    allowed_aes = []
    weak_aes = []
    for cipher in sorted(aes):
        named_size = re.search(r"(?:^|[^A-Z0-9])AES[_-]?(\d+)", cipher)
        sizes = measured_bits.get(cipher, set()).copy()
        if named_size:
            sizes.add(int(named_size[1]))
        weak_sizes = sorted(bits for bits in sizes if 0 < bits < 128)
        if re.search(r"(?:^|[^A-Z])ECB(?:[^A-Z]|$)", cipher) or weak_sizes:
            weak_aes.append(f"{cipher} (observed key sizes: {sorted(sizes)})")
        else:
            allowed_aes.append(cipher)

    if weak_aes:
        findings.append(_state_finding(
            "BLK-06",
            "AES en modo ECB o con clave inferior a 128 bits",
            STATUS_DISALLOWED,
            "SP 800-131A Rev.2, Table 1, Section 2",
            "AES key lengths approved by SP 800-131A are 128, 192 and 256 bits; CipherLens disallows ECB in TLS",
            f"cipher suites = {weak_aes}",
            "Usar una suite TLS AES-GCM o AES-CCM con una clave de al menos 128 bits.",
        ))

    if allowed_aes:
        findings.append(_state_finding(
            "BLK-05",
            "AES-128/192/256 en uso",
            STATUS_ACCEPTABLE,
            "SP 800-131A Rev.2, Table 1, Section 2",
            "AES-128/192/256 is acceptable for encryption",
            f"cipher suites = {allowed_aes}",
            "Ninguna accion requerida.",
        ))

    return findings


def _check_sig(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 3, Tabla 2 - firmas digitales del certificado."""
    findings = []
    cert = _leaf_cert(data)
    if not cert:
        return findings

    key_type = str(cert.get("key_type") or "")
    key_size = cert.get("key_size") or 0
    observed = f"key_type={key_type} key_size={key_size}"

    if "RSA" in key_type:
        state = classify("rsa", key_size if isinstance(key_size, int) else 0, "sign", eval_date)
        if state["status"] == STATUS_DISALLOWED:
            findings.append(_state_finding(
                "SIG-01",
                "Clave RSA < 2048 bits usada para firmar",
                STATUS_DISALLOWED,
                "SP 800-131A Rev.2, Table 2, Section 3",
                "RSA with len(n)<2048 shall not generate digital signatures",
                observed,
                "Usar claves RSA de al menos 2048 bits.",
            ))
        else:
            findings.append(_state_finding(
                "SIG-06",
                "Clave RSA con parametros aprobados para firma",
                STATUS_ACCEPTABLE,
                "SP 800-131A Rev.2, Table 2, Section 3",
                "RSA with len(n)>=2048 is acceptable for signature generation",
                observed,
                "Ninguna accion requerida.",
            ))

    elif "EC" in key_type or "Ed" in key_type:
        order = ec_group_order_bits(str(cert.get("curve") or key_type)) or key_size
        state = classify("ecdsa", order if isinstance(order, int) else 0, "sign", eval_date)
        if state["status"] == STATUS_ACCEPTABLE:
            findings.append(_state_finding(
                "SIG-06",
                "Clave ECDSA/EdDSA con parametros aprobados para firma",
                STATUS_ACCEPTABLE,
                "SP 800-131A Rev.2, Table 2, Section 3",
                "ECDSA/EdDSA with len(n)>=224 is acceptable for signature generation",
                observed,
                "Ninguna accion requerida.",
            ))
        elif state["status"] == STATUS_LEGACY_USE:
            findings.append(_state_finding(
                "SIG-04",
                "Curva ECDSA de 160-223 bits (legacy use)",
                STATUS_LEGACY_USE,
                "SP 800-131A Rev.2, Section 3, p.10",
                "B-163, K-163 and P-192 may continue to be used for signature verification only",
                observed,
                "Migrar a P-256 o superior.",
            ))
        else:
            findings.append(_state_finding(
                "SIG-03",
                "Curva ECDSA/EdDSA con len(n) < 224 bits",
                STATUS_DISALLOWED,
                "SP 800-131A Rev.2, Table 2, Section 3, p.10",
                "the length of n shall be at least 224 bits",
                observed,
                "Usar curvas de 224 bits o superiores.",
            ))

    elif "DSA" in key_type:
        state = classify("dsa", key_size if isinstance(key_size, int) else 0, "sign", eval_date)
        if state["status"] == STATUS_DISALLOWED:
            findings.append(_state_finding(
                "SIG-05",
                "DSA con parametros fuera de los pares aprobados",
                STATUS_DISALLOWED,
                "SP 800-131A Rev.2, Table 2, Section 3",
                "DSA with L,N outside the approved pairs is disallowed for signature generation",
                observed,
                "Migrar a ECDSA/RSA con parametros aprobados.",
            ))
        else:
            findings.append(_state_finding(
                "SIG-06",
                "Clave DSA con parametros aprobados",
                STATUS_ACCEPTABLE,
                "SP 800-131A Rev.2, Table 2, Section 3",
                "DSA with (L,N) in the three approved pairs is acceptable",
                observed,
                "Ninguna accion requerida.",
            ))

    return findings


def _check_rbg(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 4, Tabla 3 - RBG no observable en handshake."""
    return [_not_evaluable(
        "RBG-01",
        "Generador de bits aleatorios (RBG) del servidor",
        "SP 800-131A Rev.2, Table 3, Section 4",
        "Dual_EC_DRBG and 3TDEA-based CTR_DRBG are disallowed",
        "el RBG usado por el servidor no es observable desde un JSON de handshake pasivo.",
    )]


def _check_dh(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 5, Tabla 4 - acuerdos de claves DH/MQV."""
    findings = []
    group = key_share_group_name(data)
    handshake = data.get("handshake") or {}
    negotiated = _negotiated_cipher(data)

    if not group:
        groups = [str(g.get("name", "")) for g in (handshake.get("supported_groups") or []) if isinstance(g, dict)]
        groups += [str(g) for g in (handshake.get("supported_groups") or []) if isinstance(g, (str, int))]
        group = groups[0] if groups else ""
    if not group:
        nl = negotiated.lower()
        if "ecdhe" in nl:
            group = "ECDHE"
        elif "dhe" in nl:
            group = "DHE"
    if not group:
        return [_not_evaluable(
            "DH-06",
            "Grupo de key exchange no identificado",
            "SP 800-131A Rev.2, Table 4, Section 5",
            "DH/MQV elliptic conforming groups with len(n)>=224 are acceptable",
            "no hay key_share ni supported_groups en el JSON para determinar el grupo.",
        )]

    gl = group.lower()

    if gl == "dhe":
        return [_not_evaluable(
            "DH-02",
            "Grupo DH finito (DHE) sin parametros identificables",
            "SP 800-131A Rev.2, Table 4, Section 5",
            "DH/MQV finite-field with len(p)<2048 is disallowed",
            "no se puede derivar len(p) sin el nombre del grupo o supported_groups.",
        )]

    if gl == "ecdhe":
        return [_not_evaluable(
            "DH-05",
            "Curva ECDHE no identificada en el JSON",
            "SP 800-131A Rev.2, Table 4, Section 5 + IG A.2",
            "curves not listed in SP 800-56A Rev.3 require case-by-case assessment",
            "el key_share no reporta el grupo concreto (solo ECDHE).",
        )]

    if "ffdhe" in gl or "modp" in gl:
        bits = ffdhe_group_security_bits(group)
        if isinstance(bits, int) and bits < 112:
            findings.append(_state_finding(
                "DH-02",
                "Grupo DH de fuerza menor a 112 bits",
                STATUS_DISALLOWED,
                "SP 800-131A Rev.2, Table 4, Section 5",
                "DH/MQV with less than 112 bits of security strength is disallowed",
                f"group = {group}",
                "Usar grupos FFDHE de 2048 bits o superiores.",
            ))
        else:
            findings.append(_state_finding(
                "DH-06",
                "Grupo DH conforme (FFDHE/safe-prime)",
                STATUS_ACCEPTABLE,
                "SP 800-131A Rev.2, Table 4, Section 5",
                "DH/MQV conforming to SP 800-56A is acceptable",
                f"group = {group}",
                "Ninguna accion requerida.",
            ))
        return findings

    if "x25519" in gl or "x448" in gl:
        findings.append(_not_evaluable(
            "DH-06",
            f"Grupo {group} no cubierto explícitamente por SP 800-131A Rev.2",
            "SP 800-131A Rev.2, Table 4, Section 5 + IG A.2",
            "curves not listed in SP 800-56A Rev.3 require case-by-case assessment",
            f"el grupo {group} no aparece en las tablas de este documento (2019); su aceptacion depende de si cumple los criterios generales de fuerza (~128 bits).",
        ))
        return findings

    ec_bits = ec_group_order_bits(group)
    if ec_bits is not None:
        if ec_bits >= 224:
            findings.append(_state_finding(
                "DH-06",
                "Curva ECDHE conforme a SP 800-56A",
                STATUS_ACCEPTABLE,
                "SP 800-131A Rev.2, Table 4, Section 5",
                "DH/MQV elliptic conforming with len(n)>=224 is acceptable",
                f"group = {group}",
                "Ninguna accion requerida.",
            ))
        else:
            findings.append(_state_finding(
                "DH-04",
                "Curva ECDHE con len(n) < 224 bits",
                STATUS_DISALLOWED,
                "SP 800-131A Rev.2, Table 4, Section 5",
                "DH/MQV elliptic with len(n)<224 is disallowed",
                f"group = {group}",
                "Migrar a P-256 o superior.",
            ))
        return findings

    if "1024" in gl or "160" in gl:
        findings.append(_state_finding(
            "DH-01",
            "Grupo DH clasico de 1024/160 bits",
            STATUS_DISALLOWED,
            "SP 800-131A Rev.2, Table 4, Section 5",
            "the (1024,160) group is disallowed",
            f"group = {group}",
            "Usar grupos FFDHE de 2048 bits o superiores.",
        ))
    else:
        findings.append(_not_evaluable(
            "DH-05",
            "Curva/grupo ECDHE no listado en SP 800-56A Rev.3",
            "SP 800-131A Rev.2, Table 4, Section 5 + IG A.2",
            "nonconforming schemes are disallowed after 2020",
            f"el grupo {group} no esta en la lista de safe-primes ni de curvas de SP 800-56A.",
        ))

    return findings


def _check_rsa(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 6, Tabla 5 - key transport RSA (refuerza CIPH-06)."""
    findings = []
    negotiated = _negotiated_cipher(data)
    pool = _cipher_pool(data)

    rsa_kt = [cipher for cipher in pool if cipher.startswith("TLS_RSA_")]
    cert = _leaf_cert(data)
    key_size = cert.get("key_size") or 0 if cert else 0

    if rsa_kt:
        if eval_date > RSA_PKCS1V15_CUTOFF:
            findings.append(_state_finding(
                "RSA-02",
                "PKCS#1 v1.5 para transporte de claves RSA, disallowed desde 2024",
                STATUS_DISALLOWED,
                "SP 800-131A Rev.2, Table 5, Section 6",
                "After December 31, 2023, the use of PKCS1-v1_5 padding is disallowed",
                f"cipher suites = {sorted(rsa_kt)}",
                "Deshabilitar cipher suites RSA key-transport; usar solo ECDHE/DHE.",
            ))
        else:
            findings.append(_state_finding(
                "RSA-03",
                "PKCS#1 v1.5 para transporte de claves RSA (deprecated)",
                STATUS_DEPRECATED,
                "SP 800-131A Rev.2, Table 5, Section 6",
                "nonconforming PKCS1-v1_5 is deprecated through 2023",
                f"cipher suites = {sorted(rsa_kt)}",
                "Planificar la migracion a ECDHE/DHE antes del corte de 2023.",
            ))
        if isinstance(key_size, int) and 0 < key_size < 2048:
            findings.append(_state_finding(
                "RSA-01",
                "Clave RSA < 2048 bits en key transport",
                STATUS_DISALLOWED,
                "SP 800-131A Rev.2, Table 5, Section 6",
                "RSA conforming to SP 800-56B with len(n)<2048 is disallowed",
                f"key_size = {key_size}",
                "Usar claves RSA de al menos 2048 bits.",
            ))
    else:
        findings.append(_state_finding(
            "RSA-04",
            "Cifrado de key exchange distinto de RSA key transport",
            STATUS_ACCEPTABLE,
            "SP 800-131A Rev.2, Table 5, Section 6",
            "RSA conforming to SP 800-56B with len(n)>=2048 is acceptable",
            f"cipher = {negotiated or '<none>'}",
            "Ninguna accion requerida.",
        ))

    return findings


def _check_hash(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 9, Tabla 8 - funciones hash en la firma del certificado."""
    findings = []
    cert = _leaf_cert(data)
    if not cert:
        return findings

    sig = str(cert.get("signature_algorithm") or "")
    sl = sig.lower()

    if "sha1" in sl or "sha-1" in sl:
        findings.append(_state_finding(
            "HASH-01",
            "SHA-1 usado para generar la firma digital del certificado",
            STATUS_DISALLOWED,
            "SP 800-131A Rev.2, Table 8, Section 9",
            "SHA-1 is disallowed for digital signature generation",
            f"signature_algorithm = {sig}",
            "Reemitir el certificado con SHA-256 o superior.",
        ))
    elif hash_strength_bits(sig) is not None:
        findings.append(_state_finding(
            "HASH-04",
            "Hash SHA-2/SHA-3 en la firma del certificado",
            STATUS_ACCEPTABLE,
            "SP 800-131A Rev.2, Table 8, Section 9",
            "SHA-2 and SHA-3 are acceptable for all uses",
            f"signature_algorithm = {sig}",
            "Ninguna accion requerida.",
        ))

    return findings


def _check_mac(data: dict, profile: str, eval_date: date) -> list[Finding]:
    """Seccion 10, Tabla 9 - MAC implicito en el cipher suite."""
    findings = []
    negotiated = _negotiated_cipher(data)
    nl = (negotiated or "").lower()

    if "gcm" in nl or "ccm" in nl or "chacha" in nl or "ocb" in nl:
        return findings

    if nl.endswith(("_sha", "_sha1", "-sha1")):
        findings.append(_state_finding(
            "MAC-02",
            "HMAC-SHA-1 como MAC en cipher suite legado",
            STATUS_LEGACY_USE,
            "SP 800-131A Rev.2, Table 9, Section 10",
            "HMAC with key <112 bits is legacy use for verification",
            f"cipher = {negotiated}",
            "Migrar a AES-GCM o HMAC-SHA256 (TLS 1.2 _SHA256).",
        ))

    strength = security_strength_bits("", 0)
    if strength is not None and strength < 112:
        findings.append(_state_finding(
            "MAC-01",
            "Clave HMAC con menos de 112 bits",
            STATUS_DISALLOWED,
            "SP 800-131A Rev.2, Table 9, Section 10",
            "HMAC generation with key <112 bits is disallowed",
            f"cipher = {negotiated}",
            "Usar claves derivadas de al menos 112 bits.",
        ))

    return findings


RULES = [
    ("blk", _check_blk),
    ("sig", _check_sig),
    ("rbg", _check_rbg),
    ("dh", _check_dh),
    ("rsa", _check_rsa),
    ("hash", _check_hash),
    ("mac", _check_mac),
]


# ---------------------------------------------------------------------------
# API publica
# ---------------------------------------------------------------------------


def evaluate(data: dict, profile: str = DEFAULT_PROFILE, evaluation_date: Any = None) -> dict:
    """Evalua el JSON de escaneo contra NIST SP 800-131A Rev.2."""
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

    summary = {
        "disallowed": 0,
        "deprecated": 0,
        "legacy_use": 0,
        "acceptable": 0,
        "not_evaluable": 0,
    }
    for f in findings:
        status = f.get("status") or f.get("severity")
        if status == STATUS_DISALLOWED:
            summary["disallowed"] += 1
        elif status == STATUS_DEPRECATED:
            summary["deprecated"] += 1
        elif status == STATUS_LEGACY_USE:
            summary["legacy_use"] += 1
        elif status == STATUS_ACCEPTABLE:
            summary["acceptable"] += 1
        else:
            summary["not_evaluable"] += 1

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
    }
