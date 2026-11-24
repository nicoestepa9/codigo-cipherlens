"""Clasificacion de fuerza criptografica compartida entre los modulos NIST.

Helpers puros para convertir tamanos de clave, curvas, hash y cipher suites a
"bits de seguridad equivalentes" segun la Tabla 2 de NIST SP 800-57 Part 1
Rev.5 (Seccion 5.6.1.1), y constantes de fecha de corte de NIST SP 800-131A
Rev.2 (Seccion 13 del spec).

Estos helpers son agnosticos del estandar que los consume: los usan los modulos
SP 800-52, SP 800-57 Part 1 y SP 800-131A.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Fechas de corte (SP 800-131A Rev.2, Seccion 13 - configurable, no hardcodeado)
# ---------------------------------------------------------------------------

TDEA_3KEY_CUTOFF = date(2023, 12, 31)  # cifrado, CTR_DRBG, key wrapping, CMAC
RSA_PKCS1V15_CUTOFF = date(2023, 12, 31)  # PKCS#1 v1.5 para key transport
DH_MQV_NONCOMPLIANT_CUTOFF = date(2020, 12, 31)  # esquemas DH/MQV no conformes
RSA_NONCOMPLIANT_OTHER_CUTOFF = date(2020, 12, 31)  # esquemas RSA no conformes

# SP 800-57 Part 1 Rev.5, Tabla 4: la fuerza de 112 bits deja de ser aceptable
# para aplicar proteccion en 2031.
SCHEDULE_112_CUTOFF = date(2030, 12, 31)

# Tipo de extension TLS key_share (RFC 8446)
EXT_KEY_SHARE = 0x0033


def resolve_evaluation_date(data: dict, evaluation_date: Any = None) -> date:
    """Resuelve la fecha de evaluacion usada por las reglas de transicion.

    Prioridad: parametro explicito > `_meta.scan_time` del archivo > hoy.
    """
    if evaluation_date is not None:
        if isinstance(evaluation_date, date):
            return evaluation_date
        try:
            return date.fromisoformat(str(evaluation_date))
        except ValueError:
            pass

    meta = data.get("_meta") if isinstance(data, dict) else None
    scan_time = (meta or {}).get("scan_time")
    if scan_time:
        try:
            return datetime.fromisoformat(str(scan_time).replace("Z", "+00:00")).date()
        except ValueError:
            pass

    return datetime.now(timezone.utc).date()


# ---------------------------------------------------------------------------
# Bits de seguridad equivalentes (SP 800-57 Part 1 Rev.5, Tabla 2, Seccion 5.6.1.1)
# ---------------------------------------------------------------------------


def security_strength_bits(key_type: Any, key_size: Any) -> int | None:
    """Bits de seguridad equivalentes para un tipo/tamano de clave.

    Tabla 2: RSA k=2048->112, 3072->128; ECC f=224-255->112, 256-383->128;
    FFC L=2048->112, 3072->128; simetrico 128/192/256.
    """
    kt = str(key_type or "")
    ks = key_size if isinstance(key_size, int) else 0

    if "RSA" in kt:
        if ks <= 0:
            return None
        if ks >= 15360:
            return 256
        if ks >= 7680:
            return 192
        if ks >= 3072:
            return 128
        if ks >= 2048:
            return 112
        return 80  # 1024..2047

    if "EC" in kt or "Ed" in kt:
        if ks <= 0:
            return None
        if ks >= 512:
            return 256
        if ks >= 384:
            return 192
        if ks >= 256:
            return 128
        if ks >= 224:
            return 112
        return 80  # curvas menores a P-224

    if "DSA" in kt or "DH" in kt:
        if ks <= 0:
            return None
        if ks >= 15360:
            return 256
        if ks >= 7680:
            return 192
        if ks >= 3072:
            return 128
        if ks >= 2048:
            return 112
        if ks >= 1024:
            return 80
        return None

    if "AES" in kt:
        return ks if ks in (128, 192, 256) else None

    return None


def hash_strength_bits(algorithm: Any) -> int | None:
    """Bits de seguridad de una funcion hash (SP 800-57 Part 1 Rev.5, Tabla 3)."""
    a = str(algorithm or "").lower().replace("-", "").replace("_", "")
    if "sha512" in a:
        return 256
    if "sha384" in a:
        return 192
    if "sha256" in a:
        return 128
    if "sha224" in a:
        return 112
    if "sha1" in a or a == "sha":
        return 80
    return None


_OPENSSL_AES_SUITE = re.compile(
    r"(?:(ECDHE-ECDSA|ECDHE-RSA|DHE-RSA|DHE-DSS|ECDH-ECDSA|ECDH-RSA)-)?"
    r"AES(128|256)(?:-(GCM))?-(SHA|SHA256|SHA384)"
)


def normalize_cipher_name(name: str) -> str:
    """Canonicalize OpenSSL AES suite names whose IANA structure is known."""
    alias = name.strip().upper()
    match = _OPENSSL_AES_SUITE.fullmatch(alias)
    if not match:
        return alias
    exchange, bits, mode, digest = match.groups()
    exchange = exchange.replace("-", "_") if exchange else "RSA"
    return f"TLS_{exchange}_WITH_AES_{bits}_{mode or 'CBC'}_{digest}"


def cipher_strength_bits(cipher_name: Any) -> int | None:
    """Bits de seguridad del componente simetrico de un cipher suite."""
    n = str(cipher_name or "").upper()
    if "CHACHA20" in n:
        return 256
    if "AES_256" in n or "AES256" in n or "AES-256" in n:
        return 256
    if "AES_192" in n or "AES192" in n or "AES-192" in n:
        return 192
    if "AES_128" in n or "AES128" in n or "AES-128" in n:
        return 128
    if "3DES" in n or "TDEA" in n or "DES-CBC3" in n or "DES-EDE3" in n:
        return 112
    if "DES" in n:
        return 56
    if "AES" in n:
        return 128
    return None


# ---------------------------------------------------------------------------
# Grupos TLS del key_share
# ---------------------------------------------------------------------------


def _group_name(raw: Any) -> str:
    s = str(raw or "").strip()
    if "(" in s and ")" in s:
        return s[s.index("(") + 1 : s.index(")")].strip().lower()
    return s.lower()


def key_share_group_name(data: dict) -> str:
    """Nombre normalizado del grupo del key_share (ej. 'x25519', 'secp256r1')."""
    she = (data.get("handshake") or {}).get("server_hello_extensions") or {}
    exts = she.get("extensions") if isinstance(she, dict) else None
    if not exts:
        return ""
    for e in exts:
        if isinstance(e, dict) and e.get("type") == EXT_KEY_SHARE:
            return _group_name(e.get("group"))
    return ""


_EC_GROUP_BITS = {
    "x25519": 128,
    "x448": 224,
    "secp256r1": 128,
    "prime256v1": 128,
    "p-256": 128,
    "secp384r1": 192,
    "p-384": 192,
    "secp521r1": 256,
    "p-521": 256,
    "secp224r1": 112,
    "p-224": 112,
    "secp192r1": 96,
    "p-192": 96,
    "secp160r1": 80,
    "secp160r2": 80,
    "secp160k1": 80,
}

_FFDHE_BITS = {
    "ffdhe2048": 112,
    "ffdhe3072": 128,
    "ffdhe4096": 128,
    "ffdhe6144": 192,
    "ffdhe8192": 192,
}

_NIST_APPROVED_EC = {
    "secp256r1",
    "prime256v1",
    "p-256",
    "secp384r1",
    "p-384",
    "secp521r1",
    "p-521",
}


def ec_group_security_bits(name: Any) -> int | None:
    """Bits de seguridad de una curva ECDHE (orden del grupo)."""
    return _EC_GROUP_BITS.get(_group_name(name))


_EC_ORDER_BITS = {
    "x25519": 255,
    "x448": 448,
    "secp256r1": 256,
    "prime256v1": 256,
    "p-256": 256,
    "secp256k1": 256,
    "secp384r1": 384,
    "p-384": 384,
    "secp521r1": 521,
    "p-521": 521,
    "secp224r1": 224,
    "p-224": 224,
    "secp192r1": 192,
    "p-192": 192,
    "secp160r1": 160,
    "secp160r2": 160,
    "secp160k1": 160,
    "b-163": 163,
    "k-163": 163,
    "brainpoolp256r1": 256,
    "brainpoolp256t1": 256,
    "brainpoolp384r1": 384,
    "brainpoolp384t1": 384,
    "brainpoolp512r1": 512,
    "brainpoolp512t1": 512,
    "ed25519": 255,
    "ed448": 448,
}


def ec_group_order_bits(name: Any) -> int | None:
    """Longitud del orden n de una curva (len(n)), tal como la usa SP 800-131A.

    Distinto de la fuerza de seguridad: para P-256, len(n)=256 bits pero la
    fuerza es 128 bits. SP 800-131A formula sus reglas con len(n) (>=224).
    """
    return _EC_ORDER_BITS.get(_group_name(name))


def ffdhe_group_security_bits(name: Any) -> int | None:
    """Bits de seguridad de un grupo DH finite-field (RFC 7919)."""
    return _FFDHE_BITS.get(_group_name(name))


def is_nist_approved_ec_curve(name: Any) -> bool:
    """True si la curva figura en SP 800-56A (P-256/P-384/P-521)."""
    return _group_name(name) in _NIST_APPROVED_EC
