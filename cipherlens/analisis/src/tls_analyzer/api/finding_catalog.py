"""Catalogo server-side de hallazgos aceptados en la ingesta de agentes."""

from __future__ import annotations

from dataclasses import dataclass

from ..ai_safety import (
    AI_FIELD_MAX_LEN,
    is_prompt_injection_attempt,
    sanitize_untrusted_value,
)

STANDARD_80052 = "80052"
STANDARD_80057 = "80057"
STANDARD_800131A = "800131a"

STANDARD_NAMES = {
    STANDARD_80052: "NIST SP 800-52 Rev.2 (Aug 2019)",
    STANDARD_80057: "NIST SP 800-57 Part 1 Rev.5 (May 2020)",
    STANDARD_800131A: "NIST SP 800-131A Rev.2 (March 2019)",
}


class InvalidAgentFinding(ValueError):
    """Finding de agente fuera del catalogo o con evidencia invalida."""


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    severity: str
    section: str
    citation: str
    recommendation: str
    category: str
    standard: str
    evaluable: bool = True


_CATEGORY_FOR_PREFIX = {
    "PROTO": "Protocol",
    "CERT": "Certificate",
    "CIPH": "Cipher Suite",
    "EXT": "Extension",
    "COMP": "Compression",
    "NE": "Not Evaluable",
    "KEY": "Key Management",
    "HASH": "Hash",
    "SCHED": "Key Schedule",
    "COMBO": "Combination",
    "PQC": "Post-Quantum",
    "CRYPTO": "Cryptoperiod",
    "REDUCE": "Strength Reduction",
    "BLK": "Block Cipher",
    "SIG": "Signature",
    "RBG": "Random Bit Generator",
    "DH": "Key Agreement",
    "RSA": "RSA Key Transport",
    "MAC": "MAC",
}


def _standard_for(rule_id: str) -> str:
    if rule_id.startswith(("BLK-", "SIG-", "RBG-", "DH-", "RSA-", "MAC-")):
        return STANDARD_800131A
    if rule_id == "HASH-04":
        return STANDARD_800131A
    if rule_id.startswith(
        ("KEY-", "HASH-", "SCHED-", "COMBO-", "PQC-", "CRYPTO-", "REDUCE-")
    ):
        return STANDARD_80057
    return STANDARD_80052


def _make(
    rule_id: str,
    title: str,
    severity: str,
    section: str,
    citation: str,
    recommendation: str,
    *,
    evaluable: bool = True,
) -> RuleInfo:
    prefix = rule_id.split("-", 1)[0]
    return RuleInfo(
        rule_id=rule_id,
        title=title,
        severity=severity.lower(),
        section=section,
        citation=citation,
        recommendation=recommendation,
        category=_CATEGORY_FOR_PREFIX.get(prefix, "NIST"),
        standard=_standard_for(rule_id),
        evaluable=evaluable,
    )


_RAW: dict[str, tuple[str, str, str, str, str]] = {
    "PROTO-01": (
        "SSL 2.0/3.0 habilitado",
        "CRITICAL",
        "SP 800-52 Rev.2, Section 3.1",
        "shall not use TLS 1.0, SSL 3.0, or SSL 2.0",
        "Deshabilitar SSL 2.0 y SSL 3.0 por completo.",
    ),
    "PROTO-02": (
        "TLS 1.0 habilitado",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.1",
        "use of TLS versions 1.1 and 1.0 is generally discouraged",
        "Deshabilitar TLS 1.0 salvo justificacion de interoperabilidad (Apendice F).",
    ),
    "PROTO-03": (
        "TLS 1.0/TLS 1.1 habilitado (perfil government-only)",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.1",
        "shall not use TLS 1.0; should not be configured to use TLS 1.1",
        "Deshabilitar TLS 1.0 y TLS 1.1.",
    ),
    "PROTO-04": (
        "TLS 1.2 ausente",
        "CRITICAL",
        "SP 800-52 Rev.2, Section 3.1",
        "shall be configured to negotiate TLS 1.2",
        "Habilitar TLS 1.2 como minimo obligatorio.",
    ),
    "PROTO-05": (
        "TLS 1.3 ausente",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.1",
        "shall support TLS 1.3 by January 1, 2024",
        "Habilitar TLS 1.3 (obligatorio desde el 1 de enero de 2024).",
    ),
    "PROTO-06": (
        "Negociacion de version no verificable",
        "INFO",
        "SP 800-52 Rev.2, Section 3.1",
        "Servers that incorrectly implement TLS version negotiation shall not be used",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "CERT-01": (
        "Certificado expirado",
        "CRITICAL",
        "SP 800-52 Rev.2, Table 3-1",
        "Validity period must be current",
        "Renovar el certificado inmediatamente.",
    ),
    "CERT-02": (
        "Vigencia mayor a 3 anios",
        "MEDIUM",
        "SP 800-52 Rev.2, Table 3-1",
        "Validity Period: 3 years or less",
        "Emitir certificados con vigencia de 3 anios o menos.",
    ),
    "CERT-03": (
        "Clave RSA menor a 2048 bits",
        "CRITICAL",
        "SP 800-52 Rev.2, Table 3-1",
        "2048-bit RSA key modulus or other approved lengths",
        "Usar claves RSA de al menos 2048 bits.",
    ),
    "CERT-04": (
        "Curva EC no aprobada",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.2",
        "either curve P-256 or curve P-384 should be used",
        "Usar P-256 o P-384.",
    ),
    "CERT-05": (
        "Fuerza de clave menor a 112 bits",
        "CRITICAL",
        "SP 800-52 Rev.2, Section 3.2.1",
        "public key and signature shall provide at least 112 bits of security",
        "Usar claves con al menos 112 bits de seguridad equivalente.",
    ),
    "CERT-06": (
        "Firma con MD5 o SHA-1",
        "CRITICAL",
        "SP 800-52 Rev.2, Table 3-1",
        "only sha256WithRSAEncryption or stronger signatures allowed",
        "Reemplazar la firma por sha256WithRSAEncryption, ecdsa-with-SHA256 o superior.",
    ),
    "CERT-07": (
        "Sin Subject Alternative Names",
        "HIGH",
        "SP 800-52 Rev.2, Table 3-1",
        "SAN: Required",
        "Agregar el/los hostname/s al campo SAN del certificado.",
    ),
    "CERT-08": (
        "Extended Key Usage sin serverAuth",
        "MEDIUM",
        "SP 800-52 Rev.2, Table 3-1",
        "id-kp-serverAuth ... Required",
        "Incluir id-kp-serverAuth (1.3.6.1.5.5.7.3.1) en el EKU.",
    ),
    "CERT-09": (
        "Sin fuente de revocacion (OCSP)",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.2",
        "CA shall publish revocation information in OCSP responses",
        "Configurar un responder OCSP en el AIA del certificado.",
    ),
    "CERT-10": (
        "Sin CA Issuers en AIA",
        "MEDIUM",
        "SP 800-52 Rev.2, Table 3-1",
        "Authority Information Access... Required",
        "Agregar el enlace al certificado del emisor en el AIA.",
    ),
    "CERT-11": (
        "Certificado autofirmado",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.2.3",
        "certificates shall be issued by a trusted CA",
        "Usar un certificado emitido por una CA de confianza publica o propia gestionada.",
    ),
    "CERT-12": (
        "Basic Constraints CA=True en certificado hoja",
        "HIGH",
        "SP 800-52 Rev.2, Table 3-1",
        "end-entity certificate shall not assert CA capability",
        "Emitir el certificado hoja sin la capacidad de CA.",
    ),
    "CIPH-01": (
        "3DES/DES en uso",
        "CRITICAL",
        "SP 800-52 Rev.2, Section 3.3.1.1",
        "3DES cipher suites are no longer allowed",
        "Remover todos los cipher suites 3DES/DES.",
    ),
    "CIPH-02": (
        "Cipher suite negociada fuera de las listas permitidas",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.3.1",
        "cipher suites not in this section, Appendix C, or Appendix D shall not be used",
        "Configurar solo cipher suites de la Seccion 3.3.1, Apendice C o D.",
    ),
    "CIPH-03": (
        "Sin Forward Secrecy",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.3.1",
        "DHE/ECDHE preferred for perfect forward secrecy",
        "Priorizar cipher suites DHE/ECDHE.",
    ),
    "CIPH-04": (
        "Clave efimera menor a 112 bits",
        "CRITICAL",
        "SP 800-52 Rev.2, Section 3.3.1",
        "each ephemeral key-pair shall have at least 112 bits of security",
        "Usar grupos DHE/ECDHE con al menos 112 bits de seguridad.",
    ),
    "CIPH-05": (
        "Preferencia de servidor no sigue el orden recomendado",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.3.1.1",
        "prefer ECDHE/DHE, then GCM/CCM over CBC",
        "Configurar la preferencia: DHE/ECDHE, luego GCM/CCM antes que CBC.",
    ),
    "CIPH-06": (
        "RSA key transport en uso",
        "HIGH",
        "SP 800-52 Rev.2, Appendix D",
        "this guideline does not recommend cipher suites that use RSA key transport",
        "Migrar a suites con DHE/ECDHE.",
    ),
    "CIPH-07": (
        "CBC sin Encrypt-then-MAC",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.4.2.7",
        "servers negotiating CBC shall support encrypt_then_mac",
        "Soportar la extension encrypt_then_mac (0x0016) o eliminar CBC.",
    ),
    "CIPH-08": (
        "Cipher TLS 1.3 fuera de la lista permitida",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.3.1.2",
        "only four TLS 1.3 cipher suites are acceptable",
        "Usar una de las 4 suites TLS 1.3 permitidas.",
    ),
    "EXT-01": (
        "Renegotiation Indication ausente",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.4.1.1",
        "renegotiation_info extension is mandatory",
        "Habilitar la extension renegotiation_info (RFC 5746).",
    ),
    "EXT-02": (
        "Extended Master Secret ausente (TLS <= 1.2)",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.4.1.3",
        "extended_master_secret extension is mandatory",
        "Habilitar extended_master_secret (RFC 7627).",
    ),
    "EXT-03": (
        "OCSP stapling (status_request) ausente",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.4.1.5",
        "status_request extension is mandatory",
        "Habilitar el OCSP stapling (status_request).",
    ),
    "EXT-04": (
        "Supported Groups ausente",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.4.2.2",
        "supported_groups extension is conditionally mandatory",
        "Indicar los grupos soportados mediante supported_groups.",
    ),
    "EXT-05": (
        "Key Share ausente en TLS 1.3",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.4.2.3",
        "key_share extension is mandatory for TLS 1.3",
        "El ServerHello TLS 1.3 debe incluir key_share.",
    ),
    "EXT-06": (
        "Raw Public Keys presente",
        "CRITICAL",
        "SP 800-52 Rev.2, Section 3.4.3.3",
        "raw public keys shall not be supported",
        "Deshabilitar el uso de raw public keys.",
    ),
    "EXT-07": (
        "Client Certificate URL presente",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.4.3.1",
        "client_certificate_url is discouraged",
        "Eliminar el soporte de client_certificate_url.",
    ),
    "EXT-08": (
        "Early Data / 0-RTT presente",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.4.3.2",
        "early_data is discouraged",
        "Deshabilitar 0-RTT.",
    ),
    "EXT-09": (
        "Fallback SCSV no verificable",
        "MEDIUM",
        "SP 800-52 Rev.2, Section 3.4.2.1",
        "TLS_FALLBACK_SCSV shall be supported to prevent downgrade",
        "Garantizar soporte de TLS_FALLBACK_SCSV (0x5600).",
    ),
    "COMP-01": (
        "Metodo de compresion distinto de null",
        "HIGH",
        "SP 800-52 Rev.2, Section 3.7",
        "null compression shall be enabled, all others disabled",
        "Habilitar solo el metodo de compresion null.",
    ),
    "NE-01": (
        "Validacion de modulo criptografico FIPS 140",
        "INFO",
        "SP 800-52 Rev.2, Section 3.3.3",
        "cryptographic modules shall be validated to FIPS 140",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "NE-02": (
        "Comportamiento de renegociacion ante splicing",
        "INFO",
        "SP 800-52 Rev.2, Section 3.4.1.1",
        "renegotiation shall be resistant to splicing attacks",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "NE-03": (
        "Gestion del trust anchor store",
        "INFO",
        "SP 800-52 Rev.2, Section 3.5.2",
        "trust anchors shall be managed and protected",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "NE-04": (
        "Comportamiento ante 0-RTT real",
        "INFO",
        "SP 800-52 Rev.2, Section 3.6",
        "0-RTT data shall be treated as replayable",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "NE-05": (
        "Parcheo y actualizacion del sistema operativo",
        "INFO",
        "SP 800-52 Rev.2, Section 3.8",
        "servers shall be patched and updated",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "KEY-01": (
        "Clave RSA por debajo de 112 bits de seguridad",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Table 2, Section 5.6.1.1",
        "RSA with k<2048 provides less than 112 bits; not approved for applying protection",
        "Usar claves RSA de al menos 2048 bits.",
    ),
    "KEY-02": (
        "Clave EC/EdDSA por debajo de 112 bits",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Table 2, Section 5.6.1.1",
        "ECC with f<224 provides less than 112 bits of security",
        "Usar curvas de 224 bits o superiores (P-256, P-384).",
    ),
    "KEY-03": (
        "Clave DSA/DH (FFC) por debajo de 112 bits",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Table 2, Section 5.6.1.1",
        "FFC with L<2048 provides less than 112 bits of security",
        "Usar grupos DSA/DH con L>=2048 y N>=224.",
    ),
    "KEY-04": (
        "Uso de 2TDEA",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Table 2, Section 5.6.1.1",
        "2TDEA provides at most 80 bits of security; not approved",
        "Eliminar cualquier cipher suite basado en 2TDEA.",
    ),
    "KEY-05": (
        "Uso de 3TDEA (3DES), disallowed desde 2023",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Table 2 footnote 68, Section 5.6.1.1",
        "3TDEA is deprecated through 2023, after which it will be disallowed",
        "Eliminar cipher suites 3DES; migrar a AES-GCM.",
    ),
    "KEY-06": (
        "Algoritmo/clave por debajo de 112 bits",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Section 5.6.1.1",
        "less than 112 bits of security is not approved for applying protection",
        "Migrar a claves con al menos 112 bits de seguridad.",
    ),
    "KEY-07": (
        "Clave con exactamente 112 bits de seguridad",
        "INFO",
        "SP 800-57 Part 1 Rev.5, Table 4, Section 5.6.3",
        "112 bits is acceptable until 2030; disallowed after 2031",
        "Planificar la migracion a 128 bits (AES-128 / P-256) antes de 2031.",
    ),
    "HASH-01": (
        "SHA-1 usado para firma digital",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Table 3, Section 5.6.1.2",
        "SHA-1 provides less than 80 bits of security for digital signatures",
        "Usar SHA-256 o superior en el certificado.",
    ),
    "HASH-02": (
        "Hash con menos de 112 bits usado para proteger informacion nueva",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Section 5.6.1.2",
        "no longer approved for applying cryptographic protection",
        "Reemplazar la firma por SHA-256 o superior.",
    ),
    "HASH-03": (
        "Combinacion firma+hash con fuerza mixta",
        "MEDIUM",
        "SP 800-57 Part 1 Rev.5, Section 5.6.2",
        "the combination provides no more than the weaker of the two algorithms",
        "Alinear la fuerza del hash y de la clave de firma.",
    ),
    "SCHED-01": (
        "Fuerza de 112 bits usada para aplicar proteccion despues de 2030",
        "HIGH",
        "SP 800-57 Part 1 Rev.5, Table 4, Section 5.6.3",
        "Applying protection: Disallowed for 112 bits in 2031+",
        "Migrar a 128 bits antes de 2031.",
    ),
    "SCHED-02": (
        "Fuerza menor a 112 bits",
        "CRITICAL",
        "SP 800-57 Part 1 Rev.5, Table 4, Section 5.6.3",
        "Applying protection: Disallowed for <112 bits",
        "Migrar a claves con al menos 128 bits.",
    ),
    "SCHED-03": (
        "Certificado con clave de 112 bits vigente despues de 2030",
        "HIGH",
        "SP 800-57 Part 1 Rev.5, Table 4 + Section 5.6.4",
        "protection should not extend beyond the algorithm security lifetime",
        "Emitir la clave siguiente con al menos 128 bits.",
    ),
    "SCHED-04": (
        "Fuerza de clave aceptable",
        "INFO",
        "SP 800-57 Part 1 Rev.5, Table 4, Section 5.6.3",
        "strength >= 128 bits is acceptable in both periods",
        "Ninguna accion requerida.",
    ),
    "COMBO-02": (
        "Key agreement de fuerza menor que el algoritmo simetrico derivado",
        "MEDIUM",
        "SP 800-57 Part 1 Rev.5, Section 5.6.2",
        "the combination can provide no more than the weaker key agreement",
        "Usar un grupo de key exchange con al menos la fuerza del cipher.",
    ),
    "COMBO-03": (
        "Reutilizacion de clave de key-agreement como clave de firma no verificable",
        "INFO",
        "SP 800-57 Part 1 Rev.5, Section 5.6.2.d",
        "the key used for key agreement shall be different from the ECDSA key used for digital signatures",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "COMBO-04": (
        "Clave fuerte procesada por algoritmo mas debil no verificable",
        "INFO",
        "SP 800-57 Part 1 Rev.5, Section 5.6.2",
        "a strong key wrapped by a weaker process loses security strength",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "PQC-01": (
        "Vigilancia post-cuantica",
        "INFO",
        "SP 800-57 Part 1 Rev.5, Section 5.6.1.1",
        "may need replacement with post-quantum counterparts when practical quantum computers exist",
        "Monitorear el cronograma de migracion a algoritmos post-cuanticos.",
    ),
    "CRYPTO-01": (
        "Vigencia del certificado mayor a 3 anios",
        "MEDIUM",
        "SP 800-57 Part 1 Rev.5, Section 5.3.6, item 1.b",
        "a maximum cryptoperiod of about one to three years is recommended",
        "Emitir certificados con vigencia de 3 anios o menos.",
    ),
    "CRYPTO-02": (
        "Uso real de la clave privada mas alla de su cryptoperiod no verificable",
        "INFO",
        "SP 800-57 Part 1 Rev.5, Section 5.3.4",
        "cryptoperiod of a public key is not the same as certificate validity",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "REDUCE-01": (
        "Firma debilitada - proteccion por SCT no verificable",
        "INFO",
        "SP 800-57 Part 1 Rev.5, Section 5.6.5",
        "the signature may still be valid if adequately protected by a stronger algorithm",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "REDUCE-02": (
        "Informacion previamente protegida puede haber perdido seguridad",
        "INFO",
        "SP 800-57 Part 1 Rev.5, Section 5.6.5",
        "information protected with now-inadequate algorithms may no longer be secure",
        "Evaluar re-firmar o migrar la informacion protegida.",
    ),
    "BLK-01": (
        "Two-key TDEA usado para cifrar",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 1, Section 2",
        "Encryption using two-key TDEA is disallowed",
        "Eliminar cipher suites con 2TDEA.",
    ),
    "BLK-02": (
        "Three-key TDEA (3DES) usado para cifrar despues de 2023",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 1, Section 2",
        "After December 31, 2023, three-key TDEA is disallowed for encryption",
        "Eliminar cipher suites 3DES; migrar a AES-GCM.",
    ),
    "BLK-03": (
        "Three-key TDEA (3DES) usado para cifrar (deprecated)",
        "MEDIUM",
        "SP 800-131A Rev.2, Table 1, Section 2",
        "three-key TDEA is deprecated through December 31, 2023",
        "Planificar la migracion a AES antes del corte de 2023.",
    ),
    "BLK-04": (
        "SKIPJACK detectado en cifrado",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 1, Section 2",
        "The use of SKIPJACK for encryption is disallowed",
        "Eliminar cualquier cipher suite basado en SKIPJACK.",
    ),
    "BLK-06": (
        "AES en modo ECB o con clave inferior a 128 bits",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 1, Section 2",
        "AES key lengths approved by SP 800-131A are 128, 192 and 256 bits; CipherLens disallows ECB in TLS",
        "Usar una suite TLS AES-GCM o AES-CCM con una clave de al menos 128 bits.",
    ),
    "BLK-05": (
        "AES-128/192/256 en uso",
        "INFO",
        "SP 800-131A Rev.2, Table 1, Section 2",
        "AES-128/192/256 is acceptable for encryption",
        "Ninguna accion requerida.",
    ),
    "SIG-01": (
        "Clave RSA < 2048 bits usada para firmar",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 2, Section 3",
        "RSA with len(n)<2048 shall not generate digital signatures",
        "Usar claves RSA de al menos 2048 bits.",
    ),
    "SIG-03": (
        "Curva ECDSA/EdDSA con len(n) < 224 bits",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 2, Section 3, p.10",
        "the length of n shall be at least 224 bits",
        "Usar curvas de 224 bits o superiores.",
    ),
    "SIG-04": (
        "Curva ECDSA de 160-223 bits (legacy use)",
        "INFO",
        "SP 800-131A Rev.2, Section 3, p.10",
        "B-163, K-163 and P-192 may continue to be used for signature verification only",
        "Migrar a P-256 o superior.",
    ),
    "SIG-05": (
        "DSA con parametros fuera de los pares aprobados",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 2, Section 3",
        "DSA with L,N outside the approved pairs is disallowed for signature generation",
        "Migrar a ECDSA/RSA con parametros aprobados.",
    ),
    "SIG-06": (
        "Parametros de firma aprobados",
        "INFO",
        "SP 800-131A Rev.2, Table 2, Section 3",
        "signature parameters conform to the approved sizes",
        "Ninguna accion requerida.",
    ),
    "RBG-01": (
        "Generador de bits aleatorios (RBG) del servidor",
        "INFO",
        "SP 800-131A Rev.2, Table 3, Section 4",
        "Dual_EC_DRBG and 3TDEA-based CTR_DRBG are disallowed",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "DH-01": (
        "Grupo DH clasico de 1024/160 bits",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 4, Section 5",
        "the (1024,160) group is disallowed",
        "Usar grupos FFDHE de 2048 bits o superiores.",
    ),
    "DH-02": (
        "Grupo DH de fuerza menor a 112 bits",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 4, Section 5",
        "DH/MQV with less than 112 bits of security strength is disallowed",
        "Usar grupos FFDHE de 2048 bits o superiores.",
    ),
    "DH-04": (
        "Curva ECDHE con len(n) < 224 bits",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 4, Section 5",
        "DH/MQV elliptic with len(n)<224 is disallowed",
        "Migrar a P-256 o superior.",
    ),
    "DH-05": (
        "Curva ECDHE no identificada o no listada",
        "INFO",
        "SP 800-131A Rev.2, Table 4, Section 5 + IG A.2",
        "curves not listed in SP 800-56A Rev.3 require case-by-case assessment",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "DH-06": (
        "Grupo de key exchange conforme",
        "INFO",
        "SP 800-131A Rev.2, Table 4, Section 5",
        "DH/MQV conforming to SP 800-56A is acceptable",
        "Ninguna accion requerida.",
    ),
    "RSA-01": (
        "Clave RSA < 2048 bits en key transport",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 5, Section 6",
        "RSA conforming to SP 800-56B with len(n)<2048 is disallowed",
        "Usar claves RSA de al menos 2048 bits.",
    ),
    "RSA-02": (
        "PKCS#1 v1.5 para transporte de claves RSA, disallowed desde 2024",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 5, Section 6",
        "After December 31, 2023, the use of PKCS1-v1_5 padding is disallowed",
        "Deshabilitar cipher suites RSA key-transport; usar solo ECDHE/DHE.",
    ),
    "RSA-03": (
        "PKCS#1 v1.5 para transporte de claves RSA (deprecated)",
        "MEDIUM",
        "SP 800-131A Rev.2, Table 5, Section 6",
        "nonconforming PKCS1-v1_5 is deprecated through 2023",
        "Planificar la migracion a ECDHE/DHE antes del corte de 2023.",
    ),
    "RSA-04": (
        "Cifrado de key exchange distinto de RSA key transport",
        "INFO",
        "SP 800-131A Rev.2, Table 5, Section 6",
        "RSA conforming to SP 800-56B with len(n)>=2048 is acceptable",
        "Ninguna accion requerida.",
    ),
    "HASH-04": (
        "Hash SHA-2/SHA-3 en la firma del certificado",
        "INFO",
        "SP 800-131A Rev.2, Table 8, Section 9",
        "SHA-2 and SHA-3 are acceptable for all uses",
        "Ninguna accion requerida.",
    ),
    "MAC-01": (
        "Clave HMAC con menos de 112 bits",
        "CRITICAL",
        "SP 800-131A Rev.2, Table 9, Section 10",
        "HMAC generation with key <112 bits is disallowed",
        "Usar claves derivadas de al menos 112 bits.",
    ),
    "MAC-02": (
        "HMAC-SHA-1 como MAC en cipher suite legado",
        "INFO",
        "SP 800-131A Rev.2, Table 9, Section 10",
        "HMAC with key <112 bits is legacy use for verification",
        "Migrar a AES-GCM o HMAC-SHA256 (TLS 1.2 _SHA256).",
    ),
}

_NOT_EVALUABLE_RAW: dict[str, tuple[str, str, str, str, str]] = {
    "CERT-09": (
        "Fuente de revocacion (OCSP) no verificable",
        "INFO",
        "SP 800-52 Rev.2, Section 3.2",
        "certificates issued by a CA that publishes revocation information in OCSP responses",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "CERT-10": (
        "CA Issuers en AIA no verificable",
        "INFO",
        "SP 800-52 Rev.2, Table 3-1",
        "Authority Information Access... Required",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "DH-02": (
        "Grupo DH finito (DHE) sin parametros identificables",
        "INFO",
        "SP 800-131A Rev.2, Table 4, Section 5",
        "DH/MQV finite-field with len(p)<2048 is disallowed",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
    "DH-06": (
        "Grupo de key exchange no identificado",
        "INFO",
        "SP 800-131A Rev.2, Table 4, Section 5",
        "DH/MQV elliptic conforming groups with len(n)>=224 are acceptable",
        "Requiere prueba activa o acceso a la configuracion del servidor.",
    ),
}

_NOT_EVALUABLE_IDS = {
    "PROTO-06",
    "NE-01",
    "NE-02",
    "NE-03",
    "NE-04",
    "NE-05",
    "COMBO-03",
    "COMBO-04",
    "CRYPTO-02",
    "REDUCE-01",
    "RBG-01",
    "DH-05",
}

RULES: dict[str, RuleInfo] = {
    rule_id: _make(
        rule_id,
        *data,
        evaluable=rule_id not in _NOT_EVALUABLE_IDS,
    )
    for rule_id, data in _RAW.items()
}

NOT_EVALUABLE_RULES: dict[str, RuleInfo] = {
    rule_id: _make(rule_id, *data, evaluable=False)
    for rule_id, data in _NOT_EVALUABLE_RAW.items()
}

_TEXT_FIELDS = (
    "title",
    "description",
    "recommendation",
    "citation",
    "sectionReference",
    "reference",
    "category",
    "evidence",
    "observedValue",
)


def _resolve_rule(rule_id: str, raw: dict) -> RuleInfo:
    rule = RULES[rule_id]
    if rule_id in NOT_EVALUABLE_RULES and raw.get("evaluable") is False:
        return NOT_EVALUABLE_RULES[rule_id]
    return rule


def canonicalize_findings(
    raw_findings: list[dict],
    *,
    host: str,
) -> tuple[list[dict], bool]:
    findings: list[dict] = []
    suspicious = False
    for raw in raw_findings:
        if not isinstance(raw, dict):
            raise InvalidAgentFinding("Formato de finding invalido")
        rule_id = raw.get("ruleId") or raw.get("id")
        if not isinstance(rule_id, str) or rule_id not in RULES:
            raise InvalidAgentFinding("findings contiene una regla desconocida")
        evidence = raw.get("evidence")
        if evidence is None:
            evidence = raw.get("observedValue")
        if evidence is not None and not isinstance(evidence, str):
            raise InvalidAgentFinding("La evidencia del finding debe ser texto")
        evidence = sanitize_untrusted_value(
            evidence or "",
            max_len=AI_FIELD_MAX_LEN,
        )
        for field in _TEXT_FIELDS:
            value = raw.get(field)
            if isinstance(value, str) and is_prompt_injection_attempt(value):
                suspicious = True
        rule = _resolve_rule(rule_id, raw)
        findings.append(
            {
                "id": rule.rule_id,
                "ruleId": rule.rule_id,
                "title": rule.title,
                "description": rule.citation,
                "evidence": evidence,
                "observedValue": evidence,
                "recommendation": rule.recommendation,
                "reference": rule.section,
                "sectionReference": rule.section,
                "citation": rule.citation,
                "severity": rule.severity,
                "category": rule.category,
                "affectedHost": host,
                "sourceDocument": rule.standard,
                "standards": [STANDARD_NAMES[rule.standard]],
                "ruleIds": [rule.rule_id],
                "evaluable": rule.evaluable,
                "status": None if rule.evaluable else "NOT_EVALUABLE",
            }
        )
    return findings, suspicious
