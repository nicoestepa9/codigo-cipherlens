"""Registro canonico de defectos para deduplicar hallazgos entre estandares.

El scan general agrupa los hallazgos de los tres estandares (SP 800-52, SP
800-57 Part 1 y SP 800-131A) por una clave canonica de defecto subyacente, de
modo que el mismo problema (ej. clave RSA de 1024 bits) no se triplique en el
resultado. Cada finding agregado lista que estandares y que reglas lo
detectaron.

Una regla sin mapeo explicito queda como issue singleton con su propio id
prefijado (ej. ``800131a-RBG-01``), por lo que jamas colisiona con otra.
"""

from __future__ import annotations

STANDARD_80052 = "80052"
STANDARD_80057 = "80057"
STANDARD_800131A = "800131a"

STANDARD_NAMES = {
    STANDARD_80052: "NIST SP 800-52 Rev.2",
    STANDARD_80057: "NIST SP 800-57 Part 1 Rev.5",
    STANDARD_800131A: "NIST SP 800-131A Rev.2",
}

STANDARD_ORDER = (STANDARD_80052, STANDARD_80057, STANDARD_800131A)

# rule_id prefijado con el estandar -> clave canonica de defecto subyacente
ISSUE_OF = {
    # --- SP 800-52 Rev.2 ---
    "80052-PROTO-01": "ssl23_enabled",
    "80052-PROTO-02": "tls10_enabled",
    "80052-PROTO-03": "tls10_11_enabled",
    "80052-PROTO-04": "tls12_missing",
    "80052-PROTO-05": "tls13_missing",
    "80052-CERT-01": "cert_expired",
    "80052-CERT-02": "cert_long_validity",
    "80052-CERT-03": "weak_rsa_key",
    "80052-CERT-04": "weak_ec_curve",
    "80052-CERT-05": "weak_key_strength",
    "80052-CERT-06": "sha1_signature",
    "80052-CERT-07": "no_san",
    "80052-CERT-08": "no_serverauth_eku",
    "80052-CERT-09": "no_ocsp",
    "80052-CERT-10": "no_ca_issuers",
    "80052-CERT-11": "self_signed",
    "80052-CERT-12": "leaf_ca_true",
    "80052-CIPH-01": "des_tdea",
    "80052-CIPH-02": "cipher_not_allowed",
    "80052-CIPH-03": "no_forward_secrecy",
    "80052-CIPH-04": "weak_ephemeral",
    "80052-CIPH-05": "server_preference_order",
    "80052-CIPH-06": "rsa_key_transport",
    "80052-CIPH-07": "cbc_no_etm",
    "80052-CIPH-08": "tls13_cipher",
    "80052-EXT-01": "renegotiation_info_missing",
    "80052-EXT-02": "ems_missing",
    "80052-EXT-03": "ocsp_stapling_missing",
    "80052-EXT-04": "supported_groups_missing",
    "80052-EXT-05": "key_share_missing",
    "80052-EXT-06": "raw_public_keys",
    "80052-EXT-07": "client_certificate_url",
    "80052-EXT-08": "early_data",
    "80052-EXT-09": "fallback_scsv",
    "80052-COMP-01": "compression_non_null",
    # --- SP 800-57 Part 1 Rev.5 ---
    "80057-KEY-01": "weak_rsa_key",
    "80057-KEY-02": "weak_ec_curve",
    "80057-KEY-03": "weak_dsa_dh",
    "80057-KEY-04": "des_tdea",
    "80057-KEY-05": "des_tdea",
    "80057-KEY-06": "weak_key_strength",
    "80057-KEY-07": "exact_112_bits",
    "80057-HASH-01": "sha1_signature",
    "80057-HASH-02": "sha1_signature",
    "80057-HASH-03": "mixed_hash_strength",
    "80057-SCHED-01": "schedule_112",
    "80057-SCHED-02": "weak_key_strength",
    "80057-SCHED-03": "schedule_112",
    "80057-SCHED-04": "acceptable_strength",
    "80057-COMBO-02": "combo_key_agreement_weaker",
    "80057-PQC-01": "pqc_note",
    "80057-CRYPTO-01": "cert_long_validity",
    "80057-REDUCE-01": "reduced_signature_strength",
    "80057-REDUCE-02": "reduced_signature_note",
    # --- SP 800-131A Rev.2 ---
    "800131a-BLK-01": "des_tdea",
    "800131a-BLK-02": "des_tdea",
    "800131a-BLK-03": "des_tdea",
    "800131a-BLK-04": "skipjack",
    "800131a-SIG-01": "weak_rsa_key",
    "800131a-SIG-02": "rsa_legacy_verify",
    "800131a-SIG-03": "weak_ec_curve",
    "800131a-SIG-04": "weak_ec_curve",
    "800131a-SIG-05": "weak_dsa_dh",
    "800131a-DH-01": "weak_dsa_dh",
    "800131a-DH-02": "weak_dsa_dh",
    "800131a-DH-03": "weak_dsa_dh",
    "800131a-DH-04": "weak_ephemeral",
    "800131a-DH-05": "weak_ephemeral",
    "800131a-DH-06": "x25519_coverage",
    "800131a-RSA-01": "weak_rsa_key",
    "800131a-RSA-02": "rsa_key_transport",
    "800131a-RSA-03": "rsa_key_transport",
    "800131a-RSA-04": "rsa_key_transport",
    "800131a-HASH-01": "sha1_signature",
    "800131a-HASH-02": "sha1_legacy_verify",
    "800131a-MAC-01": "weak_mac",
    "800131a-MAC-02": "weak_mac",
    "800131a-RBG-01": "rbg_not_evaluable",
}


def issue_of(standard: str, rule_id: str) -> str:
    """Clave canonica de defecto para un par (estandar, regla)."""
    return ISSUE_OF.get(f"{standard}-{rule_id}", f"{standard}-{rule_id}")
