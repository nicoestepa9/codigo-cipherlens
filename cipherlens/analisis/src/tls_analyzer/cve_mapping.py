"""Tabla estática de mapeo: rule_id NIST → CVEs asociados.

Cada regla de los 3 módulos NIST puede tener CVEs "históricos" conocidos.
Reglas que representan debilidades estructurales (no vulnerabilidades de
implementación específica) tienen lista vacía, como indica la spec.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CveEntry:
    cve_id: str
    name: str | None  # nombre popular (ej. "POODLE")


RULE_CVE_MAP: dict[str, list[CveEntry]] = {
    # --- NIST SP 800-52 Rev.2 (nist.py) ---
    "PROTO-01": [CveEntry("CVE-2014-3566", "POODLE")],
    "PROTO-02": [CveEntry("CVE-2011-3389", "BEAST")],
    "PROTO-03": [CveEntry("CVE-2011-3389", "BEAST")],
    "CIPH-01": [CveEntry("CVE-2016-2183", "Sweet32")],
    "CIPH-06": [
        CveEntry("CVE-2017-13099", "ROBOT"),
        CveEntry("CVE-1999-0428", "Bleichenbacher"),
    ],
    "COMP-01": [CveEntry("CVE-2012-4929", "CRIME")],

    # --- NIST SP 800-57 Part 1 Rev.5 (nist80057.py) ---
    "KEY-05": [CveEntry("CVE-2016-2183", "Sweet32")],

    # --- NIST SP 800-131A Rev.2 (nist800131a.py) ---
    "DH-01": [CveEntry("CVE-2015-4000", "Logjam")],
    "DH-02": [CveEntry("CVE-2015-4000", "Logjam")],
    "RSA-02": [CveEntry("CVE-2017-13099", "ROBOT")],

    # --- Sin CVE (debilidad estructural, no vuln de implementación) ---
    # HASH-01: SHA-1 firma → sin CVE puntual
    # CERT-06: SHA-1/MD5 firma → sin CVE puntual
}


def get_static_cves_for_rule(rule_id: str) -> list[CveEntry]:
    """Devuelve los CVEs estáticos asociados a una regla, o lista vacía."""
    return RULE_CVE_MAP.get(rule_id, [])


def get_all_unique_cve_ids() -> list[str]:
    """Devuelve lista deduplicada de todos los CVE IDs del mapeo estático."""
    seen: set[str] = set()
    result: list[str] = []
    for entries in RULE_CVE_MAP.values():
        for e in entries:
            if e.cve_id not in seen:
                seen.add(e.cve_id)
                result.append(e.cve_id)
    return result
