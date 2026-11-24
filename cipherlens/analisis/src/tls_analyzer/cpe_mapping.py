"""Mapeo de software_name a CPE vendor:product para búsquedas NVD precisas.

Estrategia:
1. Lookup rápido en CPE_MAP hardcodeado para los ~5 servicios más comunes
2. Si no está en el mapa → consultar NVD CPE Dictionary API
3. Cachear resultados de API para no repetir búsqueda
"""

from __future__ import annotations

import time

import httpx

# software_name (como lo devuelve fingerprint) → CPE name format
CPE_MAP: dict[str, str] = {
    "nginx": "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*",
    "apache httpd": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
    "apache": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
    "openssh": "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*",
    "postfix": "cpe:2.3:a:postfix:postfix:{version}:*:*:*:*:*:*:*",
    "microsoft iis": "cpe:2.3:a:microsoft:iis:{version}:*:*:*:*:*:*:*",
    "iis": "cpe:2.3:a:microsoft:iis:{version}:*:*:*:*:*:*:*",
}

CPE_WILDCARD_VERSION = "*"

# Cache en memoria para resultados de NVD CPE Dictionary API
_cpe_api_cache: dict[str, str | None] = {}

NVD_CPE_DICT_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def _query_cpe_dictionary(software_name: str) -> str | None:
    """Consulta NVD CPE Dictionary para encontrar el CPE de un software.

    Busca el primer CPE no deprecado que matchee el nombre.
    Devuelve el CPE name (ej: 'cpe:2.3:a:nginx:nginx') o None.
    """
    if software_name in _cpe_api_cache:
        return _cpe_api_cache[software_name]

    for attempt in range(3):
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    NVD_CPE_DICT_URL,
                    params={"keywordSearch": software_name, "resultsPerPage": 20},
                )
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", 30))
                    time.sleep(retry_after)
                    continue
                resp.raise_for_status()
                data = resp.json()

            products = data.get("products", [])
            for p in products:
                cpe_obj = p.get("cpe", {})
                if cpe_obj.get("deprecated", False):
                    continue
                cpe_name = cpe_obj.get("cpeName", "")
                if not cpe_name:
                    continue
                # Extraer vendor:product (primeros 5 componentes)
                parts = cpe_name.split(":")
                if len(parts) >= 5:
                    vendor_product = ":".join(parts[:5])
                    _cpe_api_cache[software_name] = vendor_product
                    return vendor_product

            _cpe_api_cache[software_name] = None
            return None
        except Exception:
            if attempt < 2:
                time.sleep(2 ** attempt)
            else:
                _cpe_api_cache[software_name] = None
                return None


def software_name_to_cpe(software_name: str | None, version: str | None = None) -> str | None:
    """Convierte software_name a CPE name format para NVD query.

    Primero intenta el mapa hardcodeado (rápido).
    Si no está, consulta NVD CPE Dictionary API.
    Devuelve None si no se pudo resolver.
    """
    if not software_name:
        return None

    key = software_name.lower().strip()
    ver = version or CPE_WILDCARD_VERSION

    # 1. Lookup rápido en mapa hardcodeado
    template = CPE_MAP.get(key)
    if template:
        return template.format(version=ver)

    # 2. Consultar NVD CPE Dictionary API
    vendor_product = _query_cpe_dictionary(key)
    if vendor_product:
        return f"{vendor_product}:{ver}:*:*:*:*:*:*:*"

    return None
