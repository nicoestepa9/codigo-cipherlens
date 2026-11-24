"""Cliente HTTP para NVD REST API 2.0 con rate limiting y cache local.

Rate limit: 5 requests / 30 segundos (sin API key).
Documentación: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import time
from typing import Any

import httpx

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limiting: max 5 requests por ventana de 30s
_RATE_WINDOW = 30.0
_RATE_MAX = 5
_request_times: list[float] = []
_MAX_RETRIES = 3


def _rate_limit() -> None:
    """Bloquea si se excede el rate limit de NVD."""
    now = time.monotonic()
    # Limpiar timestamps viejos
    while _request_times and _request_times[0] < now - _RATE_WINDOW:
        _request_times.pop(0)
    if len(_request_times) >= _RATE_MAX:
        wait = _RATE_WINDOW - (now - _request_times[0])
        if wait > 0:
            time.sleep(wait)
    _request_times.append(time.monotonic())


def _request_with_retry(params: dict[str, Any], timeout: float = 15.0) -> dict | None:
    """Realiza request a NVD con retry + backoff para 429."""
    for attempt in range(_MAX_RETRIES):
        _rate_limit()
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.get(NVD_BASE_URL, params=params)
                if resp.status_code == 429:
                    # Rate limited by NVD — wait and retry
                    retry_after = int(resp.headers.get("Retry-After", 30))
                    time.sleep(retry_after)
                    continue
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError:
            return None
        except Exception:
            if attempt < _MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
            else:
                return None
    return None


def _parse_nvd_response(data: dict) -> list[dict]:
    """Extrae la lista de vulnerabilidades de la respuesta NVD."""
    vulnerabilities = data.get("vulnerabilities", [])
    results = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        # Extraer CVSS v3.1 o v3.0
        metrics = cve.get("metrics", {})
        cvss_data = None
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                break

        # Extraer descripción en inglés
        descriptions = cve.get("descriptions", [])
        summary = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                break

        results.append({
            "cve_id": cve_id,
            "cvss_v3_score": cvss_data.get("baseScore") if cvss_data else None,
            "cvss_v3_vector": cvss_data.get("vectorString") if cvss_data else None,
            "summary": summary,
            "published_date": cve.get("published", ""),
            "last_modified_date": cve.get("lastModified", ""),
        })

    return results


def query_nvd_by_cpe(cpe_name: str, max_results: int = 20) -> list[dict]:
    """Consulta NVD por CPE usando virtualMatchString.

    Parsea el CPE para extraer vendor:product y versión, luego usa
    virtualMatchString + versionEnd para encontrar CVEs que afecten
    versiones <= a la detectada.
    Ejemplo input: ``cpe:2.3:a:nginx:nginx:1.10.3:*:*:*:*:*:*:*``
    """
    # Parsear CPE: cpe:2.3:part:vendor:product:version:...
    parts = cpe_name.split(":")
    if len(parts) < 6:
        return []

    # Construir virtualMatchString sin versión (hasta product)
    # cpe:2.3:a:vendor:product
    virtual = ":".join(parts[:5])
    version = parts[5]

    params: dict[str, str | int] = {
        "virtualMatchString": virtual,
        "resultsPerPage": max_results,
    }

    # Si hay versión concreta (no wildcard), filtrar por versionEnd
    if version and version != "*":
        params["versionEnd"] = version
        params["versionEndType"] = "including"

    data = _request_with_retry(params)
    return _parse_nvd_response(data) if data else []


def query_nvd_by_keyword(keyword: str, max_results: int = 20) -> list[dict]:
    """Consulta NVD por keyword (menos preciso, usado como fallback)."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    data = _request_with_retry(params)
    return _parse_nvd_response(data) if data else []
