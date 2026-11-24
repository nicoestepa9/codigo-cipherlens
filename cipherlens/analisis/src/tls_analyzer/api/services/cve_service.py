"""Servicio de CVEs: lookup estático, cache, y query en vivo a NVD."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ...cve_mapping import CveEntry, get_static_cves_for_rule
from ...cpe_mapping import software_name_to_cpe
from ...fingerprint import ServiceFingerprint
from ...nvd_client import query_nvd_by_cpe, query_nvd_by_keyword
from ..models import Cve, CveQueryCache, ScanCveMatch

# Ventana de cache: 7 días
CACHE_TTL = timedelta(days=7)

# Mapa rule_id → keyword corto para NVD (NVD entiende inglés técnico)
_RULE_NVD_KEYWORDS: dict[str, str] = {
    "CERT-01": "TLS certificate expiration",
    "CERT-06": "SHA-1 certificate signature",
    "CERT-09": "OCSP stapling",
    "CERT-10": "certificate AIA CA issuers",
    "PROTO-01": "SSLv3 POODLE",
    "PROTO-02": "TLS 1.0 BEAST",
    "PROTO-03": "TLS 1.0 BEAST",
    "PROTO-05": "TLS 1.3 support",
    "CIPH-01": "3DES Sweet32",
    "CIPH-05": "TLS cipher suite preference",
    "CIPH-06": "RSA padding ROBOT Bleichenbacher",
    "COMP-01": "TLS compression CRIME",
    "EXT-02": "Extended Master Secret TLS",
    "EXT-03": "OCSP stapling",
    "KEY-05": "3DES Sweet32",
    "DH-01": "DH key exchange Logjam",
    "DH-02": "DH key exchange Logjam",
    "RSA-02": "RSA padding ROBOT",
    "HASH-03": "SHA-1 RSA signature strength",
}

# Fallback por categoría: para findings sin keyword específica
_CATEGORY_KEYWORDS: dict[str, str] = {
    "Protocol": "TLS protocol vulnerability",
    "Cipher Suite": "TLS cipher suite vulnerability",
    "Certificate": "TLS certificate vulnerability",
    "Key Exchange": "cryptographic key exchange vulnerability",
    "Compression": "TLS compression vulnerability",
    "Extension": "TLS extension vulnerability",
    "Hash": "cryptographic hash vulnerability",
}


def build_nvd_keywords(findings: list[dict]) -> list[str]:
    """Extrae keywords en inglés de findings que NO tienen CVE estático.

    Solo busca en NVD para reglas nuevas que todavía no están en RULE_CVE_MAP.
    Prioriza keywords específicas del rule_id, fallback a keyword genérica de categoría.
    """
    keywords: list[str] = []
    seen: set[str] = set()
    priority = ("critical", "high", "medium")

    for severity in priority:
        for f in findings:
            if f.get("severity") != severity:
                continue
            rule_id = f.get("ruleId") or f.get("id") or ""
            # Saltar si ya tiene CVE estático (no gastar rate limit en NVD)
            if get_static_cves_for_rule(rule_id):
                continue

            # 1. Intentar keyword específica del rule_id
            kw = _RULE_NVD_KEYWORDS.get(rule_id)
            if kw and kw not in seen:
                keywords.append(kw)
                seen.add(kw)
                continue

            # 2. Fallback: keyword genérica de categoría
            category = f.get("category") or ""
            cat_kw = _CATEGORY_KEYWORDS.get(category)
            if cat_kw and cat_kw not in seen:
                keywords.append(cat_kw)
                seen.add(cat_kw)

        if len(keywords) >= 5:
            break

    return keywords[:5]


def _cve_to_dict(cve: Cve) -> dict:
    return {
        "cveId": cve.cve_id,
        "name": cve.name,
        "cvssV3Score": cve.cvss_v3_score,
        "cvssV3Vector": cve.cvss_v3_vector,
        "summary": cve.summary,
        "publishedDate": cve.published_date,
        "lastModifiedDate": cve.last_modified_date,
        "sourceUrl": cve.source_url,
        "fetchedAt": cve.fetched_at.isoformat() if cve.fetched_at else "",
    }


def get_cve_detail(db: Session, cve_id: str) -> Optional[dict]:
    """Devuelve el detalle de un CVE desde la caché local."""
    cve = db.get(Cve, cve_id)
    if cve is None:
        return None
    return _cve_to_dict(cve)


def get_static_cves_for_findings(findings: list[dict], db=None) -> dict[str, list[dict]]:
    """Para cada finding, resuelve los CVEs estáticos del mapping.

    Devuelve dict[rule_id → list[CveReferenceOut dict]]
    """
    result: dict[str, list[dict]] = {}
    for f in findings:
        rule_id = f.get("ruleId") or f.get("id") or ""
        entries = get_static_cves_for_rule(rule_id)
        if not entries:
            continue
        cves = []
        for entry in entries:
            cvss_score = None
            if db is not None:
                cve_row = db.get(Cve, entry.cve_id)
                cvss_score = cve_row.cvss_v3_score if cve_row else None
            cves.append({
                "cveId": entry.cve_id,
                "name": entry.name,
                "cvssV3Score": cvss_score,
                "matchType": "static_mapping",
                "referenceUrl": f"https://nvd.nist.gov/vuln/detail/{entry.cve_id}",
            })
        result[rule_id] = cves
    return result


def _upsert_cve(db: Session, cve_data: dict, name: str | None = None) -> Cve:
    """Inserta o actualiza un registro Cve."""
    cve_id = cve_data["cve_id"]
    # La sesion usa autoflush=False. Dos respuestas de NVD pueden traer el
    # mismo ID antes de que el primer registro sea visible para db.get().
    cve = next(
        (row for row in db.new if isinstance(row, Cve) and row.cve_id == cve_id),
        None,
    )
    if cve is None:
        cve = db.get(Cve, cve_id)
    if cve is None:
        cve = Cve(cve_id=cve_id, source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        db.add(cve)
    cve.name = name or cve.name
    cve.cvss_v3_score = cve_data.get("cvss_v3_score") or cve.cvss_v3_score
    cve.cvss_v3_vector = cve_data.get("cvss_v3_vector") or cve.cvss_v3_vector
    cve.summary = cve_data.get("summary") or cve.summary
    cve.published_date = cve_data.get("published_date") or cve.published_date
    cve.last_modified_date = cve_data.get("last_modified_date") or cve.last_modified_date
    cve.fetched_at = datetime.now(timezone.utc)
    return cve


def _check_cache(db: Session, query_type: str, query_value: str) -> list[str] | None:
    """Devuelve CVE IDs cacheados si la entrada está fresca, o None si está vencida/ausente."""
    cache_entry = (
        db.query(CveQueryCache)
        .filter(CveQueryCache.query_type == query_type, CveQueryCache.query_value == query_value)
        .first()
    )
    if cache_entry is None:
        return None
    age = datetime.now(timezone.utc) - cache_entry.fetched_at.replace(tzinfo=timezone.utc)
    if age > CACHE_TTL:
        return None  # vencida
    return cache_entry.cve_ids


def _update_cache(db: Session, query_type: str, query_value: str, cve_ids: list[str]) -> None:
    """Inserta o actualiza la caché de queries NVD."""
    cache_entry = (
        db.query(CveQueryCache)
        .filter(CveQueryCache.query_type == query_type, CveQueryCache.query_value == query_value)
        .first()
    )
    if cache_entry is None:
        cache_entry = CveQueryCache(query_type=query_type, query_value=query_value)
        db.add(cache_entry)
    cache_entry.cve_ids = cve_ids
    cache_entry.fetched_at = datetime.now(timezone.utc)


def get_or_query_live_cves(
    db: Session,
    fingerprint: ServiceFingerprint,
    keywords: list[str] | None = None,
) -> tuple[list[dict], list[dict], str | None]:
    """Consulta CVEs en vivo (con cache) basándose en el fingerprint del servidor.

    Retorna:
    - keyword_matches: CVEs encontrados por keyword search (fallback para reglas sin mapping)
    - cpe_matches: CVEs encontrados por CPE (bugs del software detectado)
    - cpe_name: el CPE usado para la búsqueda (o None)
    """
    keyword_matches: list[dict] = []
    cpe_matches: list[dict] = []
    cpe_name_used: str | None = None
    seen_cve_ids: set[str] = set()

    def _append_match(target: list[dict], cve_id: str, cvss_score, match_type: str, stale: bool = False, unverified: bool = False, keyword: str | None = None) -> None:
        if cve_id not in seen_cve_ids:
            seen_cve_ids.add(cve_id)
            target.append({
                "cveId": cve_id,
                "cvssV3Score": cvss_score,
                "matchType": match_type,
                "stale": stale,
                "unverified": unverified,
                "keyword": keyword,
            })

    # --- Paso 1: CPE search si hay software detectado ---
    use_cpe = (
        fingerprint.detected
        and fingerprint.confidence == "high"
        and fingerprint.software_name
    )
    if use_cpe:
        cpe_name = software_name_to_cpe(fingerprint.software_name, fingerprint.software_version)
        if cpe_name:
            cpe_name_used = cpe_name
            cached_ids = _check_cache(db, "cpe", cpe_name)
            if cached_ids is not None:
                for cve_id in cached_ids:
                    cve_row = db.get(Cve, cve_id)
                    _append_match(cpe_matches, cve_id, cve_row.cvss_v3_score if cve_row else None, "cpe")
            else:
                nvd_results = query_nvd_by_cpe(cpe_name)
                cve_ids = []
                for r in nvd_results:
                    _upsert_cve(db, r)
                    cve_ids.append(r["cve_id"])
                    _append_match(cpe_matches, r["cve_id"], r.get("cvss_v3_score"), "cpe")
                _update_cache(db, "cpe", cpe_name, cve_ids)
                db.flush()

    # --- Paso 2: Keyword search (solo para findings sin CVE estático) ---
    if keywords:
        for kw in keywords[:5]:
            kw = kw.strip()
            if not kw:
                continue
            cached_ids = _check_cache(db, "keyword", kw)
            if cached_ids is not None:
                for cve_id in cached_ids:
                    cve_row = db.get(Cve, cve_id)
                    _append_match(keyword_matches, cve_id, cve_row.cvss_v3_score if cve_row else None, "keyword", unverified=True, keyword=kw)
                continue

            nvd_results = query_nvd_by_keyword(kw)
            cve_ids = []
            for r in nvd_results:
                _upsert_cve(db, r)
                cve_ids.append(r["cve_id"])
                _append_match(keyword_matches, r["cve_id"], r.get("cvss_v3_score"), "keyword", unverified=True, keyword=kw)
            _update_cache(db, "keyword", kw, cve_ids)
        db.flush()

    return keyword_matches, cpe_matches, cpe_name_used


def persist_scan_cve_matches(db: Session, scan_id: str, static_cves: dict, live_matches: list[dict]) -> None:
    """Guarda las asociaciones scan↔CVE en la tabla ScanCveMatch."""
    seen: set[str] = set()

    # CVEs estáticos
    for rule_id, cve_refs in static_cves.items():
        for ref in cve_refs:
            cve_id = ref["cveId"]
            if cve_id in seen:
                continue
            seen.add(cve_id)
            # Asegurar que el Cve exista en la tabla
            if db.get(Cve, cve_id) is None:
                db.add(Cve(
                    cve_id=cve_id,
                    name=ref.get("name"),
                    source_url=ref.get("referenceUrl", ""),
                ))
            db.add(ScanCveMatch(
                scan_id=scan_id,
                cve_id=cve_id,
                match_type="static",
            ))

    # CVEs live
    for match in live_matches:
        cve_id = match["cveId"]
        if cve_id in seen:
            continue
        seen.add(cve_id)
        db.add(ScanCveMatch(
            scan_id=scan_id,
            cve_id=cve_id,
            match_type=match.get("matchType", "keyword"),
            stale=match.get("stale", False),
            keyword=match.get("keyword"),
        ))

    db.flush()


def get_scan_cve_matches(db: Session, scan_id: str) -> list[dict]:
    """Devuelve los CVEs asociados a un scan (estáticos + live)."""
    matches = db.query(ScanCveMatch).filter(ScanCveMatch.scan_id == scan_id).all()
    result = []
    for m in matches:
        cve = db.get(Cve, m.cve_id)
        result.append({
            "cveId": m.cve_id,
            "name": cve.name if cve else None,
            "cvssV3Score": cve.cvss_v3_score if cve else None,
            "matchType": m.match_type,
            "stale": m.stale,
            "keyword": m.keyword,
            "referenceUrl": f"https://nvd.nist.gov/vuln/detail/{m.cve_id}",
        })
    return result


def refresh_cve_cache(db: Session) -> int:
    """Fuerza actualización de todos los CVEs en la caché.

    Devuelve la cantidad de CVEs actualizados.
    """
    from ...cve_mapping import get_all_unique_cve_ids

    cve_ids = get_all_unique_cve_ids()
    updated = 0
    for cve_id in cve_ids:
        nvd_results = query_nvd_by_keyword(cve_id)
        for r in nvd_results:
            if r["cve_id"] == cve_id:
                _upsert_cve(db, r, name=None)
                updated += 1
                break
    db.commit()
    return updated
