"""Seed de CVEs: pobla la tabla Cve con el detalle real desde NVD.

Ejecutar con:
    python -m tls_analyzer.scripts.seed_cves

Requiere que la base de datos ya esté creada (Base.metadata.create_all).
"""

from __future__ import annotations

import sys
import time

from ..cve_mapping import get_all_unique_cve_ids, RULE_CVE_MAP
from ..nvd_client import query_nvd_by_keyword
from ..api.db import SessionLocal, engine
from ..api.models import Base, Cve
from ..api.tenancy import set_system_session


def seed_cves() -> int:
    """Consulta NVD para cada CVE del mapping estático y guarda el detalle.

    Devuelve la cantidad de CVEs insertados/actualizados.
    """
    Base.metadata.create_all(engine)
    db = SessionLocal()
    set_system_session(db)
    updated = 0

    try:
        cve_ids = get_all_unique_cve_ids()
        print(f"Seedando {len(cve_ids)} CVEs desde NVD...")

        for i, cve_id in enumerate(cve_ids, 1):
            # Buscar nombre popular del mapping
            popular_name = None
            for entries in RULE_CVE_MAP.values():
                for e in entries:
                    if e.cve_id == cve_id:
                        popular_name = e.name
                        break

            # Consultar NVD
            print(f"  [{i}/{len(cve_ids)}] {cve_id} ({popular_name or 'N/A'})...", end=" ")
            results = query_nvd_by_keyword(cve_id, max_results=5)

            # Buscar el resultado exacto
            found = False
            for r in results:
                if r["cve_id"] == cve_id:
                    cve = db.get(Cve, cve_id)
                    if cve is None:
                        cve = Cve(cve_id=cve_id, source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                        db.add(cve)
                    cve.name = popular_name or cve.name
                    cve.cvss_v3_score = r.get("cvss_v3_score") or cve.cvss_v3_score
                    cve.cvss_v3_vector = r.get("cvss_v3_vector") or cve.cvss_v3_vector
                    cve.summary = r.get("summary") or cve.summary
                    cve.published_date = r.get("published_date") or cve.published_date
                    cve.last_modified_date = r.get("last_modified_date") or cve.last_modified_date
                    from datetime import datetime, timezone
                    cve.fetched_at = datetime.now(timezone.utc)
                    found = True
                    updated += 1
                    print(f"OK (CVSS: {cve.cvss_v3_score})")
                    break

            if not found:
                print("SKIP (no encontrado en NVD)")

            # Rate limit: NVD permite 5 req/30s sin key
            if i % 5 == 0:
                print("  (esperando 30s por rate limit de NVD...)")
                time.sleep(31)

        db.commit()
        print(f"\nSeed completado: {updated}/{len(cve_ids)} CVEs actualizados.")
        return updated

    finally:
        db.close()


if __name__ == "__main__":
    seed_cves()
