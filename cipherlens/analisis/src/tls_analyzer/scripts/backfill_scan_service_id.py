"""Backfill de Scan.service_id para scans existentes.

Resuelve el Service por (host, port) y enlaza los scans que quedaron con
service_id NULL (creados antes de que persist_scan enlazara el inventario).
NO crea servicios: los scans que no encuentran match se reportan y quedan
igual.

Ejecutar con:
    python -m tls_analyzer.scripts.backfill_scan_service_id

Opciones:
    --apply    efectiva los cambios (sin esta flag corre en dry-run)
"""

from __future__ import annotations

import argparse
import sys

from ..api.db import SessionLocal, engine
from ..api.models import Base, Scan, Service
from ..api.tenancy import set_system_session


def backfill_scan_service_id(apply: bool = False) -> dict:
    """Enlaza scans.service_id con el Service existente (host, port).

    Devuelve un resumen: {linked, unresolved, skipped} y una lista de
    ``unresolved_samples`` con los scans que no se pudieron resolver.
    """
    Base.metadata.create_all(engine)
    db = SessionLocal()
    set_system_session(db)
    summary = {"linked": 0, "unresolved": 0, "skipped": 0, "unresolved_samples": []}

    try:
        pending = db.query(Scan).filter(Scan.service_id.is_(None)).all()
        if not pending:
            print("Nada que hacer: ningun scan tiene service_id NULL.")
            return summary

        print(f"Scans con service_id NULL: {len(pending)}")

        # Indice unico de services por (host, port)
        services = db.query(Service).all()
        by_target: dict[tuple[str, int], Service] = {
            (s.host, s.port): s for s in services
        }

        for row in pending:
            service = by_target.get((row.host, row.port))
            if service is None:
                summary["unresolved"] += 1
                if len(summary["unresolved_samples"]) < 20:
                    summary["unresolved_samples"].append(
                        {"scanId": row.id, "target": row.target, "origin": row.origin}
                    )
                continue

            summary["linked"] += 1
            if apply:
                row.service_id = service.id

        if apply and summary["linked"]:
            db.commit()
            print(f"Enlazados: {summary['linked']}")
        elif summary["linked"]:
            print(f"Dry-run: se enlazarian {summary['linked']} scans (usa --apply).")

        if summary["unresolved"]:
            print(f"Sin Service (host, port) para resolver: {summary['unresolved']}")
            for s in summary["unresolved_samples"]:
                print(f"  scan={s['scanId']} target={s['target']} origin={s['origin']}")
            print("  (no se crean servicios: quedan para revision manual)")

        return summary
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="efectiva los cambios (por defecto dry-run)",
    )
    args = parser.parse_args(argv)
    backfill_scan_service_id(apply=args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
