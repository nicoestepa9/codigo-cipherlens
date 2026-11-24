"""Backfill de Issues para scans existentes (Parte 2).

Reproduce el historial de scans COMPLETADOS en orden cronologico por service
para reconstruir los Issues con su SLA, auto-resolve y auto-verify. Los scans
fallidos / connection_error se ignoran (no reconcilian).

Ejecutar con:
    python -m tls_analyzer.scripts.backfill_issues

Opciones:
    --apply    efectiva los cambios (sin esta flag corre en dry-run)
"""

from __future__ import annotations

import argparse
import sys

from ..api.db import SessionLocal, engine
from ..api.models import Base, Finding, Scan
from ..api.services import issue_service
from ..api.tenancy import set_system_session


def _findings_dtos_for_scan(db, scan_id: str) -> list[dict]:
    rows = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return [
        {
            "ruleId": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "sourceDocument": f.source_document or "",
            "evaluable": f.evaluable,
            "status": f.status,
        }
        for f in rows
    ]


def backfill_issues(apply: bool = False) -> dict:
    Base.metadata.create_all(engine)
    db = SessionLocal()
    set_system_session(db)
    summary = {"scans": 0, "issues_created": 0, "skipped": 0}

    try:
        before = db.query(issue_service.Issue).count()
        scans = (
            db.query(Scan)
            .filter(Scan.status == "completed", Scan.service_id.isnot(None))
            .order_by(Scan.service_id, Scan.started_at)
            .all()
        )
        if not scans:
            print("Nada que hacer: no hay scans completados enlazados a un service.")
            return summary

        print(f"Scans completados a reproducir: {len(scans)}")
        for scan in scans:
            if not apply:
                # dry-run: no tocar la DB, solo contar
                summary["scans"] += 1
                continue
            dtos = _findings_dtos_for_scan(db, scan.id)
            issue_service.reconcile_scan(db, scan, dtos)
            db.commit()
            summary["scans"] += 1

        if apply:
            after = db.query(issue_service.Issue).count()
            summary["issues_created"] = after - before
            print(f"Issues creados: {summary['issues_created']} (total ahora: {after})")
        else:
            print(
                f"[dry-run] Scans que se reproducirian: {summary['scans']}. "
                "Ejecuta con --apply para efectivar."
            )
        return summary
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill de Issues (Parte 2)")
    parser.add_argument("--apply", action="store_true", help="efectiva los cambios")
    args = parser.parse_args()
    backfill_issues(apply=args.apply)
    return 0


if __name__ == "__main__":
    sys.exit(main())
