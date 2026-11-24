"""Reporte de cumplimiento combinado de los tres estandares NIST.

Corre los tres modulos (SP 800-52, SP 800-57 Part 1 y SP 800-131A) sobre el
mismo JSON de escaneo y produce un reporte unificado. Los IDs de las reglas se
prefijan con el codigo del estandar (ej. ``80057-KEY-01``) para trazabilidad
maxima: una misma colision de id (ej. ``HASH-01`` existe en 80057 y 800131a)
queda desambiguada por el prefijo.

Este reporte es la superficie de maxima trazabilidad. El scan general (modulo
``scanner``) hace un paso adicional de deduplicacion por defecto subyacente.
"""

from __future__ import annotations

from typing import Any

from . import nist, nist80057, nist800131a
from .crypto_strength import resolve_evaluation_date
from .issues import (
    STANDARD_80052,
    STANDARD_80057,
    STANDARD_800131A,
    STANDARD_ORDER,
    STANDARD_NAMES,
)

MODULES = {
    STANDARD_80052: nist,
    STANDARD_80057: nist80057,
    STANDARD_800131A: nist800131a,
}

Summary = dict


def _empty_summary() -> dict:
    return {"critical": 0, "high": 0, "medium": 0, "info": 0, "not_evaluable": 0}


def _merge_summaries(acc: dict, s: dict) -> dict:
    for key in acc:
        acc[key] += s.get(key, 0)
    return acc


def evaluate_all(
    data: dict,
    profile: str = nist.DEFAULT_PROFILE,
    standards: list[str] | None = None,
    evaluation_date: Any = None,
) -> dict:
    """Evalua el JSON contra los estandares seleccionados y combina los reportes.

    ``standards`` es una lista de codigos en ``issues.STANDARD_ORDER``
    (default: los tres). Cada finding del reporte combinado lleva el id
    prefijado con el estandar y el campo ``standard`` para trazabilidad.
    """
    if not isinstance(data, dict):
        raise nist.NISTEvaluationError("El JSON de entrada debe ser un objeto.")
    if "handshake" not in data:
        raise nist.NISTEvaluationError("Falta el campo clave 'handshake' en el JSON de entrada.")

    selected = standards or list(STANDARD_ORDER)

    reports = []
    flat = []
    summary = _empty_summary()
    for code in STANDARD_ORDER:
        if code not in selected:
            continue
        mod = MODULES[code]
        if code == STANDARD_80052:
            report = mod.evaluate(data, profile=profile)
        else:
            report = mod.evaluate(data, profile=profile, evaluation_date=evaluation_date)
        for f in report.get("findings", []):
            f["id"] = f"{code}-{f['id']}"
            f["standard"] = code
            flat.append(f)
        _merge_summaries(summary, report.get("summary", {}))
        reports.append({
            "standard": code,
            "name": STANDARD_NAMES[code],
            "evaluated_against": report.get("evaluated_against"),
            "summary": report.get("summary", {}),
            "findings": report.get("findings", []),
        })

    return {
        "host": data.get("host") or (data.get("handshake") or {}).get("host") or "",
        "port": data.get("port") or (data.get("handshake") or {}).get("port") or 443,
        "profile": profile,
        "evaluation_date": resolve_evaluation_date(data, evaluation_date).isoformat(),
        "standards": [c for c in STANDARD_ORDER if c in selected],
        "summary": summary,
        "reports": reports,
        "findings": flat,
    }
