"""Useful hybrid review: deterministic evidence and separately scoped local ML."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from .java_review import inspect_java
from .train_cipher_v3 import parameter_features
from .rsa_classifier import load_rsa_model, predict_size
from .context_model import screen_current as screen
from .presentation import context_notes

MODEL_PATH = Path(__file__).with_name("assets") / "cipher_model_v3.json"


@lru_cache(maxsize=1)
def model() -> dict:
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def predict_cipher(transformation: str, artifact: dict) -> float | None:
    """Portable decision tree. Abstain outside transformations present in train."""
    if transformation.upper() not in artifact["knownTransformations"]:
        return None
    values = parameter_features(transformation)
    vector = {f"{key}={value}": 1.0 for key, value in values.items() if isinstance(value, str)}
    vector.update({key: float(value) for key, value in values.items() if not isinstance(value, str)})
    node = 0
    while artifact["childrenLeft"][node] != -1:
        feature = artifact["features"][artifact["feature"][node]]
        node = artifact["childrenLeft"][node] if vector.get(feature, 0.0) <= artifact["threshold"][node] else artifact["childrenRight"][node]
    weights = artifact["values"][node][0]
    return weights[1] / sum(weights)


def analyze(source: str, filename: str = "source.java") -> dict:
    if not filename.lower().endswith(".java"):
        raise ValueError("Solo se admiten archivos .java")
    try:
        byte_count = len(source.encode("utf-8"))
    except UnicodeError as exc:
        raise ValueError("El archivo debe contener texto UTF-8 válido") from exc
    if not source.strip() or "\x00" in source or byte_count > 100_000:
        raise ValueError("El archivo debe contener texto y no superar 100 KB UTF-8")
    artifact = model()
    checked = inspect_java(source)
    rsa_artifact = load_rsa_model()
    predictions, rsa_predictions, out_of_scope = [], [], []
    for fact in checked["facts"]:
        if fact["kind"] == "rsa_bits":
            score = predict_size(fact["value"], rsa_artifact)
            if score is None:
                out_of_scope.append({"line": fact["line"], "transformation": f"RSA {fact['value']} bits (fuera del dominio del modelo)"})
            else:
                rsa_predictions.append({"line": fact["line"], "bits": fact["value"], "score": score, "classification": "below_size_minimum" if score >= 0.5 else "meets_size_minimum", "source": "supervised_rsa_policy_classifier"})
            continue
        if fact["kind"] != "cipher":
            continue
        score = predict_cipher(fact["value"], artifact)
        if score is None:
            out_of_scope.append({"line": fact["line"], "transformation": fact["value"]})
        else:
            predictions.append({"line": fact["line"], "transformation": fact["value"], "score": score, "classification": "possible_misuse" if score >= 0.5 else "no_indication", "source": "supervised_classifier"})
    context = screen(source)
    context_predictions = [context] if context["status"] == "applied" else []
    ml_score = max((s["score"] for s in predictions + rsa_predictions + context_predictions), default=None)
    parameter_score = max((s["score"] for s in predictions + rsa_predictions), default=None)
    if checked["findings"] or (parameter_score is not None and parameter_score >= 0.5):
        status = "possible_misuse"
    elif context_predictions and context["classification"] == "possible_misuse":
        status = "needs_review"
    elif checked["unresolved"]:
        status = "needs_review"
    elif checked["facts"]:
        status = "no_indication"
    elif context_predictions:
        status = "needs_review"
    else:
        status = "not_evaluable"
    if checked["findings"]:
        recommendation = "Revisar las evidencias y aplicar las recomendaciones específicas de cada control."
    elif checked["unresolved"]:
        recommendation = "Completar la revisión de los parámetros no resueltos antes de decidir cambios."
    elif ml_score is not None and ml_score >= 0.5:
        recommendation = "El clasificador señaló un patrón a revisar; confirmar su contexto antes de decidir cambios. La predicción no determina por sí sola qué parámetro corregir."
    elif status == "not_evaluable":
        recommendation = "No se identificaron llamadas evaluables para estos controles. Esto no demuestra ausencia de problemas criptográficos."
    elif status == "needs_review":
        recommendation = "El contextual no señaló un patrón, pero no se pudieron aplicar los controles de parámetros. Revisar manualmente el fragmento."
    else:
        recommendation = "No se requieren correcciones por los controles aplicados. Esto no evalúa todos los aspectos de seguridad del archivo."
    return {
        "filename": Path(filename.replace("\\", "/")).name,
        "modelVersion": context.get("modelVersion", "v5-review") + "-cipher-" + artifact["version"] + "-rsa-" + rsa_artifact["version"],
        "datasetRevision": "CryptoAPI-e6b6b50fef69+OWASP-10dfcc54ad02+RSA-policy-v1" + ("+CryptoLLM-30aaab85" if "modelVersion" in context else ""),
        "status": status,
        "misuseScore": ml_score,
        "scoreMeaning": "Máximo de puntajes de clasificadores independientes de contexto, transformaciones y política RSA; no es una probabilidad conjunta ni certifica el archivo",
        "findings": checked["findings"], "observations": checked["facts"], "unresolved": checked["unresolved"],
        "contextNotes": context_notes(source) if checked["parsed"] else [],
        "ml": {"status": "applied" if predictions or rsa_predictions or context_predictions else "out_of_scope" if out_of_scope else "not_applicable", "context": context, "predictions": predictions, "rsaPredictions": rsa_predictions, "rsaDomain": rsa_artifact["domain"], "rsaPolicyMinimum": rsa_artifact["policyMinimum"], "rsaProvenance": rsa_artifact["provenance"], "outOfScope": out_of_scope, "supportedTransformations": artifact["knownTransformations"], "scope": artifact["scope"]},
        "limitations": [
            "Las comprobaciones de parámetros son deterministas y no se atribuyen al ML.",
            "El contextual aprende etiquetas binarias de CryptoLLM y usa tamaños y procedencia cuando se resuelven, con respaldo léxico en otros casos. Sus submodelos estructurados tienen pocos ejemplos; no localiza defectos ni certifica seguridad.",
            "Los controles de clave/IV siguen procedencia local hasta Cipher.init y redactan el material. Un IV constante no demuestra reutilización entre ejecuciones.",
            "Se resuelven literales, alias locales, constantes static final y setters estáticos simples llamados desde main. Otras llamadas, ramas y bucles requieren revisión.",
            "El clasificador anterior de transformaciones solo reconoce las listadas; es independiente del nuevo clasificador contextual. Su test interno no es validación externa de seguridad.",
            "El modelo RSA aprende una política simple con ejemplos propios; no supera a la regla de tamaño ni demuestra detección general de vulnerabilidades.",
            "No se ejecuta ni compila Java. No hallar problemas en estos controles no demuestra seguridad integral.",
        ],
        "recommendation": recommendation,
    }
