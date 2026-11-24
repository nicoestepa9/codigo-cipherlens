"""Portable inference from local JSON weights; never loads pickle or executes Java."""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

from .experiment import normalize

MODEL_PATH = Path(__file__).with_name("assets") / "model.json"
LIMITATIONS = [
    "Modelo experimental entrenado con CryptoAPI-Bench (Java/JCA).",
    "La evaluación externa OWASP no distinguió los casos positivos de los negativos; este prototipo no es apto para decidir remediaciones.",
    "Una predicción no confirma una vulnerabilidad; revisar el contexto.",
    "No resuelve flujo de datos entre métodos ni determina qué ramas se ejecutan.",
    "No encontrar indicios no demuestra que el archivo sea seguro.",
    "No reemplaza los controles NIST del scanner TLS. El código no se ejecuta ni se conserva en el servidor.",
]


@lru_cache(maxsize=1)
def load_model() -> dict:
    """Load only the application-bundled JSON artifact, not a user path."""
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def probability(text: str, model: dict) -> float:
    """Match sklearn TF-IDF/L2 and binary logistic regression numerically."""
    words = re.findall(r"(?u)\b\w+\b", text)
    counts = Counter(words + [a + " " + b for a, b in zip(words, words[1:])])
    values = {model["vocabulary"][token]: count * model["idf"][model["vocabulary"][token]] for token, count in counts.items() if token in model["vocabulary"]}
    norm = math.sqrt(sum(value * value for value in values.values()))
    decision = model["intercept"] + (sum(value * model["coefficients"][index] for index, value in values.items()) / norm if norm else 0)
    return 1 / (1 + math.exp(-max(-700, min(700, decision))))


def supports_normalized_source(clean: str) -> bool:
    """Shared eligibility check for the API and external evaluation."""
    return bool(re.search(r"\b(?:Cipher|KeyGenerator|KeyPairGenerator|MessageDigest|Mac|SecureRandom|Random|PBEKeySpec|PBEParameterSpec|KeyStore|SSLContext|X509TrustManager|HostnameVerifier|HttpsURLConnection)\b", clean))


def analyze_java_legacy(source: str, filename: str = "source.java") -> dict:
    """Classify bounded source with explicit abstention on unsupported inputs."""
    if not filename.lower().endswith(".java"):
        raise ValueError("Solo se admiten archivos .java")
    if not source.strip() or len(source.encode("utf-8")) > 100_000 or "\x00" in source:
        raise ValueError("El archivo debe contener texto y no superar 100 KB UTF-8")
    model = load_model()
    clean = normalize(source)
    relevant = supports_normalized_source(clean)
    score = probability(clean, model) if relevant else None
    return {"filename": Path(filename.replace("\\", "/")).name, "modelVersion": model["modelVersion"], "datasetRevision": model["datasetRevision"], "status": ("possible_misuse" if score >= model["threshold"] else "no_indication") if score is not None else "not_evaluable", "misuseScore": round(score, 4) if score is not None else None, "scoreMeaning": "Salida del clasificador, no probabilidad calibrada de vulnerabilidad", "limitations": LIMITATIONS, "recommendation": "Revisar las llamadas criptográficas y sus parámetros, confirmar el contexto antes de corregir. La predicción no identifica por sí sola la línea ni el tipo de defecto."}


def analyze_java(source: str, filename: str = "source.java") -> dict:
    """Current scoped hybrid review; V1 remains available for experiments only."""
    from .review import analyze
    return analyze(source, filename)
