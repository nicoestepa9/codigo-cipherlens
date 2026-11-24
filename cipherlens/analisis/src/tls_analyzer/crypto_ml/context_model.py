"""Local contextual screening. JSON only; Java is never executed.

The training corpus contains snippets with binary labels, not line-level labels.
This classifier must never supply a vulnerability location or remediation.
"""
from __future__ import annotations

import json
import hashlib
import math
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

from .experiment import TOKEN

MODEL_PATH = Path(__file__).resolve().parents[3] / "artifacts/cryptollm-v6/model.json"
KEYWORDS = frozenset("abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null String Object Exception".split())
APIS = frozenset("Cipher KeyGenerator KeyPairGenerator SecretKeySpec SecretKeyFactory IvParameterSpec GCMParameterSpec SecureRandom Random PBEKeySpec PBEParameterSpec DESKeySpec DESedeKeySpec KeyStore KeyPair MessageDigest Mac SecretKey getInstance init initialize getBytes nextBytes generateSeed setSeed generateKey generateKeyPair generateSecret doFinal update ENCRYPT_MODE DECRYPT_MODE WRAP_MODE UNWRAP_MODE getEncoded copyOf fill arraycopy decode encodeToString getDecoder getEncoder setKeySize setBlockModes setEncryptionPaddings setRandomizedEncryptionRequired".split())
TRANSFORM = re.compile(r"(?:AES|DES|DESEDE|RSA|BLOWFISH|RC2|RC4|ARCFOUR|CHACHA20|PBEWITH)[A-Z0-9_/+.-]*", re.I)


def canonical(source: str, *, skeleton: bool = False) -> str:
    """Strip comments/provenance and names; retain API context, not app identity.

    Non-crypto strings become STRING, so no key material is stored in weights.
    Skeletons also mask transformation and numeric literals for clone grouping.
    """
    source = re.sub(r"(?m)^\s*(?:package|import)\s+[^;]+;", "", source)
    result = []
    for match in TOKEN.finditer(source):
        token = match.group()
        if token.startswith(("//", "/*")):
            continue
        if token.startswith(('"', "'")):
            value = token[1:-1].upper()
            token = 'STRING' if skeleton or not TRANSFORM.fullmatch(value) else 'CRYPTO_' + value
        elif token[0].isdigit():
            token = 'NUMBER' if skeleton else token
        elif re.fullmatch(r"[A-Za-z_$][\w$]*", token) and token not in KEYWORDS and token not in APIS:
            token = 'ID'
        result.append(token)
    return ' '.join(result)


def tokens(text: str) -> list[str]:
    # Same tokenization used by sklearn at training and portable inference.
    return re.findall(r"(?u)\b\w+\b", text)


@lru_cache(maxsize=1)
def load_context_model() -> dict | None:
    if not MODEL_PATH.is_file():
        return None
    raw = MODEL_PATH.read_bytes()
    artifact = json.loads(raw)
    if artifact.get('schemaVersion') != 6 or artifact.get('kind') != 'context_tfidf_logistic':
        raise ValueError('Unsupported contextual model schema')
    external_path = MODEL_PATH.with_name('external-cryptoapi.json')
    if external_path.is_file():
        external = json.loads(external_path.read_text(encoding='utf-8'))
        if external.get('modelSha256') == hashlib.sha256(raw).hexdigest():
            artifact['externalEvaluation'] = {k:external[k] for k in ('benchmark','retained','covered','coverage','metrics')}
    return artifact


def score_text(text: str, model: dict) -> tuple[float, float]:
    words = tokens(text)
    terms = [' '.join(words[i:i+n]) for n in range(1, 4) for i in range(len(words)-n+1)]
    counts = Counter(terms)
    vocabulary = model['vocabulary']
    values = {vocabulary[t]: (1 + math.log(n)) * model['idf'][vocabulary[t]] for t, n in counts.items() if t in vocabulary}
    norm = math.sqrt(sum(v*v for v in values.values()))
    logit = model['intercept'] + (sum(v * model['coefficients'][i] for i, v in values.items()) / norm if norm else 0)
    score = 1 / (1 + math.exp(-max(-700, min(700, logit))))
    coverage = sum(n for t, n in counts.items() if t in vocabulary) / max(1, len(terms))
    return score, coverage


def in_scope(text: str, model: dict, coverage: float) -> bool:
    return bool(re.search(r'\b(?:Cipher|KeyGenerator|KeyPairGenerator|SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec|DESKeySpec)\b', text)) and len(tokens(text)) <= model['maxTokens'] and coverage >= model['minVocabularyCoverage']


def screen(source: str) -> dict:
    artifact = load_context_model()
    if artifact is None:
        return {'status': 'unavailable', 'reason': 'No se entrenó el modelo contextual local. Ejecutar el experimento CryptoLLM V6.'}
    clean = canonical(source)
    relevant = bool(re.search(r'\b(?:Cipher|KeyGenerator|KeyPairGenerator|SecretKeySpec|IvParameterSpec|GCMParameterSpec|PBEKeySpec|DESKeySpec)\b', clean))
    base = {'modelVersion': artifact['version'], 'dataset': 'CryptoLLM original', 'trainingSamples': artifact['counts']['train'], 'validationSamples': artifact['counts']['validation'], 'testSamples': artifact['counts']['test'], 'threshold': artifact['threshold'], 'scope': 'Clasificación binaria de patrones en fragmentos Java/JCA; sin localización de defectos', 'evaluation': artifact['evaluation']}
    if 'externalEvaluation' in artifact:
        base['externalEvaluation'] = artifact['externalEvaluation']
    if not relevant:
        return {**base, 'status': 'abstained', 'reason': 'No se reconocen las APIs de cifrado representadas por este experimento.'}
    if len(tokens(clean)) > artifact['maxTokens']:
        return {**base, 'status': 'abstained', 'reason': 'El código excede el tamaño de contexto evaluado; revisar un fragmento más pequeño.'}
    score, coverage = score_text(clean, artifact)
    if coverage < artifact['minVocabularyCoverage']:
        return {**base, 'status': 'abstained', 'reason': 'El fragmento tiene poca representación en el vocabulario entrenado.', 'vocabularyCoverage': round(coverage, 4)}
    return {**base, 'status': 'applied', 'score': round(score, 6), 'classification': 'possible_misuse' if score >= artifact['threshold'] else 'no_indication', 'vocabularyCoverage': round(coverage, 4), 'reason': 'Predicción estadística del fragmento completo; no confirma una vulnerabilidad ni identifica su línea. La similitud de vocabulario no garantiza que esté dentro de distribución.'}


def screen_current(source: str) -> dict:
    """Prefer the validated structured experiment; preserve V6 as a baseline."""
    from .enhanced_context import screen as enhanced_screen
    result = enhanced_screen(source)
    return result if result is not None else screen(source)
