"""Reproducible local research experiment on original CryptoLLM snippets.

python -m tls_analyzer.crypto_ml.cryptollm --download
python -m tls_analyzer.crypto_ml.cryptollm
python -m tls_analyzer.crypto_ml.cryptollm --evaluate-only

No upstream split is trusted blindly. Canonical duplicates with conflicting
labels are excluded. Structural clones are grouped across all upstream splits.
Only validation selects regularization. Test is evaluated after model freeze.
No corpus/weights are bundled or redistributed: upstream license is unspecified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

from .context_model import canonical, score_text, tokens, in_scope
from .experiment import digest

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'data/cryptollm-source'
OUTPUT = ROOT / 'artifacts/cryptollm-v6'
REVISION = '30aaab85c6d38322d0722d6ba6197b56469f659b'
FILES = {
    'train_dataset.jsonl': '9048c238d4d73b2b8713aac6bdce2e5c1b922dd93077686548a9cd602e5bd089',
    'valid_dataset.jsonl': '8447f2cdd9996c5815a116e63afd83af765b569330eb5fc6c640a055e9093cd7',
    'test_dataset.jsonl': 'dd91e6a344446d7921feb07234b0235ea69acc608624f328c9f4ff6977b0104e',
}


def download():
    SOURCE.mkdir(parents=True, exist_ok=True)
    for name, expected in FILES.items():
        path = SOURCE / name
        raw = path.read_bytes() if path.exists() else urllib.request.urlopen(f'https://media.githubusercontent.com/media/heewonB/CryptoLLM/{REVISION}/train/dataset/{name}', timeout=60).read()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f'Upstream checksum mismatch: {name}')
        path.write_bytes(raw)


def prepare():
    rows = []
    for filename, expected in FILES.items():
        raw = (SOURCE / filename).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError(f'Checksum mismatch: {filename}')
        for line, value in enumerate(raw.decode('utf-8').splitlines(), 1):
            item = json.loads(value)
            if not isinstance(item.get('code'), str) or type(item.get('label')) is not int or item['label'] not in (0, 1):
                raise ValueError(f'Invalid record: {filename}:{line}')
            text = canonical(item['code'])
            rows.append({'id': f'{filename}:{line}', 'label': item['label'], 'text': text, 'hash': digest(text), 'group': digest(canonical(item['code'], skeleton=True)), 'upstreamSplit': filename})
    by_hash = defaultdict(list)
    for row in rows:
        by_hash[row['hash']].append(row)
    conflict = {h for h, values in by_hash.items() if len({r['label'] for r in values}) > 1}
    unique = [values[0] for h, values in sorted(by_hash.items()) if h not in conflict]
    # Whole-group assignment is mandatory even for legitimate opposite labels.
    group_hashes = defaultdict(set)
    for row in rows:
        group_hashes[row['group']].add(row['upstreamSplit'])
    audit = {'rawRows': len(rows), 'rawLabels': dict(Counter(r['label'] for r in rows)), 'canonicalUniqueBeforeConflicts': len(by_hash), 'conflictingCanonicalGroups': len(conflict), 'conflictingRowsExcluded': sum(len(by_hash[h]) for h in conflict), 'duplicateRowsRemoved': sum(len(v)-1 for h, v in by_hash.items() if h not in conflict), 'retained': len(unique), 'structuralGroups': len({r['group'] for r in unique}), 'upstreamStructuralGroupsCrossingSplits': sum(len(s)>1 for s in group_hashes.values()), 'grouping': 'Identifiers, non-crypto strings, comments and imports removed; skeleton also masks numbers and crypto strings. Same skeleton never crosses splits. Not a proof of semantic independence.', 'projectSeparation': 'Not possible: corpus lacks application IDs. No claim of project-independent external validation.', 'labelMeaning': '1 misuse / 0 benign, upstream binary snippet labels; no per-rule or line annotations'}
    return unique, audit


def partition(rows):
    from sklearn.model_selection import StratifiedGroupKFold
    labels, groups = [r['label'] for r in rows], [r['group'] for r in rows]
    dev, test = next(StratifiedGroupKFold(5, shuffle=True, random_state=42).split(rows, labels, groups))
    development = [rows[i] for i in dev]
    tr, va = next(StratifiedGroupKFold(4, shuffle=True, random_state=42).split(development, [r['label'] for r in development], [r['group'] for r in development]))
    splits = {'train': [development[i] for i in tr], 'validation': [development[i] for i in va], 'test': [rows[i] for i in test]}
    for name, part in splits.items():
        if {r['label'] for r in part} != {0, 1}:
            raise ValueError(f'Insufficient classes in fixed split: {name}')
        for other, other_part in splits.items():
            if name != other and {r['group'] for r in part} & {r['group'] for r in other_part}:
                raise AssertionError('Group leakage')
    return splits


def metrics(actual, predicted):
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, balanced_accuracy_score
    p, r, f, _ = precision_recall_fscore_support(actual, predicted, average='binary', zero_division=0)
    return {'count': len(actual), 'accuracy': accuracy_score(actual, predicted), 'precision': p, 'recall': r, 'f1': f, 'macroF1': precision_recall_fscore_support(actual, predicted, average='macro', zero_division=0)[2], 'balancedAccuracy': balanced_accuracy_score(actual, predicted), 'confusionMatrix': confusion_matrix(actual, predicted, labels=[0, 1]).tolist(), 'matrixOrder': 'rows actual [benign, misuse], columns predicted [benign, misuse]'}


def split_fingerprint(splits):
    return digest(json.dumps({n:[{k:r[k] for k in ('id','hash','label','group')} for r in p] for n,p in splits.items()},sort_keys=True))


def evaluate(artifact, splits):
    report, predictions = {}, []
    for name in ('validation', 'test'):
        part = splits[name]
        scored = [(r, *score_text(r['text'], artifact)) for r in part]
        actual = [r['label'] for r, _, _ in scored]
        predicted = [int(s >= artifact['threshold']) for _, s, _ in scored]
        covered = [(r, s, c) for r, s, c in scored if in_scope(r['text'], artifact, c)]
        report[name] = {'allCases': metrics(actual, predicted), 'covered': metrics([r['label'] for r, _, _ in covered], [int(s >= artifact['threshold']) for _, s, _ in covered]) if covered else None, 'coverage': len(covered)/len(part), 'abstentions': len(part)-len(covered), 'majorityBaseline': metrics(actual, [artifact['majorityClass']]*len(part))}
        predictions.extend({'id': r['id'], 'split': name, 'actual': r['label'], 'predicted': int(s >= artifact['threshold']), 'score': s, 'covered': in_scope(r['text'], artifact, c)} for r, s, c in scored)
    return report, predictions


def train():
    import sklearn
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    rows, audit = prepare()
    splits = partition(rows)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, part in splits.items():
        (OUTPUT / f'{name}.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in part), encoding='utf-8')
    vectorizer = TfidfVectorizer(lowercase=False, token_pattern=r'(?u)\b\w+\b', ngram_range=(1, 3), sublinear_tf=True, min_df=2, max_features=40000)
    x = vectorizer.fit_transform([r['text'] for r in splits['train']])
    xv = vectorizer.transform([r['text'] for r in splits['validation']])
    candidates = []
    winner = None
    for c in (0.25, 1.0, 4.0):
        model = LogisticRegression(C=c, class_weight='balanced', max_iter=1000, random_state=42)
        model.fit(x, [r['label'] for r in splits['train']])
        result = metrics([r['label'] for r in splits['validation']], model.predict(xv))
        candidates.append({'C': c, 'validation': result})
        if winner is None or result['macroF1'] > winner[0]:
            winner = (result['macroF1'], c, model)
    _, c, model = winner
    manifest_hash = split_fingerprint(splits)
    artifact = {'schemaVersion': 6, 'kind': 'context_tfidf_logistic', 'version': 'v6-cryptollm-'+manifest_hash[:16], 'revision': REVISION, 'counts': {n:len(p) for n,p in splits.items()}, 'threshold': 0.5, 'maxTokens': 2000, 'minVocabularyCoverage': 0.5, 'majorityClass': Counter(r['label'] for r in splits['train']).most_common(1)[0][0], 'vocabulary': {k:int(v) for k,v in vectorizer.vocabulary_.items()}, 'idf': vectorizer.idf_.tolist(), 'coefficients': model.coef_[0].tolist(), 'intercept': float(model.intercept_[0]), 'C': c, 'manifestHash': manifest_hash, 'use': 'Local research only; no explicit upstream license; do not redistribute pending clarification'}
    # Portable implementation must match sklearn BEFORE looking at test labels.
    expected = model.predict_proba(xv)[:, 1]
    delta = max(abs(score_text(r['text'], artifact)[0]-float(s)) for r,s in zip(splits['validation'], expected))
    if delta > 1e-10:
        raise AssertionError(f'Portable inference mismatch: {delta}')
    evaluation, predictions = evaluate(artifact, splits)
    artifact['evaluation'] = {n:{'metrics':m['covered'], 'coverage':m['coverage'], 'total':m['allCases']['count']} for n,m in evaluation.items()}
    report = {'version': artifact['version'], 'source': 'https://github.com/heewonB/CryptoLLM', 'revision': REVISION, 'sourceHashes': FILES, 'audit': audit, 'counts': artifact['counts'], 'labels': {n:dict(Counter(r['label'] for r in p)) for n,p in splits.items()}, 'split': 'Fixed seed 42; first StratifiedGroupKFold(5) test and first StratifiedGroupKFold(4) validation from development; no seed search', 'candidates': candidates, 'selectedC': c, 'threshold': 0.5, 'portableMaximumError': delta, 'evaluation': evaluation, 'manifestHash': manifest_hash, 'modelSelection': 'Validation macro F1; test never used for selection; no refit on validation', 'versions': {'python': platform.python_version(), 'sklearn': sklearn.__version__}, 'limitations': ['No explicit upstream license. Local research artifacts only.', 'Labels apply to snippets, not individual lines or full-file security.', 'Preprocessed Android snippets differ from uploaded Java; distribution shift remains.', 'No project identifiers; structural grouping cannot prove app-level independence.', 'Vocabulary coverage is only an input filter, not calibrated out-of-distribution detection.', 'Test is internal grouped holdout, not external production validation.', 'RSA numeric policy model is a separate earlier experiment.']}
    (OUTPUT/'model.json.tmp').write_text(json.dumps(artifact), encoding='utf-8')
    (OUTPUT/'model.json.tmp').replace(OUTPUT/'model.json')
    (OUTPUT/'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    (OUTPUT/'predictions.json').write_text(json.dumps(predictions, indent=2), encoding='utf-8')
    return report


def evaluate_only():
    artifact = json.loads((OUTPUT/'model.json').read_text(encoding='utf-8'))
    splits = {n:[json.loads(s) for s in (OUTPUT/f'{n}.jsonl').read_text(encoding='utf-8').splitlines()] for n in ('train','validation','test')}
    manifest = split_fingerprint(splits)
    if manifest != artifact['manifestHash'] or any(digest(r['text']) != r['hash'] for p in splits.values() for r in p):
        raise ValueError('Frozen split mismatch')
    result, _ = evaluate(artifact, splits)
    return {'trainingPerformed': False, 'evaluation': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--evaluate-only', action='store_true')
    args = parser.parse_args()
    if args.download:
        download()
        print('Pinned original dataset downloaded and SHA-256 verified. No training performed.')
    else:
        result = evaluate_only() if args.evaluate_only else train()
        print(json.dumps({k:v for k,v in result.items() if k in ('audit','counts','evaluation','selectedC','portableMaximumError','trainingPerformed')}, indent=2))


if __name__ == '__main__':
    main()
