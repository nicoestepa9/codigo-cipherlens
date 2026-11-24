"""Offline structured CryptoLLM/OWASP experiment; never changes the active model.

Reuse frozen grouped partitions. Select with validation only, serialize before
test, and report each source separately. Previously observed tests are development
benchmarks, not a new independent certification of security.
"""
from __future__ import annotations

import argparse
import hashlib
import json

from . import combined_owasp as combined
from .cryptollm import ROOT, split_fingerprint
from .enhanced_context import export_forest, forest_score, predict as baseline_predict

OUTPUT = ROOT / 'artifacts/structured-owasp-candidate'


def predict(source, artifact, *, values=None):
    values = combined.features(source) if values is None else values
    _, coverage, _ = baseline_predict(source, artifact['baseline'], values=values)
    # The structured model sees algorithm/mode literals and provenance together.
    # Routing uses observations, never findings, labels or severity.
    if any(k.startswith(('literal.', 'init.')) for k in values) or values.get('rsaSizeObserved'):
        score = forest_score(values, artifact)
        if 'ensembleWeight' in artifact:
            baseline_score, _, _ = baseline_predict(source, artifact['baseline'], values=values)
            score = artifact['ensembleWeight']*score + (1-artifact['ensembleWeight'])*baseline_score
        return score, coverage, 'combined_structured_forest'
    return baseline_predict(source, artifact['baseline'], values=values)


def evaluate(rows, artifact, codes, values):
    # Reuse the source-specific metric and abstention conventions of V13.
    from .context_model import in_scope
    from .cryptollm import metrics
    predictions = []
    for row in rows:
        score, coverage, route = predict(codes[row['id']], artifact, values=values[row['id']])
        predictions.append({'id': row['id'], 'source': row['source'], 'actual': row['label'],
                            'score': score, 'predicted': int(score >= .5), 'route': route,
                            'covered': in_scope(row['text'], artifact['baseline']['lexicalModel'], coverage)})
    report = {}
    for source in ('CryptoLLM', 'OWASP'):
        selected = [r for r in predictions if r['source'] == source]
        covered = [r for r in selected if r['covered']]
        report[source] = {'total': len(selected), 'allCases': metrics([r['actual'] for r in selected], [r['predicted'] for r in selected]),
                          'coverage': len(covered)/len(selected),
                          'covered': metrics([r['actual'] for r in covered], [r['predicted'] for r in covered]) if covered else None}
    report['meanSourceMacroF1'] = sum(report[s]['allCases']['macroF1'] for s in ('CryptoLLM', 'OWASP'))/2
    return report, predictions


def train():
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.ensemble import ExtraTreesClassifier
    splits, baseline, audit = combined.prepare()
    codes = combined.load_inputs(splits)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, rows in splits.items():
        (OUTPUT/f'{name}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows), encoding='utf-8')
    values = {r['id']: combined.features(codes[r['id']]) for name in ('train', 'validation') for r in splits[name]}
    vectorizer = DictVectorizer()
    x = vectorizer.fit_transform([values[r['id']] for r in splits['train']])
    y = [r['label'] for r in splits['train']]
    source_counts = {s: sum(r['source'] == s for r in splits['train']) for s in ('CryptoLLM', 'OWASP')}
    candidates = []
    winner = None
    for leaf in (1, 3):
        for weighting in ('uniform', 'equal_sources'):
            weights = None if weighting == 'uniform' else [len(y)/(2*source_counts[r['source']]) for r in splits['train']]
            model = ExtraTreesClassifier(n_estimators=160, max_depth=16, min_samples_leaf=leaf, max_features=1.0,
                                         class_weight='balanced', random_state=42, n_jobs=2)
            model.fit(x, y, sample_weight=weights)
            artifact = {**export_forest(model, vectorizer), 'baseline': baseline,
                        'lexicalModel': baseline['lexicalModel'], 'schemaVersion': 14,
                        'combinedManifestHash': split_fingerprint(splits), 'trainingSources': source_counts}
            validation, _ = evaluate(splits['validation'], artifact, codes, values)
            # Guard against sacrificing the dominant source to improve OWASP.
            eligible = validation['CryptoLLM']['allCases']['f1'] >= .93
            entry = {'minSamplesLeaf': leaf, 'weighting': weighting, 'eligible': eligible, 'validation': validation}
            candidates.append(entry)
            rank = (eligible, validation['meanSourceMacroF1'])
            if winner is None or rank > winner[0]:
                winner = rank, artifact, entry
    _, artifact, selected = winner
    artifact['version'] = 'v14-structured-' + hashlib.sha256(json.dumps(artifact, sort_keys=True).encode()).hexdigest()[:16]
    (OUTPUT/'selected-model-before-test.json').write_text(json.dumps(artifact), encoding='utf-8')
    values.update({r['id']: combined.features(codes[r['id']]) for r in splits['test']})
    test, predictions = evaluate(splits['test'], artifact, codes, values)
    baseline_test, _ = combined.evaluate_rows(splits['test'], baseline, codes, values)
    audit['limitations'] = [x for x in audit['limitations'] if not x.startswith('No OWASP sample')]
    report = {'version': artifact['version'], 'active': False, 'audit': audit, 'selected': selected,
              'candidates': candidates, 'test': test, 'baselineTest': baseline_test,
              'counts': {n: len(r) for n, r in splits.items()}, 'trainingSources': source_counts,
              'selection': 'Validation mean source macro F1; prefer CryptoLLM validation F1 >= 0.93; threshold 0.5',
              'scriptSha256': hashlib.sha256(__import__('pathlib').Path(__file__).read_bytes()).hexdigest()}
    for name, data in (('model', artifact), ('report', report), ('test-predictions', predictions)):
        (OUTPUT/f'{name}.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
    return report


def evaluate_only():
    artifact = json.loads((OUTPUT/'model.json').read_text(encoding='utf-8'))
    splits = {n: combined.jsonl(OUTPUT/f'{n}.jsonl') for n in ('train', 'validation', 'test')}
    combined.assert_disjoint(splits)
    if split_fingerprint(splits) != artifact['combinedManifestHash']:
        raise ValueError('Combined manifest mismatch')
    codes = combined.load_inputs(splits)
    values = {r['id']: combined.features(codes[r['id']]) for r in splits['test']}
    report, _ = evaluate(splits['test'], artifact, codes, values)
    return {'trainingPerformed': False, 'test': report}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evaluate-only', action='store_true')
    args = parser.parse_args()
    print(json.dumps(evaluate_only() if args.evaluate_only else train(), indent=2))
