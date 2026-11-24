"""Frozen contextual-model transfer check; never fits or selects a threshold.

CryptoAPI-Bench was previously observed in this project: a transfer diagnostic,
not an untouched external test. Labels cover benchmark targets, not all security.
"""
from __future__ import annotations

import json
from collections import Counter

from .context_model import canonical, score_text, in_scope
from .cryptollm import ROOT, OUTPUT, metrics
from .experiment import digest

CATEGORIES = {'brokencrypto', 'ecbcrypto', 'insecureasymmetriccrypto', 'predictablecryptographickey', 'staticinitializationvector'}


def evaluate():
    artifact = json.loads((OUTPUT/'model.json').read_text(encoding='utf-8'))
    frozen = [json.loads(line) for name in ('train','validation','test') for line in (OUTPUT/f'{name}.jsonl').read_text(encoding='utf-8').splitlines()]
    hashes, groups = {r['hash'] for r in frozen}, {r['group'] for r in frozen}
    source = ROOT/'data/cryptoapi/CryptoAPI-Bench-e6b6b50fef6970151300c1ac2de62e188ba6de19'
    rows = [json.loads(line) for line in (ROOT/'data/crypto_ml/dataset.jsonl').read_text(encoding='utf-8').splitlines()]
    result, excluded = [], []
    for row in rows:
        if row['category'] not in CATEGORIES:
            continue
        code = '\n'.join((source/path).read_text(encoding='utf-8-sig') for path in row['sourcePaths'])
        text = canonical(code)
        if digest(text) in hashes or digest(canonical(code,skeleton=True)) in groups:
            excluded.append({'id':row['id'], 'reason':'canonical_or_structural_overlap_with_CryptoLLM'})
            continue
        score, coverage = score_text(text,artifact)
        result.append({'id':row['id'], 'category':row['category'], 'actual':row['label'], 'predicted':int(score>=artifact['threshold']), 'score':score, 'covered':in_scope(text,artifact,coverage)})
    covered = [r for r in result if r['covered']]
    report = {'modelVersion':artifact['version'], 'modelSha256':digest((OUTPUT/'model.json').read_text(encoding='utf-8')), 'trainingPerformed':False, 'thresholdChanged':False, 'benchmark':'CryptoAPI-Bench', 'categories':sorted(CATEGORIES), 'retained':len(result), 'excluded':excluded, 'covered':len(covered), 'coverage':len(covered)/len(result) if result else 0, 'metrics':metrics([r['actual'] for r in covered],[r['predicted'] for r in covered]) if covered else None, 'byCategory':{}, 'results':result, 'limitations':['Previously observed benchmark; transfer diagnostic, not untouched external validation.', 'Overlap detection covers whole canonical snippets/skeletons, not semantic or substring overlap.', 'Labels concern benchmark-specific targets; model output is binary snippet screening.']}
    for category in sorted(CATEGORIES):
        part = [r for r in covered if r['category']==category]
        report['byCategory'][category] = metrics([r['actual'] for r in part],[r['predicted'] for r in part]) if part else None
    (OUTPUT/'external-cryptoapi.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return {k:v for k,v in report.items() if k!='results'}


if __name__ == '__main__':
    print(json.dumps(evaluate(),indent=2))
