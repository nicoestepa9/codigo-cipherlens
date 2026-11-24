"""Offline, category-specific supervised experiment. Never selected by the API.

Only original category labels are used. A negative for one category is never a
negative for another. Existing OWASP partitions stay frozen; tiny CryptoAPI
categories may fail the predeclared grouped split and then remain unavailable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from .cryptollm import ROOT, partition, metrics, split_fingerprint
from .combined_owasp import prepare as combined_prepare, assert_disjoint, jsonl
from .context_model import canonical
from .experiment import digest, normalize, REVISION
from .semantic_features import features
from .enhanced_context import export_forest, forest_score

OUTPUT = ROOT/'artifacts/category-experiment'
CATEGORIES = ('algorithm_mode', 'predictable_key', 'constant_iv')
MAPPING = {'predictablecryptographickey': 'predictable_key', 'staticinitializationvector': 'constant_iv'}


def category_features(values, category):
    """Project neutral observations, without labels, findings or risk thresholds."""
    if category == 'algorithm_mode':
        # Identity of observed crypto literals only, no servlet boilerplate.
        return {k:v for k,v in values.items() if k.startswith('literal.')}
    if category not in CATEGORIES:
        raise ValueError('Unsupported category')
    field = 'keyOrigin=' if category == 'predictable_key' else 'parameterOrigin='
    result = {}
    for key, value in values.items():
        if key.startswith('init.') and ('.'+field in key or '.operation=' in key):
            attribute = key.rsplit('.', 1)[1]
            result[attribute] = max(result.get(attribute, 0), value)
    return result


def deduplicate(rows):
    buckets = defaultdict(list)
    for row in rows:
        buckets[row['hash']].append(row)
    kept, excluded = [], []
    for bucket in buckets.values():
        if len({r['label'] for r in bucket}) > 1:
            excluded.extend({'id':r['id'],'reason':'contradictory_canonical_labels'} for r in bucket)
        else:
            kept.append(bucket[0])
            excluded.extend({'id':r['id'],'reason':'canonical_duplicate'} for r in bucket[1:])
    return kept, excluded


def prepare():
    combined, _, audit = combined_prepare()
    splits = {'algorithm_mode': {n:[r for r in rows if r['source']=='OWASP'] for n,rows in combined.items()}}
    codes, raw = {}, defaultdict(list)
    for rows in splits['algorithm_mode'].values():
        for r in rows:
            codes[r['id']] = (ROOT/'data/owasp-source'/(r['id'].split(':',1)[1]+'.java')).read_text(encoding='utf-8-sig')
    source = ROOT/f'data/cryptoapi/CryptoAPI-Bench-{REVISION}'
    for row in jsonl(ROOT/'data/crypto_ml/dataset.jsonl'):
        if row['category'] not in MAPPING:
            continue
        code = '\n'.join((source/p).read_text(encoding='utf-8-sig') for p in row['sourcePaths'])
        if digest(normalize(code)) != row['sha256']:
            raise ValueError('CryptoAPI source mismatch')
        identifier = 'cryptoapi:'+row['id']
        codes[identifier] = code
        raw[MAPPING[row['category']]].append({'id':identifier,'label':row['label'],
            'hash':digest(canonical(code)),'group':digest(canonical(code,skeleton=True)),
            'source':'CryptoAPI-Bench','text':canonical(code)})
    unavailable = {}
    for category in ('predictable_key','constant_iv'):
        rows, excluded = deduplicate(raw[category])
        try:
            splits[category] = partition(rows)
        except ValueError as exc:
            unavailable[category] = {'status':'insufficient_data','reason':str(exc),
                'rawCount':len(raw[category]),'retained':len(rows),
                'labels':dict(Counter(r['label'] for r in rows)), 'excluded':excluded}
    for parts in splits.values():
        assert_disjoint(parts)
    return splits, codes, {'upstream':audit,'unavailable':unavailable}


def score(values, artifact):
    projected = category_features(values, artifact['category'])
    supported = any(k in artifact['features'] for k in projected)
    if artifact['category'] == 'algorithm_mode' and any(k not in artifact['features'] for k in projected):
        return {'status':'abstained','reason':'Unseen cryptographic literal; cannot classify this category'}
    if not supported:
        return {'status':'abstained','reason':'No represented observations for this category'}
    return {'status':'applied','score':forest_score(projected, artifact)}


def evaluate(rows, values, artifact):
    predictions = []
    for row in rows:
        result = score(values[row['id']], artifact)
        predictions.append({'id':row['id'],'actual':row['label'],**result})
    covered = [r for r in predictions if r['status']=='applied']
    return {'total':len(rows),'covered':len(covered),'coverage':len(covered)/len(rows),
            'metrics':metrics([r['actual'] for r in covered],[int(r['score']>=.5) for r in covered]) if covered else None,
            'predictions':predictions}


def transfer_algorithm(artifact, parts):
    """Previously observed cross-source diagnostic, never used for selection."""
    source = ROOT/f'data/cryptoapi/CryptoAPI-Bench-{REVISION}'
    groups = {r['group'] for part in parts.values() for r in part}
    hashes = {r['hash'] for part in parts.values() for r in part}
    rows, values, excluded = [], {}, []
    for row in jsonl(ROOT/'data/crypto_ml/dataset.jsonl'):
        if row['category'] not in {'brokencrypto','ecbcrypto'}:
            continue
        code = '\n'.join((source/p).read_text(encoding='utf-8-sig') for p in row['sourcePaths'])
        if digest(normalize(code)) != row['sha256']:
            raise ValueError('CryptoAPI source mismatch')
        if digest(canonical(code)) in hashes or digest(canonical(code,skeleton=True)) in groups:
            excluded.append(row['id'])
            continue
        rows.append(row)
        values[row['id']] = features(code)
    return {'benchmark':'CryptoAPI-Bench algorithm categories; already observed',
            'excludedOverlaps':excluded, **evaluate(rows,values,artifact)}


def run():
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.ensemble import ExtraTreesClassifier
    splits, codes, audit = prepare()
    OUTPUT.mkdir(parents=True,exist_ok=True)
    report = {'active':False,'labelMeaning':'Category-target binary label; never a full-file security verdict',
              'audit':audit,'categories':{},'limitations':[
                  'OWASP and CryptoAPI-Bench have already been observed during development.',
                  'CryptoLLM has no category annotations and is deliberately not relabelled with rules.',
                  'Grouped template splits do not prove semantic or project independence.',
                  'No category is automatically enabled in the API.']}
    models = {}
    for category, parts in splits.items():
        out = OUTPUT/category
        out.mkdir(exist_ok=True)
        for name, rows in parts.items():
            (out/f'{name}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf-8')
        values = {r['id']:features(codes[r['id']]) for n in ('train','validation') for r in parts[n]}
        vectorizer = DictVectorizer()
        x = vectorizer.fit_transform([category_features(values[r['id']],category) for r in parts['train']])
        if x.shape[1] == 0:
            report['categories'][category] = {'status':'unavailable','reason':'No training observations'}
            continue
        candidates, winner = [], None
        for leaf in (1, 3):
            model = ExtraTreesClassifier(n_estimators=80,max_depth=8,min_samples_leaf=leaf,
                class_weight='balanced',random_state=42,n_jobs=2)
            model.fit(x,[r['label'] for r in parts['train']])
            artifact = {**export_forest(model,vectorizer),'category':category,
                        'manifestHash':split_fingerprint(parts)}
            xv = vectorizer.transform([category_features(values[r['id']],category) for r in parts['validation']])
            portable_error = max(abs(forest_score(category_features(values[r['id']],category),artifact)-float(p))
                for r,p in zip(parts['validation'],model.predict_proba(xv)[:,1]))
            if portable_error>1e-10:
                raise AssertionError('Portable forest mismatch')
            validation = evaluate(parts['validation'],values,artifact)
            entry = {'minLeaf':leaf,'portableMaximumError':portable_error,'validation':{k:v for k,v in validation.items() if k!='predictions'}}
            candidates.append(entry)
            rank = validation['metrics']['macroF1'] if validation['metrics'] else -1
            if winner is None or rank>winner[0]:
                winner = rank, artifact, entry
        _, artifact, selected = winner
        artifact['version'] = 'category-'+category+'-'+digest(json.dumps(artifact,sort_keys=True))[:16]
        (out/'selected-model-before-test.json').write_text(json.dumps(artifact),encoding='utf-8')
        values.update({r['id']:features(codes[r['id']]) for r in parts['test']})
        test = evaluate(parts['test'],values,artifact)
        entry = {'status':'experimental','version':artifact['version'],
            'counts':{n:{'total':len(rows),'labels':dict(Counter(r['label'] for r in rows))} for n,rows in parts.items()},
            'selected':selected,'candidates':candidates,'test':test}
        report['categories'][category] = entry
        if category == 'algorithm_mode':
            entry['transfer'] = transfer_algorithm(artifact,parts)
        models[category] = artifact
        (out/'model.json').write_text(json.dumps(artifact),encoding='utf-8')
    report['categories'].update(audit['unavailable'])
    report['scriptSha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (OUTPUT/'models.json').write_text(json.dumps(models),encoding='utf-8')
    (OUTPUT/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


def evaluate_only():
    models = json.loads((OUTPUT/'models.json').read_text(encoding='utf-8'))
    _, codes, _ = prepare()
    results = {}
    for category, artifact in models.items():
        parts = {n:jsonl(OUTPUT/category/f'{n}.jsonl') for n in ('train','validation','test')}
        assert_disjoint(parts)
        if split_fingerprint(parts) != artifact['manifestHash']:
            raise ValueError('Frozen category manifest changed')
        for part in parts.values():
            for row in part:
                if digest(canonical(codes[row['id']])) != row['hash']:
                    raise ValueError('Frozen category source changed')
        values = {r['id']:features(codes[r['id']]) for r in parts['test']}
        results[category] = evaluate(parts['test'],values,artifact)
    return {'trainingPerformed':False,'test':results}


def analyze_file(path):
    if path.suffix.lower() != '.java' or path.stat().st_size>100_000:
        raise ValueError('Expected .java file up to 100000 bytes')
    values = features(path.read_text(encoding='utf-8-sig'))
    models = json.loads((OUTPUT/'models.json').read_text(encoding='utf-8'))
    return {category:score(values,models[category]) if category in models else
            {'status':'unavailable','reason':'No trained model with sufficient labelled data'} for category in CATEGORIES}


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,help='Infer only; does not fit or change the API')
    parser.add_argument('--evaluate-only',action='store_true')
    args = parser.parse_args()
    print(json.dumps(analyze_file(args.source) if args.source else evaluate_only() if args.evaluate_only else run(),indent=2))
