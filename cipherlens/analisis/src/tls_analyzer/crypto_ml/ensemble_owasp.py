"""Validation-selected convex ensemble; preserve V14 and active V12 artifacts.

This follow-up was designed after observing V14 test results. Tests are reused
development benchmarks; all coefficient selection still uses validation only.
"""
import copy
import hashlib
import json

from . import structured_owasp as structured
from . import combined_owasp as combined
from .cryptollm import ROOT, metrics, split_fingerprint
from .enhanced_context import predict as baseline_predict

OUTPUT = ROOT/'artifacts/ensemble-owasp-candidate'


def run():
    parent = json.loads((structured.OUTPUT/'model.json').read_text(encoding='utf-8'))
    splits = {n: combined.jsonl(structured.OUTPUT/f'{n}.jsonl') for n in ('train','validation','test')}
    combined.assert_disjoint(splits)
    if split_fingerprint(splits) != parent['combinedManifestHash']:
        raise ValueError('Combined manifest mismatch')
    codes = combined.load_inputs(splits)
    values = {r['id']: combined.features(codes[r['id']]) for r in splits['validation']}
    baseline, _ = combined.evaluate_rows(splits['validation'], parent['baseline'], codes, values)
    candidates = []
    # Scores are cached; no tree or lexical weights are fit in this experiment.
    pairs = {r['id']: (baseline_predict(codes[r['id']],parent['baseline'], values=values[r['id']])[0],
                       structured.predict(codes[r['id']],parent,values=values[r['id']])[0]) for r in splits['validation']}
    for weight in (.0, .25, .4, .5, .6, .75, 1.):
        report = {}
        for source in ('CryptoLLM','OWASP'):
            rows = [r for r in splits['validation'] if r['source']==source]
            report[source] = metrics([r['label'] for r in rows], [int((1-weight)*pairs[r['id']][0]+weight*pairs[r['id']][1]>=.5) for r in rows])
        eligible = report['CryptoLLM']['f1'] >= baseline['CryptoLLM']['allCases']['f1']-.005
        candidates.append({'weight':weight,'eligible':eligible,'metrics':report,
                           'meanMacroF1':sum(report[s]['macroF1'] for s in report)/2})
    selected = max((r for r in candidates if r['eligible']), key=lambda r:r['meanMacroF1'])
    artifact = copy.deepcopy(parent)
    artifact['ensembleWeight'] = selected['weight']
    artifact['version'] = 'v15-ensemble-'+hashlib.sha256(json.dumps(artifact,sort_keys=True).encode()).hexdigest()[:16]
    OUTPUT.mkdir(parents=True,exist_ok=True)
    (OUTPUT/'selected-model-before-test.json').write_text(json.dumps(artifact),encoding='utf-8')
    values = {r['id']: combined.features(codes[r['id']]) for r in splits['test']}
    test, predictions = structured.evaluate(splits['test'],artifact,codes,values)
    report = {'version':artifact['version'],'active':False,'selected':selected,'candidates':candidates,'test':test,
              'trainingPerformed':False,'trainingSources':parent['trainingSources'],
              'limitations':['Follow-up designed after V14 test inspection; test is a reused development benchmark.',
                             'Scores are a convex ensemble, not calibrated vulnerability probabilities.',
                             'No independent external generalization claim.']}
    for name, data in (('model',artifact),('report',report),('test-predictions',predictions)):
        (OUTPUT/f'{name}.json').write_text(json.dumps(data,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    run()
