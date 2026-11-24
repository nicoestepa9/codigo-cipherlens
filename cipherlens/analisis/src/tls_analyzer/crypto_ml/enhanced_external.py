"""Transfer diagnostic on the same predeclared CryptoAPI categories as V6."""
from __future__ import annotations

import hashlib
import json

from .cryptollm import ROOT,OUTPUT as BASE_OUTPUT,metrics
from .context_external import CATEGORIES
from .context_model import canonical,in_scope,score_text
from .enhanced_context import OUTPUT,MODEL_PATH,predict
from .experiment import digest,normalize


def evaluate():
    artifact=json.loads(MODEL_PATH.read_text(encoding='utf-8'))
    frozen=[json.loads(s) for n in ('train','validation','test') for s in (BASE_OUTPUT/f'{n}.jsonl').read_text(encoding='utf-8').splitlines()]
    hashes,groups={r['hash'] for r in frozen},{r['group'] for r in frozen}
    benchmark=ROOT/'data/cryptoapi/CryptoAPI-Bench-e6b6b50fef6970151300c1ac2de62e188ba6de19'
    selected=[json.loads(s) for s in (ROOT/'data/crypto_ml/dataset.jsonl').read_text(encoding='utf-8').splitlines() if json.loads(s)['category'] in CATEGORIES]
    result=[];excluded=[]
    for row in selected:
        source='\n'.join((benchmark/p).read_text(encoding='utf-8-sig') for p in row['sourcePaths'])
        if digest(normalize(source))!=row['sha256']:
            raise ValueError('External source mismatch')
        clean=canonical(source)
        if digest(clean) in hashes or digest(canonical(source,skeleton=True)) in groups:
            excluded.append(row['id']);continue
        score,coverage,route=predict(source,artifact)
        old,_=score_text(clean,artifact['lexicalModel'])
        result.append({'id':row['id'],'actual':row['label'],'score':score,'prediction':int(score>=0.5),'v6Prediction':int(old>=0.5),'covered':in_scope(clean,artifact['lexicalModel'],coverage),'route':route})
    covered=[r for r in result if r['covered']]
    report={'benchmark':'CryptoAPI-Bench','modelVersion':artifact['version'],'modelSha256':hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest(),'trainingPerformed':False,'thresholdChanged':False,'retained':len(result),'covered':len(covered),'coverage':len(covered)/len(result),'excludedOverlap':excluded,'metrics':metrics([r['actual'] for r in covered],[r['prediction'] for r in covered]),'v6SameCases':metrics([r['actual'] for r in covered],[r['v6Prediction'] for r in covered]),'results':result,'limitations':['Previously observed transfer benchmark, not untouched external validation.','Same five categories as V6; overlap check on full canonical snippets and structures only.']}
    (OUTPUT/'external-cryptoapi.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


if __name__=='__main__':
    print(json.dumps({k:v for k,v in evaluate().items() if k!='results'},indent=2))
