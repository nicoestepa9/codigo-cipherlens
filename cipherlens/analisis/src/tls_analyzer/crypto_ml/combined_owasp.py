"""Candidate contextual model: CryptoLLM + labelled OWASP crypto cases.

Train only the lexical component; preserve V12's structured models. Freeze
source-specific grouped splits, select using validation only, evaluate test last.
OWASP is already observed development data, not untouched external validation.
Nothing here changes the model served by the API.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from .context_model import canonical, score_text, in_scope
from .cryptollm import ROOT, OUTPUT as LEXICAL_OUTPUT, partition, metrics, split_fingerprint
from .enhanced_context import OUTPUT as V12_OUTPUT, predict, features
from .experiment import digest
from .external import expected_rows, OWASP_REVISION

OUTPUT = ROOT/'artifacts/cryptollm-owasp-candidate'


def jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line]


def prepare():
    crypto={n:jsonl(LEXICAL_OUTPUT/f'{n}.jsonl') for n in ('train','validation','test')}
    baseline=json.loads((V12_OUTPUT/'model.json').read_text(encoding='utf-8'))
    if split_fingerprint(crypto)!=baseline['manifestHash']:
        raise ValueError('Frozen CryptoLLM partitions changed')
    known_groups={r['group'] for part in crypto.values() for r in part}
    known_hashes={r['hash'] for part in crypto.values() for r in part}
    source=ROOT/'data/owasp-source'
    manifest=json.loads((source/'download-manifest.json').read_text(encoding='utf-8'))
    if manifest['revision']!=OWASP_REVISION:
        raise ValueError('OWASP revision mismatch')
    expected_hashes={r['id']:r['sha256'] for r in manifest['files']}
    selected=[];excluded=[]
    for row in expected_rows(source):
        if row['category']!='crypto':
            continue
        raw=(source/(row['id']+'.java')).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected_hashes[row['id']]:
            raise ValueError('OWASP source checksum mismatch')
        code=raw.decode('utf-8-sig');text=canonical(code)
        sample={'id':'owasp:'+row['id'],'label':row['label'],'text':text,'hash':digest(text),'group':digest(canonical(code,skeleton=True)),'source':'OWASP','sourceSha256':expected_hashes[row['id']]}
        if sample['group'] in known_groups or sample['hash'] in known_hashes:
            excluded.append({'id':sample['id'],'reason':'overlap_with_frozen_CryptoLLM'})
        else:
            selected.append(sample)
    buckets=defaultdict(list)
    for row in selected:
        buckets[row['hash']].append(row)
    retained=[]
    for bucket in buckets.values():
        if len({r['label'] for r in bucket})>1:
            excluded.extend({'id':r['id'],'reason':'conflicting_normalized_labels'} for r in bucket)
        else:
            retained.append(bucket[0])
            excluded.extend({'id':r['id'],'reason':'duplicate_normalized_source'} for r in bucket[1:])
    owasp=partition(retained)
    splits={n:[{**r,'source':'CryptoLLM'} for r in crypto[n]]+owasp[n] for n in crypto}
    assert_disjoint(splits)
    return splits,baseline,{'owaspRevision':OWASP_REVISION,'owaspLabelCsvSha256':hashlib.sha256((source/'expectedresults-1.2.csv').read_bytes()).hexdigest(),'selectedCategory':'crypto','selectedBeforeDeduplication':len(selected),'retained':len(retained),'excluded':excluded,'limitations':['OWASP has been observed in previous experiments and V3, so it is not a newly untouched external benchmark.','Only whole canonical and structural matches are excluded; no proof of semantic independence.','OWASP labels concern target cipher misuses, not every possible defect in a servlet.','CryptoLLM license remains unspecified; corpus and derived model stay local.','No OWASP sample is used to refit the structured provenance or numeric RSA models.']}


def assert_disjoint(splits):
    for a,b in (('train','validation'),('train','test'),('validation','test')):
        for key in ('id','hash','group'):
            if {r[key] for r in splits[a]} & {r[key] for r in splits[b]}:
                raise ValueError('Cross-partition leakage: '+key)


def load_inputs(splits):
    from .enhanced_context import load_sources
    crypto=load_sources()
    codes={}
    for part in splits.values():
        for row in part:
            code=(ROOT/'data/owasp-source'/(row['id'].split(':',1)[1]+'.java')).read_text(encoding='utf-8-sig') if row['source']=='OWASP' else crypto[row['id']]
            if digest(canonical(code))!=row['hash']:
                raise ValueError('Frozen source mismatch')
            codes[row['id']]=code
    return codes


def evaluate_rows(rows,artifact,codes,observations):
    scored=[]
    for row in rows:
        score,coverage,route=predict(codes[row['id']],artifact,values=observations[row['id']])
        scored.append({'id':row['id'],'source':row['source'],'actual':row['label'],'score':score,'predicted':int(score>=0.5),'covered':in_scope(row['text'],artifact['lexicalModel'],coverage),'route':route})
    report={}
    for source in ('CryptoLLM','OWASP'):
        part=[r for r in scored if r['source']==source]
        covered=[r for r in part if r['covered']]
        report[source]={'total':len(part),'allCases':metrics([r['actual'] for r in part],[r['predicted'] for r in part]),'coverage':len(covered)/len(part),'covered':metrics([r['actual'] for r in covered],[r['predicted'] for r in covered]) if covered else None}
    report['meanSourceMacroF1']=sum(report[s]['allCases']['macroF1'] for s in ('CryptoLLM','OWASP'))/2
    return report,scored


def train():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import sklearn
    splits,baseline,audit=prepare();codes=load_inputs(splits)
    OUTPUT.mkdir(parents=True,exist_ok=True)
    for name,part in splits.items():
        (OUTPUT/f'{name}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in part),encoding='utf-8')
    # Test observations are computed only after model selection and freeze.
    observations={r['id']:features(codes[r['id']]) for n in ('train','validation') for r in splits[n]}
    vectorizer=TfidfVectorizer(lowercase=False,token_pattern=r'(?u)\b\w+\b',ngram_range=(1,3),sublinear_tf=True,min_df=2,max_features=40000)
    xt=vectorizer.fit_transform([r['text'] for r in splits['train']])
    xv=vectorizer.transform([r['text'] for r in splits['validation']])
    y=[r['label'] for r in splits['train']]
    source_counts=Counter(r['source'] for r in splits['train'])
    baseline_validation,_=evaluate_rows(splits['validation'],baseline,codes,observations)
    candidates=[];winner=None
    for weighting in ('uniform','equal_sources'):
        weights=None if weighting=='uniform' else [len(y)/(2*source_counts[r['source']]) for r in splits['train']]
        for c in (0.25,1.0,4.0):
            model=LogisticRegression(C=c,class_weight='balanced',max_iter=1000,random_state=42)
            model.fit(xt,y,sample_weight=weights)
            lexical={**baseline['lexicalModel'],'vocabulary':{k:int(v) for k,v in vectorizer.vocabulary_.items()},'idf':vectorizer.idf_.tolist(),'coefficients':model.coef_[0].tolist(),'intercept':float(model.intercept_[0]),'C':c,'counts':{n:len(p) for n,p in splits.items()}}
            lexical.pop('evaluation',None)
            artifact={**baseline,'lexicalModel':lexical}
            # Validate portable scores on validation before any test evaluation.
            delta=max(abs(score_text(r['text'],lexical)[0]-float(s)) for r,s in zip(splits['validation'],model.predict_proba(xv)[:,1]))
            if delta>1e-10:
                raise AssertionError('Portable lexical inference mismatch')
            validation,_=evaluate_rows(splits['validation'],artifact,codes,observations)
            entry={'C':c,'sourceWeighting':weighting,'validation':validation,'portableMaximumError':delta}
            candidates.append(entry)
            if winner is None or validation['meanSourceMacroF1']>winner[0]:
                winner=(validation['meanSourceMacroF1'],entry,copy.deepcopy(artifact))
    _,selected,artifact=winner
    artifact.pop('externalEvaluation',None)
    artifact.pop('evaluation',None)
    artifact['schemaVersion']=13
    artifact['kind']='context_combined_cryptollm_owasp'
    artifact['counts']={n:len(p) for n,p in splits.items()}
    artifact['trainingSources']=dict(source_counts)
    artifact['owaspRevision']=OWASP_REVISION
    artifact['baseManifestHash']=artifact.pop('manifestHash')
    artifact['combinedManifestHash']=split_fingerprint(splits)
    weights={k:artifact['lexicalModel'][k] for k in ('coefficients','idf','vocabulary','intercept')}
    artifact['version']='v13-combined-'+digest(json.dumps({'manifest':artifact['combinedManifestHash'],'weights':weights,'baselineVersion':baseline['version'],'selected':selected['sourceWeighting']},sort_keys=True))[:16]
    artifact['lexicalModel']['version']=artifact['version']+'-lexical'
    artifact['lexicalModel']['manifestHash']=artifact['combinedManifestHash']
    artifact['lexicalModel']['trainingSources']=dict(source_counts)
    # Freeze the winner before accessing test predictions.
    (OUTPUT/'selected-model-before-test.json').write_text(json.dumps(artifact),encoding='utf-8')
    observations.update({r['id']:features(codes[r['id']]) for r in splits['test']})
    test,predictions=evaluate_rows(splits['test'],artifact,codes,observations)
    baseline_test,_=evaluate_rows(splits['test'],baseline,codes,observations)
    artifact['evaluationBySource']={'validation':selected['validation'],'test':test}
    report={'version':artifact['version'],'active':False,'baselineVersion':baseline['version'],'sklearnVersion':sklearn.__version__,'audit':audit,'counts':{n:{s:{'size':len([r for r in part if r['source']==s]),'labels':dict(Counter(r['label'] for r in part if r['source']==s))} for s in ('CryptoLLM','OWASP')} for n,part in splits.items()},'selection':'Mean of source-specific validation macro F1, fixed C and weighting candidates, threshold 0.5','selected':selected,'candidates':candidates,'validationBaseline':baseline_validation,'test':test,'testBaseline':baseline_test,'structuredModelsPreserved':True,'combinedManifestHash':artifact['combinedManifestHash'],'scriptSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (OUTPUT/'model.json').write_text(json.dumps(artifact),encoding='utf-8')
    (OUTPUT/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (OUTPUT/'test-predictions.json').write_text(json.dumps(predictions,indent=2),encoding='utf-8')
    return {k:v for k,v in report.items() if k!='candidates'}


def evaluate_only():
    artifact=json.loads((OUTPUT/'model.json').read_text(encoding='utf-8'))
    splits={n:jsonl(OUTPUT/f'{n}.jsonl') for n in ('train','validation','test')}
    assert_disjoint(splits)
    if split_fingerprint(splits)!=artifact['combinedManifestHash']:
        raise ValueError('Combined manifest mismatch')
    codes=load_inputs(splits)
    observations={r['id']:features(codes[r['id']]) for r in splits['test']}
    result,_=evaluate_rows(splits['test'],artifact,codes,observations)
    return {'trainingPerformed':False,'test':result}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evaluate-only',action='store_true')
    args=parser.parse_args()
    print(json.dumps(evaluate_only() if args.evaluate_only else train(),indent=2))
