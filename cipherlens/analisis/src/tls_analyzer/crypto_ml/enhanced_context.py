"""V12: learned numerical/provenance models with lexical fallback.

The routing condition depends on availability of neutral observations, never on
security findings or a hand-written risk threshold. All model weights are learned
from upstream labels. Previously observed benchmarks remain development checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from functools import lru_cache
from pathlib import Path

from .context_model import canonical, score_text, in_scope, tokens
from .cryptollm import ROOT, OUTPUT as BASE_OUTPUT, FILES, split_fingerprint, metrics
from .semantic_features import features

OUTPUT = ROOT/'artifacts/cryptollm-v12'
MODEL_PATH = OUTPUT/'model.json'


def has_observations(values):
    return bool(values.get('rsaSizeObserved') or any(k.startswith('init.') and ('.parameterOrigin=constant' in k or '.parameterOrigin=runtime' in k or '.keyOrigin=constant' in k) for k in values))


def observation_features(values):
    """Represent provenance independently of transformation and boilerplate."""
    result={k:v for k,v in values.items() if k in {'rsaSizeObserved','rsaMinLog2','rsaMaxLog2'}}
    for key,value in values.items():
        if not key.startswith('init.'):
            continue
        transformation,attribute=key[5:].rsplit('.',1)
        # Provenance should transfer between CBC/GCM and padding spellings.
        # These neutral observations describe the same dataflow regardless of
        # the transformation's lexical identity. Policy decisions stay learned.
        # Encoded string lengths are often absent from upstream snippets while
        # random arrays have explicit lengths. Do not learn that missingness as
        # a shortcut for provenance. RSA sizes remain genuine numeric inputs.
        if not attribute.startswith(('keyLength','parameterLength','parameterKind')):
            result['observed.'+attribute]=max(result.get('observed.'+attribute,0),value)
    for origin in ('constant','runtime','unknown'):
        result['materialCount.'+origin]=sum(value for key,value in result.items() if key in {'observed.keyOrigin='+origin,'observed.parameterOrigin='+origin})
    # The classifier screens a fragment for material-origin patterns, not a
    # defect type. Role-specific findings and recommendations remain in the
    # deterministic analyzer. Pool provenance roles to transfer to combinations
    # absent from this small structured training subset.
    result={k:v for k,v in result.items() if not k.startswith(('observed.keyOrigin','observed.parameterOrigin'))}
    return result


def forest_score(values, artifact):
    if artifact.get('projection')=='neutral_observations_v1':
        values=observation_features(values)
    scores = []
    for tree in artifact['trees']:
        node = 0
        while tree['left'][node] != -1:
            name = artifact['features'][tree['feature'][node]]
            node = tree['left'][node] if values.get(name,0.0) <= tree['threshold'][node] else tree['right'][node]
        scores.append(tree['positive'][node])
    return sum(scores)/len(scores)


def predict(source, artifact, *, values=None):
    values = features(source) if values is None else values
    lexical, coverage = score_text(canonical(source),artifact['lexicalModel'])
    if numeric_rsa(values) and artifact.get('rsaNumeric'):
        model=artifact['rsaNumeric']
        z=model['intercept']+model['coefficient']*values['rsaMinLog2']
        return 1/(1+math.exp(-max(-700,min(700,z)))),coverage,'numerical_rsa_logistic'
    use_semantic = has_observations(values)
    return (forest_score(values,artifact) if use_semantic else lexical), coverage, 'numerical_provenance_forest' if use_semantic else 'lexical_fallback'


def numeric_rsa(values):
    return bool(values.get('rsaSizeObserved') and values.get('rsaMinLog2')==values.get('rsaMaxLog2') and not any(k.startswith('init.') for k in values))


def load_model():
    if not MODEL_PATH.is_file():
        return None
    external_path=OUTPUT/'external-cryptoapi.json'
    signature=(MODEL_PATH.stat().st_mtime_ns,MODEL_PATH.stat().st_size,external_path.stat().st_mtime_ns if external_path.is_file() else None)
    return _load_model(str(MODEL_PATH),str(external_path),signature)


@lru_cache(maxsize=1)
def _load_model(model_path,external_file,signature):
    """Reload atomic artifact updates; never cache absence until restart."""
    model_path=Path(model_path)
    raw=model_path.read_bytes()
    model = json.loads(raw)
    if model.get('schemaVersion') != 12:
        raise ValueError('Unsupported enhanced context model')
    external_path=Path(external_file)
    if external_path.is_file():
        external=json.loads(external_path.read_text(encoding='utf-8'))
        if external.get('modelSha256')==hashlib.sha256(raw).hexdigest():
            model['externalEvaluation']={k:external[k] for k in ('benchmark','retained','covered','coverage','metrics')}
    return model


def screen(source):
    artifact = load_model()
    if artifact is None:
        return None
    clean = canonical(source)
    base = {'modelVersion':artifact['version'],'dataset':'CryptoLLM original', 'trainingSamples':artifact['counts']['train'],'validationSamples':artifact['counts']['validation'],'testSamples':artifact['counts']['test'],'semanticTrainingSamples':artifact['semanticTrainingSamples'],'numericTrainingSamples':artifact['numericTrainingSamples'],'threshold':0.5,'scope':'Clasificación aprendida con observaciones numéricas y de procedencia; fallback léxico en fragmentos no resueltos','evaluation':artifact['evaluation']}
    if 'externalEvaluation' in artifact:
        base['externalEvaluation']=artifact['externalEvaluation']
    lexical, coverage = score_text(clean,artifact['lexicalModel'])
    if not in_scope(clean,artifact['lexicalModel'],coverage):
        return {**base,'status':'abstained','reason':'El fragmento no cumple el alcance de APIs, tamaño de contexto o vocabulario evaluado.'}
    score,_,route = predict(source,artifact)
    explanation={'numerical_provenance_forest':'Bosque supervisado sobre procedencia observada.','numerical_rsa_logistic':'Regresión logística supervisada sobre el tamaño RSA observado.','lexical_fallback':'Clasificador léxico de respaldo: no se resolvieron observaciones para los modelos estructurados.'}[route]
    return {**base,'status':'applied','score':round(score,6),'classification':'possible_misuse' if score>=0.5 else 'no_indication','route':route,'vocabularyCoverage':round(coverage,4),'reason':explanation+' Las observaciones son entradas del modelo, no etiquetas generadas por reglas. Puede equivocarse y no certifica seguridad.'}


def load_sources():
    codes = {}
    for name,expected in FILES.items():
        raw = (ROOT/'data/cryptollm-source'/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=expected:
            raise ValueError('Source checksum mismatch')
        for i,line in enumerate(raw.decode('utf-8').splitlines(),1):
            codes[f'{name}:{i}'] = json.loads(line)['code']
    return codes


def export_forest(model,vectorizer):
    trees=[]
    for estimator in model.estimators_:
        t=estimator.tree_
        trees.append({'left':t.children_left.tolist(),'right':t.children_right.tolist(),'feature':t.feature.tolist(),'threshold':t.threshold.tolist(),'positive':[(v[0][1]/sum(v[0])) for v in t.value]})
    return {'features':vectorizer.get_feature_names_out().tolist(),'trees':trees}


def evaluate(artifact,splits,codes,values):
    report,predictions={},[]
    for name in ('validation','test'):
        rows=splits[name]
        scored=[(r,*predict(codes[r['id']],artifact,values=values[r['id']])) for r in rows]
        covered=[(r,s,c,route) for r,s,c,route in scored if in_scope(r['text'],artifact['lexicalModel'],c)]
        report[name]={'allCases':metrics([r['label'] for r,_,_,_ in scored],[int(s>=0.5) for _,s,_,_ in scored]),'covered':metrics([r['label'] for r,_,_,_ in covered],[int(s>=0.5) for _,s,_,_ in covered]),'coverage':len(covered)/len(rows),'abstentions':len(rows)-len(covered),'semanticRouted':sum(route!='lexical_fallback' for _,_,_,route in scored),'numericRouted':sum(route=='numerical_rsa_logistic' for _,_,_,route in scored),'v6SameCases':metrics([r['label'] for r in rows],[int(score_text(r['text'],artifact['lexicalModel'])[0]>=0.5) for r in rows])}
        predictions.extend({'id':r['id'],'split':name,'actual':r['label'],'predicted':int(s>=0.5),'score':s,'route':route} for r,s,_,route in scored)
    return report,predictions


def train():
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.ensemble import ExtraTreesClassifier,RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    import sklearn
    splits={n:[json.loads(s) for s in (BASE_OUTPUT/f'{n}.jsonl').read_text(encoding='utf-8').splitlines()] for n in ('train','validation','test')}
    base=json.loads((BASE_OUTPUT/'model.json').read_text(encoding='utf-8'))
    if split_fingerprint(splits)!=base['manifestHash']:
        raise ValueError('V6 frozen manifest changed')
    codes=load_sources()
    for part in splits.values():
        for row in part:
            if canonical(codes[row['id']])!=row['text']:
                raise ValueError('Source mismatch')
    # Test feature extraction and labels are not used for model selection.
    values={r['id']:features(codes[r['id']]) for n in ('train','validation') for r in splits[n]}
    rsa_train=[r for r in splits['train'] if numeric_rsa(values[r['id']])]
    rsa_validation=[r for r in splits['validation'] if numeric_rsa(values[r['id']])]
    rsa_candidates=[];rsa_winner=None
    for c in (0.25,1.0,4.0):
        numeric=LogisticRegression(C=c,class_weight='balanced',random_state=42,max_iter=1000)
        numeric.fit([[values[r['id']]['rsaMinLog2']] for r in rsa_train],[r['label'] for r in rsa_train])
        metric=metrics([r['label'] for r in rsa_validation],numeric.predict([[values[r['id']]['rsaMinLog2']] for r in rsa_validation]))
        rsa_candidates.append({'C':c,'validation':metric})
        if rsa_winner is None or metric['macroF1']>rsa_winner[0]:
            rsa_winner=(metric['macroF1'],c,numeric)
    _,rsa_c,numeric=rsa_winner
    rsa_artifact={'coefficient':float(numeric.coef_[0,0]),'intercept':float(numeric.intercept_[0]),'C':rsa_c,'trainingSamples':len(rsa_train),'validationSamples':len(rsa_validation)}
    semantic_train=[r for r in splits['train'] if has_observations(values[r['id']]) and not numeric_rsa(values[r['id']])]
    v=DictVectorizer(sparse=True)
    xt=v.fit_transform([observation_features(values[r['id']]) for r in semantic_train])
    xv=v.transform([observation_features(values[r['id']]) for r in splits['validation']])
    y=[r['label'] for r in semantic_train]
    candidates=[];winner=None
    for name,cls in (('extra',ExtraTreesClassifier),('forest',RandomForestClassifier)):
        for leaf in (1,3):
            model=cls(n_estimators=160,max_depth=16,min_samples_leaf=leaf,max_features=1.0,class_weight='balanced',random_state=42,n_jobs=2)
            model.fit(xt,y)
            semantic=model.predict_proba(xv)[:,1]
            scores=[]
            for r,s in zip(splits['validation'],semantic):
                f=values[r['id']]
                if numeric_rsa(f):
                    z=rsa_artifact['intercept']+rsa_artifact['coefficient']*f['rsaMinLog2']
                    scores.append(1/(1+math.exp(-max(-700,min(700,z)))))
                else:
                    scores.append(float(s) if has_observations(f) else score_text(r['text'],base)[0])
            result=metrics([r['label'] for r in splits['validation']],[int(s>=0.5) for s in scores])
            candidates.append({'kind':name,'minLeaf':leaf,'validation':result})
            if winner is None or result['macroF1']>winner[0]:
                winner=(result['macroF1'],name,leaf,model)
    _,name,leaf,model=winner
    forest=export_forest(model,v)
    artifact={'schemaVersion':12,'kind':'context_provenance_forest','projection':'neutral_observations_v1','lexicalModel':base,'rsaNumeric':rsa_artifact,**forest,'counts':base['counts'],'semanticTrainingSamples':len(semantic_train),'numericTrainingSamples':len(rsa_train),'threshold':0.5,'manifestHash':base['manifestHash'],'selectedKind':name,'selectedMinLeaf':leaf}
    parity=max(abs(forest_score(values[r['id']],artifact)-float(s)) for r,s in zip(splits['validation'],model.predict_proba(xv)[:,1]))
    if parity>1e-10:
        raise AssertionError('Portable forest mismatch')
    feature_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),Path(__file__).with_name('semantic_features.py'),Path(__file__).with_name('material_review.py'),Path(__file__).with_name('java_review.py')]}
    artifact['version']='v12-context-'+hashlib.sha256(json.dumps({'manifest':base['manifestHash'],'forest':forest,'rsaNumeric':rsa_artifact,'featureCode':feature_hashes},sort_keys=True).encode()).hexdigest()[:16]
    values.update({r['id']:features(codes[r['id']]) for r in splits['test']})
    evaluation,predictions=evaluate(artifact,splits,codes,values)
    artifact['evaluation']={n:{'metrics':m['covered'],'coverage':m['coverage'],'total':m['allCases']['count']} for n,m in evaluation.items()}
    report={'version':artifact['version'],'counts':base['counts'],'manifestHash':base['manifestHash'],'sourceHashes':FILES,'featureCodeHashes':feature_hashes,'candidates':candidates,'rsaCandidates':rsa_candidates,'selectedKind':name,'selectedMinLeaf':leaf,'sklearnVersion':sklearn.__version__,'portableMaximumError':parity,'evaluation':evaluation,'trainingFacts':{'rsaObserved':len(rsa_train),'provenanceModel':len(semantic_train),'semanticRoutable':sum(has_observations(values[r['id']]) for r in splits['train'])},'limitations':['V6 test reused for regression; not a newly untouched test.','Original binary snippet labels, not per-rule annotations.','Neutral observations use a bounded static analysis; unresolved dataflow falls back to lexical screening.','Small subgroup support, particularly RSA; cannot claim a learned exact policy boundary.','No explicit upstream license: corpus and weights remain local research artifacts.','Previously shown four examples are development regressions, never added to training.']}
    OUTPUT.mkdir(parents=True,exist_ok=True)
    (OUTPUT/'model.json.tmp').write_text(json.dumps(artifact),encoding='utf-8');(OUTPUT/'model.json.tmp').replace(MODEL_PATH)
    (OUTPUT/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    (OUTPUT/'predictions.json').write_text(json.dumps(predictions,indent=2),encoding='utf-8')
    (OUTPUT/'features.jsonl').write_text(''.join(json.dumps({'id':key,'features':val})+'\n' for key,val in values.items()),encoding='utf-8')
    return report


def evaluate_only():
    artifact=json.loads(MODEL_PATH.read_text(encoding='utf-8'))
    splits={n:[json.loads(s) for s in (BASE_OUTPUT/f'{n}.jsonl').read_text(encoding='utf-8').splitlines()] for n in ('train','validation','test')}
    if split_fingerprint(splits)!=artifact['manifestHash']:
        raise ValueError('Frozen manifest mismatch')
    codes=load_sources()
    values={r['id']:features(codes[r['id']]) for p in splits.values() for r in p}
    result,_=evaluate(artifact,splits,codes,values)
    return {'trainingPerformed':False,'evaluation':result}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evaluate-only',action='store_true');args=p.parse_args()
    result=evaluate_only() if args.evaluate_only else train()
    print(json.dumps({k:v for k,v in result.items() if k in ('version','counts','selectedKind','selectedMinLeaf','trainingFacts','evaluation','portableMaximumError','trainingPerformed')},indent=2))
