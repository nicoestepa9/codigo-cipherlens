"""Prevent source or partition leakage in the combined contextual experiment."""
import copy
import json

import pytest

from tls_analyzer.crypto_ml.combined_owasp import assert_disjoint


def partitions():
    return {name:[{'id':name,'hash':'hash-'+name,'group':'group-'+name}]
            for name in ('train','validation','test')}


def test_distinct_sources_and_groups_preserve_frozen_partitions():
    splits=partitions()
    before=copy.deepcopy(splits)
    assert_disjoint(splits)
    assert splits==before


@pytest.mark.parametrize('field',['id','hash','group'])
def test_cross_partition_matches_are_rejected(field):
    splits=partitions()
    splits['test'][0][field]=splits['train'][0][field]
    with pytest.raises(ValueError,match='Cross-partition leakage'):
        assert_disjoint(splits)


def test_frozen_evaluation_cannot_fit_and_rejects_changed_labels(tmp_path,monkeypatch):
    sklearn=pytest.importorskip('sklearn.linear_model')
    from tls_analyzer.crypto_ml import combined_owasp as module
    from tls_analyzer.crypto_ml.cryptollm import split_fingerprint
    from tls_analyzer.crypto_ml.context_model import canonical
    from tls_analyzer.crypto_ml.experiment import digest
    splits={};codes={}
    for name in ('train','validation','test'):
        splits[name]=[]
        for origin in ('CryptoLLM','OWASP'):
            for label in (0,1):
                identifier=f'{name}-{origin}-{label}'
                code='Cipher '+str(len(codes))
                text=canonical(code)
                codes[identifier]=code
                splits[name].append({'id':identifier,'hash':digest(text),'group':identifier,'source':origin,'label':label,'text':text})
        (tmp_path/f'{name}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in splits[name]),encoding='utf-8')
    artifact={'combinedManifestHash':split_fingerprint(splits),'lexicalModel':{'vocabulary':{'Cipher':0},'idf':[1.0],'coefficients':[1.0],'intercept':0,'maxTokens':2000,'minVocabularyCoverage':0}}
    (tmp_path/'model.json').write_text(json.dumps(artifact),encoding='utf-8')
    monkeypatch.setattr(module,'OUTPUT',tmp_path)
    monkeypatch.setattr(module,'load_inputs',lambda _:codes)
    monkeypatch.setattr(module,'features',lambda _: {})
    def forbidden(*args,**kwargs):
        pytest.fail('Evaluation must not fit')
    monkeypatch.setattr(sklearn.LogisticRegression,'fit',forbidden)
    result=module.evaluate_only()
    assert result['trainingPerformed'] is False
    assert result['test']['OWASP']['total']==2
    assert result['test']['CryptoLLM']['total']==2
    splits['test'][0]['label']=1-splits['test'][0]['label']
    (tmp_path/'test.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in splits['test']),encoding='utf-8')
    with pytest.raises(ValueError,match='manifest mismatch'):
        module.evaluate_only()
