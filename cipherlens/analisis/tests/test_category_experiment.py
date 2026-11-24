"""Category labels must stay scoped and missing support must abstain."""
import json

import pytest

from tls_analyzer.crypto_ml import category_experiment as module


def test_projection_does_not_use_other_category_or_rule_verdict():
    values = {'literal.DES/CBC/PKCS5PADDING':1,'init.AES.keyOrigin=constant':1,
              'init.AES.parameterOrigin=runtime':1,'finding.JAVA-EMBEDDED-KEY':1}
    assert module.category_features(values,'algorithm_mode') == {'literal.DES/CBC/PKCS5PADDING':1}
    assert module.category_features(values,'predictable_key') == {'keyOrigin=constant':1}
    assert module.category_features(values,'constant_iv') == {'parameterOrigin=runtime':1}


def test_conflicting_canonical_labels_are_excluded_not_relabelled():
    rows = [{'id':'a','hash':'same','label':0},{'id':'b','hash':'same','label':1},
            {'id':'c','hash':'unique','label':1}]
    kept, excluded = module.deduplicate(rows)
    assert kept == [rows[2]]
    assert {r['id'] for r in excluded} == {'a','b'}


def test_unknown_algorithm_abstains_and_does_not_count_as_true_negative():
    artifact = {'category':'algorithm_mode','features':['literal.DES']}
    result = module.evaluate([{'id':'x','label':0}], {'x':{'literal.UNKNOWN':1}},artifact)
    assert result['covered'] == 0
    assert result['metrics'] is None
    assert module.score({'literal.DES':1,'literal.UNKNOWN':1},artifact)['status'] == 'abstained'


def test_frozen_category_labels_are_verified_without_fitting(tmp_path,monkeypatch):
    from tls_analyzer.crypto_ml.cryptollm import split_fingerprint
    parts={n:[{'id':n,'hash':n,'group':n,'label':0}] for n in ('train','validation','test')}
    artifact={'manifestHash':split_fingerprint(parts)}
    (tmp_path/'algorithm_mode').mkdir()
    (tmp_path/'models.json').write_text(json.dumps({'algorithm_mode':artifact}),encoding='utf-8')
    parts['test'][0]['label']=1
    for name, rows in parts.items():
        (tmp_path/'algorithm_mode'/f'{name}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf-8')
    monkeypatch.setattr(module,'OUTPUT',tmp_path)
    monkeypatch.setattr(module,'prepare',lambda: ({},{},{}))
    with pytest.raises(ValueError,match='Frozen category manifest changed'):
        module.evaluate_only()
