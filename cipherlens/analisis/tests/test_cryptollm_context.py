"""Isolation, portable inference parity, and honest hybrid integration."""
import json

import pytest

from tls_analyzer.crypto_ml import context_model as cm


def test_canonical_preserves_crypto_but_removes_comments_names_and_secrets():
    a = 'class Foo { void f(){ /* Cipher.getInstance("DES") */ SecretKeySpec key = new SecretKeySpec("TOP_SECRET_123".getBytes(), "AES"); }}'
    b = 'class Bar { void g(){ SecretKeySpec other = new SecretKeySpec("OTHER_SECRET_456".getBytes(), "AES"); }}'
    assert cm.canonical(a) == cm.canonical(b)
    assert 'TOP_SECRET' not in cm.canonical(a)
    assert 'DES' not in cm.canonical(a)
    assert 'SecretKeySpec' in cm.canonical(a)
    assert cm.canonical('Cipher.getInstance("AES/GCM/NoPadding")') != cm.canonical('Cipher.getInstance("DES/CBC/PKCS5Padding")')
    assert cm.canonical('Cipher.getInstance("AES/GCM/NoPadding")', skeleton=True) == cm.canonical('Cipher.getInstance("DES/CBC/PKCS5Padding")', skeleton=True)


def test_portable_scores_match_sklearn_with_single_digits_repeated_tokens_and_oov():
    pytest.importorskip('sklearn')
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    texts = ['Cipher init 1 1 1 CRYPTO_AES', 'Cipher init 2 CRYPTO_DES', 'SecretKeySpec getBytes STRING', 'SecureRandom nextBytes ID']
    v = TfidfVectorizer(lowercase=False, token_pattern=r'(?u)\b\w+\b', ngram_range=(1,3), sublinear_tf=True)
    x = v.fit_transform(texts)
    model = LogisticRegression(random_state=42).fit(x,[0,1,1,0])
    artifact = {'vocabulary': v.vocabulary_, 'idf':v.idf_, 'coefficients':model.coef_[0], 'intercept':model.intercept_[0]}
    for text in texts+['unknown_word unseen 1', '']:
        assert cm.score_text(text,artifact)[0] == pytest.approx(model.predict_proba(v.transform([text]))[0,1],abs=1e-12)


def test_grouped_partition_has_no_clone_leakage():
    pytest.importorskip('sklearn')
    from tls_analyzer.crypto_ml.cryptollm import partition
    rows = [{'id':str(i), 'label':i%2, 'group':str(i//2)} for i in range(160)]
    splits = partition(rows)
    assert sum(map(len,splits.values())) == len(rows)
    assert not ({r['group'] for r in splits['train']} & {r['group'] for r in splits['test']})
    assert not ({r['group'] for r in splits['validation']} & {r['group'] for r in splits['test']})


def test_missing_model_is_explicit_and_not_a_positive_prediction(monkeypatch):
    monkeypatch.setattr(cm,'load_context_model',lambda:None)
    assert cm.screen('Cipher.getInstance("DES");')['status'] == 'unavailable'


def test_no_crypto_and_oversized_context_abstain(monkeypatch):
    artifact = {'version':'test','counts':{'train':1,'validation':1,'test':1},'threshold':0.5,'maxTokens':5,'evaluation':{}}
    monkeypatch.setattr(cm,'load_context_model',lambda:artifact)
    assert cm.screen('class Example {}')['status'] == 'abstained'
    assert cm.screen('Cipher ' + 'other '*20)['status'] == 'abstained'


def test_context_prediction_does_not_invent_a_deterministic_finding(monkeypatch):
    pytest.importorskip('javalang')
    from tls_analyzer.crypto_ml import review
    monkeypatch.setattr(review,'screen',lambda source:{'status':'applied','score':0.9,'classification':'possible_misuse','modelVersion':'context-test'})
    result = review.analyze('class Example { void f() throws Exception { Cipher.getInstance("AES/GCM/NoPadding"); }}')
    assert result['status'] == 'needs_review'
    assert result['findings'] == []
    assert result['ml']['context']['score'] == 0.9
    assert result['ml']['predictions'][0]['score'] == 0


def test_evaluate_only_never_calls_fit_and_verifies_frozen_manifest(tmp_path, monkeypatch):
    pytest.importorskip('sklearn')
    from sklearn.linear_model import LogisticRegression
    from tls_analyzer.crypto_ml import cryptollm as exp
    from tls_analyzer.crypto_ml.experiment import digest
    monkeypatch.setattr(exp,'OUTPUT',tmp_path)
    monkeypatch.setattr(LogisticRegression,'fit',lambda *args,**kwargs:pytest.fail('Evaluation must not train'))
    rows = [{'id':'a','label':0,'text':'Cipher ID', 'hash':digest('Cipher ID'),'group':'a'}, {'id':'b','label':1,'text':'Cipher STRING','hash':digest('Cipher STRING'),'group':'b'}]
    for name in ('train','validation','test'):
        (tmp_path/f'{name}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf-8')
    artifact = {'vocabulary':{'Cipher':0},'idf':[1],'coefficients':[0.1],'intercept':0,'threshold':0.5,'maxTokens':2000,'minVocabularyCoverage':0.1,'majorityClass':1,'manifestHash':exp.split_fingerprint({n:rows for n in ('train','validation','test')})}
    (tmp_path/'model.json').write_text(json.dumps(artifact),encoding='utf-8')
    assert exp.evaluate_only()['trainingPerformed'] is False
    rows[0]['text'] = 'tampered'
    (tmp_path/'test.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows),encoding='utf-8')
    with pytest.raises(ValueError,match='mismatch'):
        exp.evaluate_only()
