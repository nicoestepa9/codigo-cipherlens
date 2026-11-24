"""Neutral provenance features, independent learned predictions, and routing."""
import copy
import json

import pytest

pytest.importorskip('javalang')

from tls_analyzer.crypto_ml.semantic_features import features
from tls_analyzer.crypto_ml.enhanced_context import forest_score, has_observations


def source(material):
    return '''class Demo { void f() throws Exception {
      KeyGenerator g=KeyGenerator.getInstance("AES");
      SecretKey key=g.generateKey();
      byte[] iv=new byte[16];
      '''+material+'''
      Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      c.init(Cipher.ENCRYPT_MODE,key,new IvParameterSpec(iv));
    }}'''


def test_features_link_randomness_to_the_actual_iv_not_an_unrelated_array():
    actual=features(source('new SecureRandom().nextBytes(iv);'))
    unrelated=features(source('byte[] other=new byte[16]; new SecureRandom().nextBytes(other);'))
    assert actual['init.AES/CBC/PKCS5PADDING.parameterOrigin=runtime']==1
    assert unrelated['init.AES/CBC/PKCS5PADDING.parameterOrigin=constant']==1
    assert 'finding' not in json.dumps(actual).lower()


def test_numeric_observations_are_not_policy_flags():
    import math
    text='class D { void f() throws Exception { KeyPairGenerator g=KeyPairGenerator.getInstance("RSA"); int n=1280; g.initialize(n); }}'
    facts=features(text)
    assert facts['rsaMinLog2']==math.log2(1280)
    assert not any('weak' in k.lower() or 'minimum' in k.lower() or 'violation' in k.lower() for k in facts)


def test_security_findings_are_never_used_as_model_features(monkeypatch):
    from tls_analyzer.crypto_ml import java_review,material_review
    baseline=features(source(''))
    real_java=java_review.inspect_java
    real_material=material_review.inspect_materials
    def noisy_java(*args,**kwargs):
        result=real_java(*args,**kwargs);result['findings']=[{'id':'INVENTED','severity':'critical'}];return result
    def noisy_material(*args,**kwargs):
        result=real_material(*args,**kwargs);result['findings']=[{'id':'INVENTED','severity':'critical'}];return result
    monkeypatch.setattr(java_review,'inspect_java',noisy_java)
    monkeypatch.setattr(material_review,'inspect_materials',noisy_material)
    assert features(source(''))==baseline


def test_foreign_secret_and_identifier_values_are_not_features():
    text=source('').replace('key=g.generateKey();','key=new SecretKeySpec("PRIVATE_KEY_12345".getBytes(),"AES");')
    result=features(text)
    assert 'PRIVATE_KEY_12345' not in json.dumps(result)
    assert 'key' not in result and 'iv' not in result


def test_portable_forest_matches_sklearn_for_unseen_numeric_values():
    pytest.importorskip('sklearn')
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction import DictVectorizer
    from tls_analyzer.crypto_ml.enhanced_context import export_forest
    values=[{'size':x,'mode':float(x%2)} for x in range(20)]
    v=DictVectorizer();x=v.fit_transform(values)
    m=RandomForestClassifier(n_estimators=8,max_depth=4,random_state=42).fit(x,[int(x<10) for x in range(20)])
    artifact=export_forest(m,v)
    for row in values+[{'size':9.5},{'size':30},{}]:
        assert forest_score(row,artifact)==pytest.approx(m.predict_proba(v.transform([row]))[0,1],abs=1e-12)


def test_routing_requires_observed_values_not_a_security_verdict():
    assert not has_observations({'parsed':1,'count.Cipher':2})
    assert has_observations({'rsaSizeObserved':1,'rsaMinLog2':12})
    assert has_observations({'init.AES/CBC/PKCS5PADDING.parameterOrigin=runtime':1})
    assert has_observations({'init.AES/CBC/PKCS5PADDING.parameterOrigin=constant':1})


def test_projection_ignores_file_boilerplate_and_missing_length_shortcut():
    from tls_analyzer.crypto_ml.enhanced_context import observation_features
    f=features(source(''))
    changed=dict(f, tokensLog=1000, **{'count.doFinal':10})
    changed.pop('init.AES/CBC/PKCS5PADDING.parameterLengthLog',None)
    assert observation_features(f)==observation_features(changed)
    projected=observation_features(f)
    assert projected['materialCount.constant']==1
    assert not any(k.startswith(('observed.keyOrigin','observed.parameterOrigin')) for k in projected)
    assert not any(k.startswith(('algorithm=','mode=','padding=')) for k in projected)


def test_model_appearing_or_changing_is_loaded_without_restarting(tmp_path,monkeypatch):
    from tls_analyzer.crypto_ml import enhanced_context as module
    path=tmp_path/'model.json'
    monkeypatch.setattr(module,'MODEL_PATH',path)
    monkeypatch.setattr(module,'OUTPUT',tmp_path)
    assert module.load_model() is None
    path.write_text(json.dumps({'schemaVersion':12,'version':'first'}),encoding='utf-8')
    assert module.load_model()['version']=='first'
    replacement=tmp_path/'replacement.json'
    replacement.write_text(json.dumps({'schemaVersion':12,'version':'second-longer-version'}),encoding='utf-8')
    replacement.replace(path)
    assert module.load_model()['version']=='second-longer-version'


def test_role_swaps_preserve_pooled_origin_inputs():
    from tls_analyzer.crypto_ml.enhanced_context import observation_features
    a={'init.AES/CBC/PKCS5PADDING.operation=1':1,'init.AES/CBC/PKCS5PADDING.keyOrigin=runtime':1,'init.AES/CBC/PKCS5PADDING.parameterOrigin=constant':1}
    b={'init.AES/GCM/NOPADDING.operation=1':1,'init.AES/GCM/NOPADDING.keyOrigin=constant':1,'init.AES/GCM/NOPADDING.parameterOrigin=runtime':1}
    assert observation_features(a)==observation_features(b)
