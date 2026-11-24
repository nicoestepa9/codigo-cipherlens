"""Contract checks for portable structured inference and frozen evaluation."""
import json

import pytest

from tls_analyzer.crypto_ml import structured_owasp as module


def test_portable_forest_matches_sklearn():
    from sklearn.ensemble import ExtraTreesClassifier
    from sklearn.feature_extraction import DictVectorizer
    from tls_analyzer.crypto_ml.enhanced_context import export_forest, forest_score
    rows = [{'literal.AES/GCM/NOPADDING': 1}, {'literal.AES/ECB/PKCS5PADDING': 1},
            {'init.AES.keyOrigin=constant': 1}, {'init.AES.keyOrigin=runtime': 1}]
    vectorizer = DictVectorizer()
    model = ExtraTreesClassifier(n_estimators=11, random_state=42).fit(vectorizer.fit_transform(rows), [0, 1, 1, 0])
    artifact = export_forest(model, vectorizer)
    unseen = rows + [{'literal.OTHER': 1}, {}, {**rows[0], **rows[2]}]
    for row, expected in zip(unseen, model.predict_proba(vectorizer.transform(unseen))[:, 1]):
        assert forest_score(row, artifact) == pytest.approx(expected, abs=1e-12)


def test_routing_uses_observations_without_security_findings(monkeypatch):
    monkeypatch.setattr(module, 'baseline_predict', lambda *a, **k: (.2, .8, 'fallback'))
    monkeypatch.setattr(module, 'forest_score', lambda *a: .9)
    artifact = {'baseline': {}}
    assert module.predict('', artifact, values={'literal.DES': 1}) == (.9, .8, 'combined_structured_forest')
    assert module.predict('', artifact, values={'rsaSizeObserved': 1})[0] == .9
    assert module.predict('', artifact, values={'finding.AES_ECB': 1}) == (.2, .8, 'fallback')
    artifact['ensembleWeight'] = .25
    assert module.predict('', artifact, values={'literal.DES': 1})[0] == pytest.approx(.375)


def test_evaluation_rejects_changed_labels_before_source_loading(tmp_path, monkeypatch):
    from tls_analyzer.crypto_ml.cryptollm import split_fingerprint
    splits = {n: [{'id': n, 'hash': n, 'group': n, 'label': 0}] for n in ('train', 'validation', 'test')}
    (tmp_path/'model.json').write_text(json.dumps({'combinedManifestHash': split_fingerprint(splits)}), encoding='utf-8')
    splits['test'][0]['label'] = 1
    for name, rows in splits.items():
        (tmp_path/f'{name}.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows), encoding='utf-8')
    monkeypatch.setattr(module, 'OUTPUT', tmp_path)
    monkeypatch.setattr(module.combined, 'load_inputs', lambda _: pytest.fail('Must reject before loading source'))
    with pytest.raises(ValueError, match='manifest mismatch'):
        module.evaluate_only()
