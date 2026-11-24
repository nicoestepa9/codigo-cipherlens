"""Explain resolved decryption context without interpreting an ML alert as proof."""
import pytest

pytest.importorskip('javalang')

from tls_analyzer.crypto_ml.presentation import context_notes


def source(mode='Cipher.DECRYPT_MODE', setup=''):
    return '''class Demo { public static void main(String[] args) throws Exception {
      KeyGenerator g=KeyGenerator.getInstance("AES"); SecretKey key=g.generateKey();
      byte[] iv=new byte[16];
      '''+setup+'''
      Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");
      c.init('''+mode+''',key,new IvParameterSpec(iv));
    }}'''


def test_fixed_decryption_iv_gets_a_context_explanation():
    notes=context_notes(source())
    assert len(notes)==1
    assert 'DECRYPT_MODE' in notes[0]
    assert 'por sí sola, no demuestra una mala configuración' in notes[0]


@pytest.mark.parametrize('code',[
    source('Cipher.ENCRYPT_MODE'),
    source(setup='new SecureRandom().nextBytes(iv);'),
    source('Cipher.ENCRYPT_MODE',setup='// DECRYPT_MODE is only a comment'),
    'not valid Java',
])
def test_no_decryption_note_without_resolved_constant_decryption_parameters(code):
    assert context_notes(code)==[]


def test_api_preserves_the_explanation_and_does_not_invent_an_iv_finding(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from tls_analyzer.api.routers.crypto_ml import router
    from tls_analyzer.api.deps import AuthContext,require_auth
    from tls_analyzer.crypto_ml import review
    monkeypatch.setattr(review,'screen',lambda s:{'status':'applied','score':1.0,'classification':'possible_misuse'})
    app=FastAPI();app.include_router(router)
    app.dependency_overrides[require_auth]=lambda:AuthContext(user_id='test',role='user',actor_type='user',organization_id=1)
    with TestClient(app) as client:
        result=client.post('/api/crypto-ml/analyze',json={'filename':'Demo.java','source':source()})
    assert result.status_code==200
    body=result.json()
    assert body['findings']==[]
    assert body['status']=='needs_review'
    assert body['contextNotes']==context_notes(source())
