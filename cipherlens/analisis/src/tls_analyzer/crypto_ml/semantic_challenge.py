"""Predeclared authored transfer checks; no training and no threshold changes.

Related variants share a family. Counts are functional examples, not independent
projects. All results, including failures and unknown ground truth, are retained.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

from .cryptollm import ROOT,metrics


def cases():
    result=[]
    def add(identifier,family,expected,body,extra=''):
        source='''import javax.crypto.*; import javax.crypto.spec.*;
import java.security.*; import java.nio.charset.StandardCharsets;
public class FreshCase {
'''+extra+'''
 public static void main(String[] args) throws Exception {
'''+body+'''
 }
}
'''
        result.append({'id':identifier,'family':family,'expected':expected,'source':source})
    for size in (512,1024,1280,1792,2048,2304,3072,4096):
        add('rsa_'+str(size),'rsa-size',int(size<2048),f'KeyPairGenerator gen=KeyPairGenerator.getInstance("RSA"); int bits={size}; gen.initialize(bits,new SecureRandom()); KeyPair pair=gen.generateKeyPair(); System.out.println(pair.getPrivate().getFormat());')
    key='KeyGenerator gen=KeyGenerator.getInstance("AES"); gen.init(256); SecretKey key=gen.generateKey();'
    for mode,length in (('CBC',16),('GCM',12)):
        for name,setup,expected in (
            ('zero',f'byte[] nonce=new byte[{length}];',1),
            ('literal','byte[] nonce=new byte[]{'+','.join(str(i) for i in range(length))+'};',1),
            ('alias_zero',f'byte[] original=new byte[{length}]; byte[] nonce=original;',1),
            ('text','byte[] nonce="'+('x'*length)+'".getBytes(StandardCharsets.UTF_8);',1),
            ('random_direct',f'byte[] nonce=new byte[{length}];new SecureRandom().nextBytes(nonce);',0),
            ('random_alias',f'byte[] original=new byte[{length}];byte[] nonce=original;new SecureRandom().nextBytes(original);',0),
            ('generate_seed',f'SecureRandom rng=new SecureRandom();byte[] nonce=rng.generateSeed({length});',0),
            ('random_variable',f'byte[] nonce=new byte[{length}];SecureRandom rng=new SecureRandom();rng.nextBytes(nonce);',0),
        ):
            transform='AES/'+mode+('/NoPadding' if mode=='GCM' else '/PKCS5Padding')
            param='new GCMParameterSpec(128,nonce)' if mode=='GCM' else 'new IvParameterSpec(nonce)'
            add(mode.lower()+'_'+name,'iv-'+mode.lower(),expected,key+setup+f'Cipher enc=Cipher.getInstance("{transform}");enc.init(Cipher.ENCRYPT_MODE,key,{param});enc.doFinal(new byte[]{{2,3,5,7}});')
    for name,setup,expected in (
        ('literal','SecretKey key=new SecretKeySpec("0123456789abcdef".getBytes(StandardCharsets.UTF_8),"AES");',1),
        ('zero_array','byte[] raw=new byte[16];SecretKey key=new SecretKeySpec(raw,"AES");',1),
        ('array_alias','byte[] raw=new byte[16];byte[] alias=raw;SecretKey key=new SecretKeySpec(alias,"AES");',1),
        ('literal_array','byte[] raw=new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};SecretKey key=new SecretKeySpec(raw,"AES");',1),
        ('generator',key,0),
        ('random_array','byte[] raw=new byte[16];new SecureRandom().nextBytes(raw);SecretKey key=new SecretKeySpec(raw,"AES");',0),
        ('random_alias','byte[] raw=new byte[16];byte[] alias=raw;new SecureRandom().nextBytes(alias);SecretKey key=new SecretKeySpec(raw,"AES");',0),
        ('seed_array','SecureRandom rng=new SecureRandom();byte[] raw=rng.generateSeed(16);SecretKey key=new SecretKeySpec(raw,"AES");',0),
    ):
        add('key_'+name,'key-origin',expected,setup+'byte[] nonce=new byte[12];new SecureRandom().nextBytes(nonce);Cipher enc=Cipher.getInstance("AES/GCM/NoPadding");enc.init(Cipher.ENCRYPT_MODE,key,new GCMParameterSpec(128,nonce));enc.doFinal(new byte[]{1,4,9});')
    for transform,expected in (('DES',1),('DES/CBC/PKCS5Padding',1),('AES/ECB/PKCS5Padding',1),('RSA/ECB/NoPadding',1),('AES/GCM/NoPadding',0),('AES/CBC/PKCS5Padding',0),('RSA/ECB/OAEPWithSHA-256AndMGF1Padding',0),('AES/CTR/NoPadding',0)):
        add('transform_'+str(len(result)),'literal-transformation',expected,f'Cipher engine=Cipher.getInstance("{transform}");System.out.println(engine.getAlgorithm());')
    for i,body in enumerate((
        'KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(Integer.parseInt(args[0]));',
        'KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");int size=args.length>1?1024:4096;g.initialize(size);',
        key+'byte[] iv=args[0].getBytes(StandardCharsets.UTF_8);Cipher c=Cipher.getInstance("AES/CBC/PKCS5Padding");c.init(Cipher.ENCRYPT_MODE,key,new IvParameterSpec(iv));',
        'SecretKey key=new SecretKeySpec(args[0].getBytes(StandardCharsets.UTF_8),"AES");Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,key);',
    )):
        add('unknown_'+str(i),'unknown-input',None,body)
    return result


def evaluate(output=None):
    from .context_model import screen as legacy_screen
    from .enhanced_context import screen as current_screen,MODEL_PATH,OUTPUT
    output=output or OUTPUT/'challenge'
    output.mkdir(parents=True,exist_ok=True)
    definitions=cases()
    (output/'cases.json').write_text(json.dumps(definitions,indent=2),encoding='utf-8')
    results=[]
    for row in definitions:
        old,new=legacy_screen(row['source']),current_screen(row['source'])
        if new is None:
            raise ValueError('Train V7 before evaluating')
        results.append({'id':row['id'],'family':row['family'],'actual':row['expected'],'v6Status':old['status'],'currentStatus':new['status'],'v6Score':old.get('score'),'currentScore':new.get('score'),'route':new.get('route'),'v6Prediction':int(old['score']>=0.5) if old['status']=='applied' else None,'currentPrediction':int(new['score']>=0.5) if new['status']=='applied' else None})
    report={'modelVersion':new['modelVersion'],'modelSha256':hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest(),'definitionsSha256':hashlib.sha256(json.dumps(definitions,sort_keys=True).encode()).hexdigest(),'trainingPerformed':False,'thresholdsChanged':False,'caseCount':len(results),'knownGroundTruth':sum(r['actual'] is not None for r in results),'unknownGroundTruth':sum(r['actual'] is None for r in results),'results':results,'metrics':{},'limitations':['Project-authored functional development regression cases, not an independent corpus or project-level validation.','Related variants share families; sample count does not imply independence.','Previous four user examples are excluded and remain development regressions.','Previously observed V6 test/benchmarks are never described as untouched.','This challenge was inspected while developing V8/V9; it is not an untouched holdout.']}
    for version in ('v6','current'):
        part=[r for r in results if r['actual'] is not None and r[version+'Prediction'] is not None]
        report['metrics'][version]={'covered':len(part),'coverage':len(part)/report['knownGroundTruth'],'metrics':metrics([r['actual'] for r in part],[r[version+'Prediction'] for r in part])}
    (output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


if __name__=='__main__':
    print(json.dumps({k:v for k,v in evaluate().items() if k!='results'},indent=2))
