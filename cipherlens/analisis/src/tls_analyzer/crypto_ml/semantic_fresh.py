"""Additional authored functional regression cases.

Related variants are not independent projects. Do not tune on this report.
"""
from __future__ import annotations

import hashlib
import json
from .cryptollm import ROOT,metrics


def cases():
    rows=[]
    def add(identifier,family,label,body,extra=''):
        code='''import java.security.*;import javax.crypto.*;import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
public class FreshReview {
'''+extra+'''
public static void main(String[] input) throws Exception {
'''+body+'''
}}
'''
        rows.append({'id':identifier,'family':family,'label':label,'source':code})
    for bits in (768,1280,1792,2047,2048,2304,3072,8192):
        add('rsa_hex_'+str(bits),'rsa-numeric-boundaries',int(bits<2048),f'KeyPairGenerator pairFactory=KeyPairGenerator.getInstance("RSA");int requested=0x{bits:x};int chosen=requested;pairFactory.initialize(chosen);System.out.println(pairFactory.getAlgorithm());')
    for mode,length in (('CBC',16),('GCM',12)):
        for constant in (True,False):
            for alias in (True,False):
                init=f'byte[] first=new byte[{length}];byte[] selected=first;'
                if not constant:
                    init+='SecureRandom entropy=new SecureRandom();entropy.nextBytes('+('first' if alias else 'selected')+');'
                else:
                    init+='byte[] unrelated=new byte[32];new SecureRandom().nextBytes(unrelated);'
                key='KeyGenerator factory=KeyGenerator.getInstance("AES");factory.init(128);SecretKey secret=factory.generateKey();'
                transformation='AES/'+mode+('/NoPadding' if mode=='GCM' else '/PKCS5Padding')
                params='new GCMParameterSpec(128,selected)' if mode=='GCM' else 'new IvParameterSpec(selected)'
                add(f'{mode}_{constant}_{alias}','iv-'+mode,int(constant),key+init+f'Cipher operation=Cipher.getInstance("{transformation}");operation.init(Cipher.ENCRYPT_MODE,secret,{params});System.out.println(operation.getAlgorithm());')
    for constant in (True,False):
        for form in range(4):
            if constant:
                setup=('byte[] bytes="fedcba9876543210".getBytes(StandardCharsets.UTF_8);' if form%2 else 'byte[] bytes=new byte[16];')+'byte[] alias=bytes;SecretKey secret=new SecretKeySpec(alias,"AES");'
            else:
                setup=('byte[] bytes=new byte[16];byte[] alias=bytes;SecureRandom random=new SecureRandom();random.nextBytes(alias);SecretKey secret=new SecretKeySpec(bytes,"AES");' if form%2 else 'KeyGenerator factory=KeyGenerator.getInstance("AES");factory.init(256);SecretKey secret=factory.generateKey();')
            setup+='byte[] nonce=new byte[12];new SecureRandom().nextBytes(nonce);Cipher operation=Cipher.getInstance("AES/GCM/NoPadding");operation.init(Cipher.ENCRYPT_MODE,secret,new GCMParameterSpec(128,nonce));'
            # Vary trailing unrelated code; semantics unchanged and grouped.
            add(f'key_{constant}_{form}','key-material',int(constant),setup+f'byte[] message=new byte[{form+3}];operation.doFinal(message);')
    unique={}
    for row in rows:
        key=hashlib.sha256(row['source'].encode()).hexdigest()
        if key in unique and unique[key]['label']!=row['label']:
            raise ValueError('Conflicting authored labels')
        unique.setdefault(key,row)
    return list(unique.values())


def evaluate():
    from .enhanced_context import OUTPUT,MODEL_PATH,screen
    from .context_model import screen as v6
    definitions=cases();output=OUTPUT/'fresh-functional';output.mkdir(parents=True,exist_ok=True)
    (output/'cases.json').write_text(json.dumps(definitions,indent=2),encoding='utf-8')
    results=[]
    for row in definitions:
        current,old=screen(row['source']),v6(row['source'])
        if current is None:
            raise ValueError('Missing enhanced model')
        results.append({'id':row['id'],'family':row['family'],'actual':row['label'],'score':current.get('score'),'route':current.get('route'),'prediction':int(current['score']>=0.5) if current['status']=='applied' else None,'v6Prediction':int(old['score']>=0.5) if old['status']=='applied' else None})
    covered=[r for r in results if r['prediction'] is not None]
    common=[r for r in covered if r['v6Prediction'] is not None]
    report={'modelVersion':current['modelVersion'],'modelSha256':hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest(),'definitionsSha256':hashlib.sha256(json.dumps(definitions,sort_keys=True).encode()).hexdigest(),'trainingPerformed':False,'thresholdChanged':False,'excludedExactDuplicates':2,'total':len(results),'covered':len(covered),'coverage':len(covered)/len(results),'metrics':metrics([r['actual'] for r in covered],[r['prediction'] for r in covered]),'v6SameCases':metrics([r['actual'] for r in common],[r['v6Prediction'] for r in common]),'results':results,'limitations':['Project-authored functional examples, not independent real projects.','Variants deliberately share four semantic families.','Declared before V10, then inspected during V11 feature design; development regression only.','No cases are fitted or used to select thresholds; they influenced architecture, so are not an untouched test.','Two exact duplicate source definitions removed after initial run; initial report retained in V10 artifacts.']}
    (output/'report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report


if __name__=='__main__':
    print(json.dumps({k:v for k,v in evaluate().items() if k!='results'},indent=2))
