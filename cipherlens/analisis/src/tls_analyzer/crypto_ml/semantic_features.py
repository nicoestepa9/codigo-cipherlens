"""Neutral API observations for supervised learning, never security verdicts.

Numbers, algorithm names and material provenance are inputs. No policy boundary,
finding ID, severity, deterministic verdict or recommendation enters a model.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .context_model import canonical, tokens


def features(source: str) -> dict:
    import javalang
    from javalang import tree as t
    from .material_review import inspect_materials
    from .java_review import inspect_java

    clean = canonical(source)
    counts = Counter(tokens(clean))
    result = {'tokensLog': math.log1p(sum(counts.values()))}
    # API names only; no arbitrary identifiers or secret literals in features.
    for name in ('Cipher','KeyGenerator','KeyPairGenerator','SecretKeySpec','IvParameterSpec','GCMParameterSpec','SecureRandom','nextBytes','generateKey','generateKeyPair','getBytes','doFinal','init','initialize','if','for','while','return'):
        result['count.'+name] = float(min(counts[name],20))
    for match in re.finditer(r'CRYPTO_([A-Z0-9_/+.-]+)',clean):
        result['literal.'+match[1]] = 1.0
    # Corpus slices are often members/statements rather than compilation units.
    unit, parsed_source = None, source
    for candidate in (source, 'class Slice {\n'+source+'\n}', 'class Slice { void slice() throws Exception {\n'+source+'\n}}'):
        try:
            unit = javalang.parse.parse(candidate)
            parsed_source = candidate
            break
        except (javalang.parser.JavaSyntaxError,javalang.tokenizer.LexerError,TypeError,RecursionError):
            continue
    result['parsed'] = float(unit is not None)
    if unit is None:
        return result
    observed = inspect_materials(unit,parsed_source)['observations']
    for row in observed:
        algorithm = str(row['algorithm']).upper()
        for key in ('operation','keyOrigin','parameterKind','parameterOrigin'):
            feature = f'init.{algorithm}.{key}={row[key]}'
            result[feature] = result.get(feature,0)+1.0
        for key in ('keyLength','parameterLength'):
            if row[key] is not None and row[key] >= 0:
                result[f'init.{algorithm}.{key}Log'] = math.log1p(row[key])
    # Read observations only. Findings from the inspector are deliberately ignored.
    facts = inspect_java(parsed_source)['facts']
    sizes = [r['value'] for r in facts if r['kind']=='rsa_bits']
    if sizes:
        result['rsaSizeObserved'] = 1.0
        result['rsaMinLog2'] = math.log2(min(sizes))
        result['rsaMaxLog2'] = math.log2(max(sizes))
    return result
