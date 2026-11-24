"""Short explanations from resolved observations, never inferred ML defects."""
from __future__ import annotations


def context_notes(source: str) -> list[str]:
    import javalang
    from .material_review import inspect_materials

    try:
        unit = javalang.parse.parse(source)
    except (javalang.parser.JavaSyntaxError, javalang.tokenizer.LexerError, TypeError, RecursionError):
        return []
    observations = inspect_materials(unit, source)['observations']
    if any(row['operation'] == 2 and row['parameterOrigin'] == 'constant'
           and row['parameterKind'] in {'IvParameterSpec', 'GCMParameterSpec'}
           for row in observations):
        return ["El IV o nonce fijo se usa para descifrar (DECRYPT_MODE). Esa condición, por sí sola, no demuestra una mala configuración; el control de IV/nonce constante se aplica durante el cifrado."]
    return []
