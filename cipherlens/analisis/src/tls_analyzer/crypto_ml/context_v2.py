"""Bounded lexical crypto contexts; observations are not vulnerability verdicts.

No Java execution, constant evaluation, dataflow or control-flow resolution.
Source positions are preserved for observed calls, not inferred defects.
"""
from __future__ import annotations

import re
from collections import Counter

from .experiment import TOKEN, normalize

APIS = frozenset({"Cipher", "KeyGenerator", "KeyPairGenerator"})
CALLS = frozenset({"getInstance", "initialize", "init"})
IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*\Z")


def extract_context(source: str) -> dict:
    """Extract crypto-related statements plus directly referenced assignments.

    Dependencies are lexical candidates: no claim they refer to the same scope
    or execute. Unsupported cases remain explicitly unresolved.
    """
    tokens = [m for m in TOKEN.finditer(source) if not m.group().startswith(("//", "/*"))]
    # Split on token delimiters, never on semicolons/braces inside literals.
    statements, current = [], []
    for token in tokens:
        current.append(token)
        if token.group() in {";", "{", "}"}:
            statements.append(current)
            current = []
    if current:
        statements.append(current)
    selected = set()
    for i, statement in enumerate(statements):
        values = [m.group() for m in statement]
        if any(value in APIS for value in values) or any(value in {"initialize", "init"} for value in values):
            if not values or values[0] not in {"import", "package"}:
                selected.add(i)
    # Recover local literal/alias declarations used by selected statements.
    # The bounded closure prevents accidentally selecting an entire program.
    for _ in range(4):
        used = {m.group() for i in selected for m in statements[i] if IDENTIFIER.fullmatch(m.group())}
        additions = set()
        for i, statement in enumerate(statements):
            values = [m.group() for m in statement]
            if "=" in values:
                pos = values.index("=")
                if pos and values[pos - 1] in used:
                    additions.add(i)
        updated = selected | additions
        if updated == selected:
            break
        selected = updated
    contexts = [" ".join(m.group() for m in statements[i]) for i in sorted(selected)]
    text = normalize("\n".join(contexts))
    observations = []
    for i, token in enumerate(tokens[:-2]):
        if token.group() not in CALLS or tokens[i + 1].group() != "(":
            continue
        argument = tokens[i + 2].group()
        observations.append({"method": token.group(), "line": source.count("\n", 0, token.start()) + 1, "argumentToken": argument, "literal": argument.startswith(('"', "'")) or argument.isdigit()})
    features = dict(Counter("api:" + m.group() for m in tokens if m.group() in APIS))
    for item in observations:
        features["call:" + item["method"]] = features.get("call:" + item["method"], 0) + 1
        if item["literal"] and item["method"] == "getInstance":
            features["factory_literal:" + item["argumentToken"].strip('"')] = 1
        if item["literal"] and item["method"] == "initialize" and item["argumentToken"].isdigit():
            # Raw observation, not a hand-written secure/insecure threshold.
            features["initialization_value"] = int(item["argumentToken"])
    return {"text": text, "features": features, "observations": observations, "statementCount": len(selected), "limitation": "Lexical context only; assignment candidates may belong to different scopes or paths"}
